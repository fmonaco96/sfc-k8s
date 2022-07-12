#!/usr/bin/python3
# Import the appropriate libraries
import threading
from bcc import BPF
from pyroute2 import IPRoute
from pr2modules.netlink.exceptions import NetlinkError

import os
import shutil
import logging

ip = IPRoute()

logger=logging.getLogger('sfc')

# Path to the source file for dataplane template
LB_SOURCE_FILE = '/src/sfc_loadbalancer_dp_template.c'

# Path to the parent folder where are pinned eBPF maps for NSC
NSC_BPFFS_PATH = '/sys/fs/bpf/sfc'

# Create bpf fs folder where maps will be pinned
os.makedirs(NSC_BPFFS_PATH, exist_ok=True)

# Load loadbalancer template source file
dp_template = open(LB_SOURCE_FILE,'rt').read()

class NscLoggerAdapter(logging.LoggerAdapter):
    def process(self,msg,kwargs):
        return f"[{self.extra['lb_name']}] {msg}", kwargs

class LoadBalancer:

    # Class level lock, needed for constructor
    # in particular for BPF program compilation
    init_lock = threading.Lock()


    # Constructor
    def __init__(self, name: str):
        self.init_lock.acquire()
        try:
            # Save loadbalancer name
            self.name = name

            # Create lock object
            self.lock = threading.RLock()

            # Create logger for this instance
            self.logger = NscLoggerAdapter(logger, {'lb_name': name})

            # Create bpf object
            dp_source = dp_template.replace('__LB_NAME__',name)
            self.bpf_handle = BPF(text=dp_source)

            # Get functions
            self.frontend_lb_fn = self.bpf_handle.load_func("handle_loadbalance_fe", BPF.SCHED_CLS)
            self.backend_lb_fn = self.bpf_handle.load_func("handle_loadbalance_be", BPF.SCHED_CLS)

            # Get session maps
            self.session_map = self.bpf_handle.get_table("sessions")
            
            # Get frontends maps
            self.frontends_map = self.bpf_handle.get_table("frontends_interfaces")
            self.num_frontends_map = self.bpf_handle.get_table("num_frontends")

            # Get backends maps
            self.backends_map = self.bpf_handle.get_table("backends_interfaces")
            self.num_backends_map = self.bpf_handle.get_table("num_backends")

            self.logger.info(f"{name} instance created")
        finally:
            self.init_lock.release()

    # Methods 
    def add_frontend_interface(self, ifindex):
        self.logger.info(f"Adding interface {ifindex} to frontends")
        self.lock.acquire()
        try:
            # Add appropriate qdisc to the interface
            # But first check if the old one has to be cleaned up
            self.logger.info(f"Adding qdisc to interface {ifindex}")
            qdiscs = ip.get_qdiscs(ifindex)
            for nlmsg in qdiscs:
                tca_kind = nlmsg.get_attr('TCA_KIND')
                if(tca_kind == "clsact"):
                    # Cleanup old qdisc (this will clean all filters)
                    ip.tc("del", "clsact", ifindex)
            ip.tc("add","clsact", ifindex)

            # Add filter to the interface
            self.logger.info(f"Adding filter to interface {ifindex}")
            ip.tc("add-filter", "bpf", ifindex, ":1", fd=self.frontend_lb_fn.fd, name=self.frontend_lb_fn.name,parent="ffff:fff2", direct_action=True,classid=1)

            self.logger.info(f"Adding interface {ifindex} to maps")
            # Get current number of frontends
            num_fe = self.num_frontends_map[0].value

            # Add frontend interface to map
            fe_leaf = self.frontends_map.Leaf(ifindex)
            self.frontends_map[num_fe] = fe_leaf

            # Update number of frontends
            num_fe_leaf = self.num_frontends_map.Leaf(num_fe+1)
            self.num_frontends_map[0] = num_fe_leaf

            self.logger.info(f"Interface {ifindex} added to frontends")
        except NetlinkError as err:
            # Ignore errors on netlink
            logger.error(f"{err}")
        finally:
            self.lock.release()

    def add_backend_interface(self, ifindex):
        self.logger.info(f"Adding interface {ifindex} to backends")
        self.lock.acquire()
        try:
            # Add appropriate qdisc to the interface
            # But first check if the old one has to be cleaned up
            self.logger.info(f"Adding qdisc to interface {ifindex}")
            qdiscs = ip.get_qdiscs(ifindex)
            for nlmsg in qdiscs:
                tca_kind = nlmsg.get_attr('TCA_KIND')
                if(tca_kind == "clsact"):
                    # Cleanup old qdisc (this will clean all filters)
                    ip.tc("del", "clsact", ifindex)
            ip.tc("add","clsact", ifindex)

            # Add filter to the interface
            self.logger.info(f"Adding filter to interface {ifindex}")
            ip.tc("add-filter", "bpf", ifindex, ":1", fd=self.backend_lb_fn.fd, name=self.backend_lb_fn.name,parent="ffff:fff2", direct_action=True,classid=1)

            self.logger.info(f"Adding interface {ifindex} to maps")
            # Get current number of backends
            num_be = self.num_backends_map[0].value

            # Add backend interface to map
            be_leaf = self.backends_map.Leaf(ifindex)
            self.backends_map[num_be] = be_leaf

            # Update number of backends
            num_be_leaf = self.num_backends_map.Leaf(num_be+1)
            self.num_backends_map[0] = num_be_leaf

            self.logger.info(f"Interface {ifindex} added to backends")
        except NetlinkError as err:
            # Ignore errors on netlink
            logger.error(f"{err}")
        finally:
            self.lock.release()

    def ensure_frontend_interface(self,ifindex):
        self.logger.info(f"Ensuring interface {ifindex} as frontend")
        self.lock.acquire()
        try:
           # Get frontend interfaces
            num_fe = self.num_frontends_map[0].value
            fe_interfaces = list(map(lambda ifindex: ifindex.value,self.frontends_map.values()[:num_fe]))

            # Check if ifindex is already in the map
            if ifindex in fe_interfaces:
                return

            # Add interface to frontends
            self.add_frontend_interface(ifindex)
        finally:
            self.lock.release()

    def ensure_backend_interface(self,ifindex):
        self.logger.info(f"Ensuring interface {ifindex} as backend")
        self.lock.acquire()
        try:
           # Get backend interfaces
            num_be = self.num_backends_map[0].value
            be_interfaces = list(map(lambda ifindex: ifindex.value,self.backends_map.values()[:num_be]))

            # Check if ifindex is already in the map
            if ifindex in be_interfaces:
                return

            # Add interface to frontends
            self.add_backend_interface(ifindex)
        finally:
            self.lock.release()

    def del_frontend_interface(self, ifindex):
        self.logger.info(f"Removing interface {ifindex} from frontends")
        self.lock.acquire()
        try:
            try:
                # Delete qdisc if present (this will remove all filters)
                self.logger.info(f"Removing qdisc from interface {ifindex}")
                qdiscs = ip.get_qdiscs(ifindex)
                for nlmsg in qdiscs:
                    tca_kind = nlmsg.get_attr('TCA_KIND')
                    if(tca_kind == "clsact"):
                        ip.tc("del", "clsact", ifindex)
            except NetlinkError as err:
                # Ignore errors on netlink if interface ifindex no longer exist
                if err.code == 19:
                    logger.warn(f"NetlinkError: interface {ifindex} no longer exists, impossible to remove clsact qdisc")
                else:
                    raise

            self.logger.info(f"Removing interface {ifindex} from maps")
            # Get current number of frontends
            num_fe = self.num_frontends_map[0].value

            index = None
            found = False
            # Search index of the interface in the map
            for i in range(num_fe):
                if(self.frontends_map[i].value == ifindex):
                    index = i
                    found = True
                    break
            
            if(not found):
                return

            # Get last ifindex in the map
            last_ifindex = self.frontends_map[num_fe-1].value

            # Substitute the deleted ifindex with the last ifindex
            # (this is done in order to have an array without holes
            # last index is copied its old position will be free)
            fe_leaf = self.frontends_map.Leaf(last_ifindex)
            self.frontends_map[index] = fe_leaf

            # Update number of frontends 
            num_fe_leaf = self.num_frontends_map.Leaf(num_fe-1)
            self.num_frontends_map[0] = num_fe_leaf


            # Cleanup of sessions
            self.cleanup_sessions(ifindex)

            self.logger.info(f"Interface {ifindex} removed from frontends")
        finally:
            self.lock.release()

    def del_backend_interface(self, ifindex):
        self.logger.info(f"Removing interface {ifindex} from backends")
        self.lock.acquire()
        try:
            try:
                # Delete qdisc if present (this will remove all filters)
                self.logger.info(f"Removing qdisc from interface {ifindex}")
                qdiscs = ip.get_qdiscs(ifindex)
                for nlmsg in qdiscs:
                    tca_kind = nlmsg.get_attr('TCA_KIND')
                    if(tca_kind == "clsact"):
                        ip.tc("del", "clsact", ifindex)
            except NetlinkError as err:
                # Ignore errors on netlink if interface ifindex no longer exist
                if err.code == 19:
                    logger.warn(f"NetlinkError: interface {ifindex} no longer exists, impossible to remove clsact qdisc")
                else:
                    raise

            self.logger.info(f"Removing interface {ifindex} from maps")
            # Get current number of backends
            num_be = self.num_backends_map[0].value

            index = None
            found = False
            # Search index of the interface in the map
            for i in range(num_be):
                if(self.backends_map[i].value == ifindex):
                    index = i
                    found = True
                    break

            if(not found):
                return

            # Get last ifindex in the map
            last_ifindex = self.backends_map[num_be-1].value

            # Substitute the deleted ifindex with the last ifindex
            # (this is done in order to have an array without holes
            # last index is copied its old position will be free)
            be_leaf = self.backends_map.Leaf(last_ifindex)
            self.backends_map[index] = be_leaf

            # Update number of backends 
            num_be_leaf = self.num_backends_map.Leaf(num_be-1)
            self.num_backends_map[0] = num_be_leaf

            # Cleanup of sessions
            self.cleanup_sessions(ifindex)

            self.logger.info(f"Interface {ifindex} removed from backends")
        finally:
            self.lock.release()
    
    def clear_frontends(self):
        self.logger.info("Clearing frontends table")
        self.lock.acquire()
        try:
            # Get map frontend interfaces
            num_fe = self.num_frontends_map[0].value
            frontends_interfaces = list(map(lambda ifindex: ifindex.value,self.frontends_map.values()[:num_fe]))

            # Remove filters from interfaces
            for ifindex in frontends_interfaces:
                # Delete qdisc if present (this will remove all filters)
                qdiscs = ip.get_qdiscs(ifindex)
                for nlmsg in qdiscs:
                    tca_kind = nlmsg.get_attr('TCA_KIND')
                    if(tca_kind == "clsact"):
                        try:
                            ip.tc("del", "clsact", ifindex)
                        except NetlinkError as err:
                            # Ignore errors on netlink if interface ifindex no longer exist
                            if err.code == 19:
                                logger.warn(f"NetlinkError: interface {ifindex} no longer exists, impossible to remove clsact qdisc")
                            else:
                                raise
            
            # Set number of frontends to 0
            num_fe_leaf = self.num_frontends_map.Leaf(0)
            self.num_frontends_map[0] = num_fe_leaf

        finally:
            self.lock.release()

    def clear_backends(self):
        self.logger.info("Clearing backends table")
        self.lock.acquire()
        try:
            # Get map backend interfaces
            num_be = self.num_backends_map[0].value
            backend_interfaces = list(map(lambda ifindex: ifindex.value,self.backends_map.values()[:num_be]))

            # Remove filters from interfaces
            for ifindex in backend_interfaces:
                # Delete qdisc if present (this will remove all filters)
                qdiscs = ip.get_qdiscs(ifindex)
                for nlmsg in qdiscs:
                    tca_kind = nlmsg.get_attr('TCA_KIND')
                    if(tca_kind == "clsact"):
                        try:
                            ip.tc("del", "clsact", ifindex)
                        except NetlinkError as err:
                            # Ignore errors on netlink if interface ifindex no longer exist
                            if err.code == 19:
                                logger.warn(f"NetlinkError: interface {ifindex} no longer exists, impossible to remove clsact qdisc")
                            else:
                                raise
            
            # Set number of backends to 0
            num_be_leaf = self.num_backends_map.Leaf(0)
            self.num_backends_map[0] = num_be_leaf

        finally:
            self.lock.release()

    def clear_sessions(self):
        self.logger.info("Clearing session table")
        self.lock.acquire()
        try:
            # Clear all entries of session map
            self.session_map.items_delete_batch(None)
        finally:
            self.lock.release()

    def cleanup_sessions(self, ifindex):
        self.logger.info(f"Cleaning session table entries involved with interface: {ifindex}")
        self.lock.acquire()
        try:
            session_key_to_delete = []
            # Find all session that involve the given ifindex (as frontend or backend interface)
            for session_key, interfaces in self.session_map.items():
                if (interfaces.frontend == ifindex ) or (interfaces.backend == ifindex):
                    session_key_to_delete.append(session_key)

            # Delete all session involved
            if session_key_to_delete:
                # Create a ctype array from keys list
                keys_array = (self.session_map.Key * len(session_key_to_delete))(*session_key_to_delete) 
                self.session_map.items_delete_batch(keys_array)

        finally:
            self.lock.release()
    
    def cleanup(self):
        self.logger.info("Cleaning loadbalancer resources")
        self.lock.acquire()
        try:
            # Clear all frontend and backend interfaces
            # (to remove eBPF filter from interfaces)
            self.clear_frontends()
            self.clear_backends()

            # Delete folder of pinned eBPF maps
            self.logger.info("Removing pinned eBPF maps")
            shutil.rmtree(NSC_BPFFS_PATH+'/'+self.name,ignore_errors=False)
        finally:
            self.lock.release()
