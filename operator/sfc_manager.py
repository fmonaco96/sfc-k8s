from attrs import exceptions
import kopf
from kubernetes import client, config
import yaml
import json

import os
import sfc

# Get nodename, to handle resources on this node only
node_name = os.uname().nodename

# Get the template of loadbalancer object
lb_path = os.path.join(os.path.dirname(__file__), 'loadbalancer_template.yaml')
lb_template = open(lb_path, 'rt').read()

NF_PREFIX_NAME_LEN = 3

# Config Kubernetes client to use Service Account to authenticate
# to Kubernetes Api
config.load_incluster_config()
# Kubernetes API object for Custom Resources
api = client.CustomObjectsApi()

# Dictionary of handled LoadBalancers
loadbalancers_dict = {}

@kopf.on.startup()
def configure(settings: kopf.OperatorSettings,**_):
    settings.persistence.finalizer = 'servicefunctionchain.polito.it/finalizer'+"-"+node_name
    settings.persistence.progress_storage = kopf.AnnotationsProgressStorage(prefix='servicefunctionchain.polito.it')
    settings.persistence.diffbase_storage = kopf.AnnotationsDiffBaseStorage(
        prefix='servicefunctionchain.polito.it',
        key='last-handled-configuration',
    )
    settings.posting.enabled = False

@kopf.index('loadbalancers', field='spec.targetNodeName', value=node_name)
def lb_by_frontend_index(name, namespace, spec,**_):
    nf_name = spec['frontend']['name']
    fe_interface = spec['frontend']['interface']
    return { (namespace, nf_name): {'name': name, 'interface': fe_interface} }

@kopf.index('loadbalancers', field='spec.targetNodeName', value=node_name)
def lb_by_backend_index(name, namespace, spec,**_):
    nf_name = spec['backend']['name']
    be_interface = spec['backend']['interface']
    return { (namespace, nf_name): {'name': name, 'interface': be_interface} }

@kopf.index('pods', 
    annotations={'servicefunctionchain.polito.it/host-link': kopf.PRESENT},
    labels={'servicefunctionchain.polito.it/networkFunction': kopf.PRESENT}, 
    field='spec.nodeName', value=node_name)
def pod_by_networkfunction(name, namespace, annotations, labels, logger,**_):
    nf_name = labels['servicefunctionchain.polito.it/networkFunction']
    logger.info(f"Adding ({nf_name}) -> {name}, interfaces: {json.loads(annotations['servicefunctionchain.polito.it/host-link'])} ")
    return { (namespace, nf_name): {'name': name, 'interfaces': json.loads(annotations['servicefunctionchain.polito.it/host-link'])}}


# Chains
@kopf.on.create('servicefunctionchains', field='spec.targetNodeName', value=node_name)
def create_sfc_fn(spec, name,namespace, logger,**_):
    logger.info(f"Handling NetworkServiceChain {name} creation")

    # Get network functions
    network_functions = spec['networkFunctions']
    
    # Build a dictionary to index network functions by name
    nf_dict = {}
    for nf in network_functions:
        nf_dict[nf['name']] = nf

    # Iterate over chain network functions
    # and create load balancers
    for current_nf in network_functions:
        current_name = current_nf['name']
        # Iterate over link targets
        for target_name, current_ifname in current_nf['links'].items():
            # We assume that the chain is well formed, so that targetName exists in the
            # network functions array provided in the YAML (needed validation through AdmissionWebhook)
            # and that it has also a corresponding link to the current NF
            target_ifname = nf_dict[target_name]['links'][current_name]

            # Create load balancer name [ must be unique and deductible, to be improved]
            lb_name = "lb-"+current_name[:min(len(current_name), NF_PREFIX_NAME_LEN)] + "-" + target_name[:min(len(target_name), NF_PREFIX_NAME_LEN)]
            lb_text = lb_template.format(
                name=lb_name, target_node=node_name,
                fe_name=current_name, fe_interface=current_ifname,
                be_name=target_name,be_interface=target_ifname)
            lb_data = yaml.safe_load(lb_text)

            # Make this loadbalancer a child of current chain object 
            # (set owner reference... enable cascade deletion)
            kopf.adopt(lb_data)

            logger.info(f"Creating LoadBalancer resource {lb_name}")

            try:
                # Create the loadbalancer resource using Kubernetes client
                api.create_namespaced_custom_object(
                    group='servicefunctionchain.polito.it',
                    version='v1',
                    namespace=namespace,
                    plural='loadbalancers',
                    body=lb_data
                )
            except client.ApiException as err:
                if err.status == 409:
                    logger.warn(f"Conflict creating loadbalancer {lb_name}, resource already exist (ignoring problem)")
                else:
                    raise

            # Interconnections have been created, we remove the link entry,
            # to the current NF, from the map of the target NF.
            # This is done in order to not recreate the link when iterating on target
            target_links = nf_dict[target_name]['links']
            del target_links[current_name]

@kopf.on.delete('servicefunctionchains', field='spec.targetNodeName', value=node_name)
def delete_sfc_fn(name, logger,**_):
    logger.info(f"Deleting NetworkServiceChain object {name}")

# LoadBalancers
@kopf.on.resume('loadbalancers', deleted=True ,field='spec.targetNodeName', value=node_name)
@kopf.on.create('loadbalancers', field='spec.targetNodeName', value=node_name)
def create_lb_fn(pod_by_networkfunction: kopf.Index, spec, name, namespace, logger,**_):
    logger.info(f"Creating LoadBalancer object {name}")

    # Get interface names
    fe_interface = spec['frontend']['interface']
    be_interface = spec['backend']['interface']

    # Create loadbalancer object
    loadbalancer = sfc.LoadBalancer(name)

    # Get all frontends network functions to link 
    fe_pods = pod_by_networkfunction.get((namespace, spec['frontend']['name']), [])
    logger.info(f"Frontends network function to link: {fe_pods}")
    for fe_pod in fe_pods:
        # Get corresponding frontend interface index
        ifindex = fe_pod['interfaces'].get(fe_interface) 
        # Ensure interface in load balancer frontend interfaces
        loadbalancer.ensure_frontend_interface(int(ifindex))


    # Get all backends network functions to link
    be_pods = pod_by_networkfunction.get((namespace, spec['backend']['name']), [])
    logger.info(f"Backends network function to link: {be_pods}")
    for be_pod in be_pods:
        # Get corresponding backend interface index
        ifindex = be_pod['interfaces'].get(be_interface) 
        # Ensure interface in load balancer backend interfaces
        loadbalancer.ensure_backend_interface(int(ifindex))

    # Add loadbalancer to dictionary
    loadbalancers_dict[name] = loadbalancer


@kopf.on.delete('loadbalancers', field='spec.targetNodeName', value=node_name)
def delete_lb_fn(spec,name,logger,**_):
    logger.info(f"Deleting LoadBalancer object {name}")

    # Cleanup loadbalancer and delete from dictionary
    lb = loadbalancers_dict.get(name)
    if lb:
        lb.cleanup()
        del loadbalancers_dict[name]


# Pods
@kopf.on.update('pods', 
    labels={'servicefunctionchain.polito.it/networkFunction': kopf.PRESENT},
    annotations={'servicefunctionchain.polito.it/host-link': kopf.PRESENT},
    field='status.phase', old='Pending', new='Running',
    when=lambda spec, **_: spec.get('nodeName', '') == node_name)
def update_pod_fn(lb_by_frontend_index: kopf.Index, lb_by_backend_index: kopf.Index, namespace, annotations, labels, logger,**_):
    # Get network function name from label
    nf_name = labels['servicefunctionchain.polito.it/networkFunction']
    # Get network function interfaces
    interfaces = json.loads(annotations['servicefunctionchain.polito.it/host-link'])

    # Search using index the involved loadbalancers
    logger.info(f"A new {nf_name} Pod is running, searching LoadBalancers to update")
    lb_to_add_fe = lb_by_frontend_index.get( (namespace, nf_name), [] )
    lb_to_add_be = lb_by_backend_index.get( (namespace, nf_name), [] )

    logger.info(f"LoadBalancers to update: {list(map(lambda lb_cr: lb_cr['name'], lb_to_add_fe))} {list(map(lambda lb_cr: lb_cr['name'], lb_to_add_be))}")

    for lb_cr in lb_to_add_fe:
        # Get lb name
        lb_name = lb_cr['name']
        # Get the interface name attached to the frontend
        fe_ifname = lb_cr['interface']
        # Get the ifindex corresponding to the ifname
        ifindex = interfaces.get(fe_ifname)
        # Get LoadBalancer object from the dictionary
        lb_obj: sfc.LoadBalancer = loadbalancers_dict.get(lb_name)

        if lb_obj and ifindex:
            # Ensure interface ifindex is among load balancer frontends
            lb_obj.ensure_frontend_interface(int(ifindex))

    for lb_cr in lb_to_add_be:
        # Get lb name
        lb_name = lb_cr['name']
        # Get the interface name attached to the backend
        be_ifname = lb_cr['interface']
        # Get the ifindex corresponding to the ifname
        ifindex = interfaces.get(be_ifname)
        # Get LoadBalancer object from the dictionary
        lb_obj: sfc.LoadBalancer = loadbalancers_dict.get(lb_name)

        if lb_obj and ifindex:
            # Ensure interface ifindex is among load balancer backends
            lb_obj.ensure_backend_interface(int(ifindex))

    logger.info(f"{nf_name} Pod creation handled successfully!")

@kopf.on.delete('pods', 
    labels={'servicefunctionchain.polito.it/networkFunction': kopf.PRESENT},
    annotations={'servicefunctionchain.polito.it/host-link': kopf.PRESENT},
    when=lambda status, spec, **_: spec.get('nodeName', '') == node_name)
def delete_pod_fn(lb_by_frontend_index: kopf.Index, lb_by_backend_index: kopf.Index, namespace, annotations, labels, logger,**_):
    # Get network function name from label
    nf_name = labels['servicefunctionchain.polito.it/networkFunction']
    # Get network function interfaces
    interfaces = json.loads(annotations['servicefunctionchain.polito.it/host-link'])

    # Search using index the involved loadbalancers
    logger.info(f"A {nf_name} Pod is going to be deleted, searching LoadBalancers to update")
    lb_to_del_fe = lb_by_frontend_index.get( (namespace, nf_name), [] )
    lb_to_del_be = lb_by_backend_index.get( (namespace, nf_name), [] )

    logger.info(f"LoadBalancers to update: {list(map(lambda lb_cr: lb_cr['name'], lb_to_del_fe))} {list(map(lambda lb_cr: lb_cr['name'], lb_to_del_be))}")

    for lb_cr in lb_to_del_fe:
        # Get lb name
        lb_name = lb_cr['name']
        # Get the interface name attached to the frontend
        fe_ifname = lb_cr['interface']
        # Get the ifindex corresponding to the ifname
        ifindex = interfaces.get(fe_ifname)
        # Get LoadBalancer object from the dictionary
        lb_obj: sfc.LoadBalancer = loadbalancers_dict.get(lb_name)

        if lb_obj and ifindex:
            # Delete interface ifindex from load balancer frontends
            lb_obj.del_frontend_interface(int(ifindex))

    for lb_cr in lb_to_del_be:
        # Get lb name
        lb_name = lb_cr['name']
        # Get the interface name attached to the backend
        be_ifname = lb_cr['interface']
        # Get the ifindex corresponding to the ifname
        ifindex = interfaces.get(be_ifname)
        # Get LoadBalancer object from the dictionary
        lb_obj: sfc.LoadBalancer = loadbalancers_dict.get(lb_name)

        if lb_obj and ifindex:
            # Delete interface ifindex from load balancer backends
            lb_obj.del_backend_interface(int(ifindex))

    logger.info(f"{nf_name} Pod deletion handled successfully!")
