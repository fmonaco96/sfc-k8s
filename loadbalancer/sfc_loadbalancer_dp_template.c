#include <uapi/linux/bpf.h>      // Definition of struct __sk_buff, the
                                 // parameter passed to our eBPF program
#include <uapi/linux/pkt_cls.h>  // Definition of valid return codes for eBPF
                                 // programs attached to the TC hook (e.g.
                                 // TC_ACT_OK)

#include <uapi/linux/if_ether.h> // Definition of struct ethhdr
#include <uapi/linux/ip.h>       // Definition of struct iphdr
#include <uapi/linux/in.h>       // Definition of protocol types
#include <uapi/linux/tcp.h>      // Definition of struct tcphdr
#include <uapi/linux/udp.h>      // Definition of struct udphdr
#include <linux/jhash.h>         // Definition of jhash func
 
#define MAX_SESSIONS 65536
#define MAX_INTERFACES 32
#define MAX_ARP_CACHE 5

// ARP protocol opcodes
#define ARP_FRAME_LEN  42       /* ARP hdr (28) + eth hdr (14)*/
#define	ARPOP_REQUEST	1		/* ARP request			*/
#define	ARPOP_REPLY	    2		/* ARP reply			*/

struct arphdr {
	__be16 ar_hrd;	    	/* format of hardware address	*/
	__be16 ar_pro;  		/* format of protocol address	*/
	unsigned char ar_hln;	/* length of hardware address	*/
	unsigned char ar_pln;	/* length of protocol address	*/
	__be16 ar_op;		    /* ARP opcode (command)		*/
	unsigned char ar_sha[ETH_ALEN];	/* sender hardware address	*/
	__be32 ar_sip;		    /* sender IP address		*/
	unsigned char ar_tha[ETH_ALEN];	/* target hardware address	*/
	__be32 ar_tip;		    /* target IP address		*/

} __attribute__((packed));

struct arp_reply_frame {
    unsigned char bytes[ARP_FRAME_LEN];
} __attribute__((packed));

struct session {
  __be32 ip_src;
  __be32 ip_dst;
  __be16 port_src;
  __be16 port_dst;
  __u8 proto;
} __attribute__((packed));

struct session_interfaces {
    __u32 frontend;
    __u32 backend;
} __attribute__((packed));

BPF_TABLE_PINNED("lru_hash", struct session, struct session_interfaces, sessions, MAX_SESSIONS, "/sys/fs/bpf/sfc/__LB_NAME__/session_map");

BPF_TABLE_PINNED("array", __u32 , __u32, num_backends, 1, "/sys/fs/bpf/sfc/__LB_NAME__/num_backends_map");

BPF_TABLE_PINNED("array", __u32 , __u32, backends_interfaces, MAX_INTERFACES, "/sys/fs/bpf/sfc/__LB_NAME__/backends_interfaces_map");

BPF_TABLE_PINNED("array", __u32 , __u32, num_frontends, 1, "/sys/fs/bpf/sfc/__LB_NAME__/num_frontends_map");

BPF_TABLE_PINNED("array", __u32 , __u32, frontends_interfaces, MAX_INTERFACES, "/sys/fs/bpf/sfc/__LB_NAME__/frontends_interfaces_map");

BPF_TABLE_PINNED("lru_hash", __u32, struct arp_reply_frame, arp_cache, MAX_ARP_CACHE, "/sys/fs/bpf/sfc/__LB_NAME__/arp_cache_map");

static inline int get_packet_session(void *data, void* data_end ,struct session *session_key){
    // bpf_trace_printk("getting packet session");
    // Interpret the first part of the packet as an ethernet header
    struct ethhdr *eth = data;
    if (data + sizeof(*eth) > data_end) {
        // The packet is malformed
        return 0;

    }

    // We handle only IP and ARP for the moment
    switch(eth->h_proto) {

        case htons(ETH_P_IP): // ipv4 packet
        {
            // Get pointer to the IP header
            struct iphdr *iph = (struct iphdr*)((void*)eth + sizeof(struct ethhdr));
            if ( (void*)iph + sizeof(struct iphdr) > data_end){
                return 0;
            }

            // Get session IP parameters
            session_key->ip_src = iph->saddr;
            session_key->ip_dst = iph->daddr;
            session_key->proto = iph->protocol;

            // We handle only ICMP and TCP/UDP
            switch(iph->protocol){

                case IPPROTO_TCP:
                {
                    // Get pointer to the TCP header
                    struct tcphdr *tcph = (struct tcphdr*)((void*)iph + sizeof(struct iphdr));
                    if ( (void*)tcph + sizeof(struct tcphdr) > data_end ) {
                        return 0;
                    }

                    // Get session ports
                    session_key->port_src = tcph->source;
                    session_key->port_dst = tcph->dest;
                    break;
                }

                case IPPROTO_UDP:
                {
                    // Get pointer to the UDP header
                    struct udphdr *udph = (struct udphdr*)((void*)iph + sizeof(struct iphdr));
                    if ( (void*)udph + sizeof(struct udphdr) > data_end ) {
                        return 0;
                    }

                    // Get session ports
                    session_key->port_src = udph->source;
                    session_key->port_dst = udph->dest;
                    break;
                }

                case IPPROTO_ICMP:
                {
                    // We don't have ports here
                    session_key->port_src = 0;
                    session_key->port_dst = 0;
                    break;
                }
                default:
                    return 0;
            }
            break;
        }

        case htons(ETH_P_ARP): // arp packet
        {
            // Get pointer to the ARP header
            struct arphdr *arph = (struct arphdr*)((void*)eth + sizeof(struct ethhdr));
            if ( (void*)arph + sizeof(struct arphdr) > data_end){
                return 0;
            }
            session_key->ip_src = arph->ar_sip;
            session_key->ip_dst = arph->ar_tip;
            // Since ETH_P_ARP is on two bytes we can't use it as proto
            // We use 0 as protocol 
            session_key->proto = 0;
            // We don't have ports here
            session_key->port_src = 0;
            session_key->port_dst = 0;
            break;
        }

        default:
            return 0;
    }
    return 1;
}

static inline void swap_session_params(struct session *session_key){
    // bpf_trace_printk("swapping session params");
    __be32 ip_tmp;
    __be16 port_tmp;

    // Swap IP addresses
    ip_tmp = session_key->ip_src;
    session_key->ip_src = session_key->ip_dst;
    session_key->ip_dst = ip_tmp;

    // Swap Ports
    port_tmp = session_key->port_src;
    session_key->port_src = session_key->port_dst;
    session_key->port_dst = port_tmp;

    return;
}

// Ongoing traffic
int handle_loadbalance_fe(struct __sk_buff *ctx) {
    // bpf_trace_printk("handling loadbalancing interface: %d", ctx->ifindex);
    // Retrieve pointers to the begin and end of the packet buffer
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    // Get ingress interface index
    __u32 ingress_ifindex = ctx->ifindex;

    // Check if packet is an ARP packet
    // Interpret the first part of the packet as an ethernet header
     struct ethhdr *eth = data;
     if (data + sizeof(*eth) > data_end) {
        // The packet is malformed
        return TC_ACT_SHOT;
     }
    if(eth->h_proto == htons(ETH_P_ARP)){
        // Get pointer to the ARP header
        struct arphdr *arph = (struct arphdr*)((void*)eth + sizeof(struct ethhdr));
        if ( (void*)arph + sizeof(struct arphdr) > data_end){
            return TC_ACT_SHOT;
        }

        // ARP request
        // ARP reply frame
        struct arp_reply_frame *arp_reply;
        struct arp_reply_frame *arp_buffer = data;

        // Get target and sender IP
        __be32 target_ip = arph->ar_tip;
        __be32 sender_ip = arph->ar_sip;

        // Check if it is an ARP request
        if(arph->ar_op == htons(ARPOP_REQUEST)){
            // bpf_trace_printk("handling arp request");
            // ARP request
            // Check if the reply for target IP is in the cache
            arp_reply = arp_cache.lookup(&target_ip);
            if(arp_reply){
                // Cache hit: respond with cached reply
                // bpf_trace_printk("arp cache hit: redirecting to interface %d",ingress_ifindex);
                *arp_buffer = *arp_reply;
                return bpf_redirect(ingress_ifindex,0);
            }
            
        } else if (arph->ar_op == htons(ARPOP_REPLY)){
            // bpf_trace_printk("handling arp reply");
            // ARP reply
            // Add reply to cache
            arp_cache.update(&sender_ip,arp_buffer);
        }

    }

    // Session parameters
    struct session session_key = {};

    int success = get_packet_session(data,data_end,&session_key);

    if(!success){
        // Error during the creation of session key
        return TC_ACT_SHOT;
    }

    // Load balancing
    // Check if session is present in session table
    __u32 hash = jhash((const void *)&session_key, sizeof(struct session), JHASH_INITVAL);

    struct session_interfaces new_interfaces = {};
    struct session_interfaces *interfaces = sessions.lookup(&session_key);

    if(!interfaces){
        // Session is not present in the table
        // Calculate index of backend interface

        // Get num of backend interfaces
        unsigned int zero = 0;
        __u32 *n_backends = num_backends.lookup(&zero);

        if(!n_backends){
            return TC_ACT_SHOT;
        }

        // Calculate backend index
        __u32 backend_index = hash % (*n_backends);

        // Get egress interface index
        __u32 *egress_ifindex = backends_interfaces.lookup(&backend_index);

        if(!egress_ifindex){
            return TC_ACT_SHOT;
        }

        // Create a new entry
        new_interfaces.frontend = ingress_ifindex;
        new_interfaces.backend = *egress_ifindex;
        interfaces = sessions.lookup_or_try_init(&session_key,&new_interfaces);

        if(!interfaces){
            return TC_ACT_SHOT;
        }
    }

    // bpf_trace_printk("loadbalancing to interface: %d", interfaces->backend);
    return bpf_redirect(interfaces->backend,0);
}

// Return traffic
int handle_loadbalance_be(struct __sk_buff *ctx) {
    // bpf_trace_printk("handling redirect interface: %d", ctx->ifindex);
    // Retrieve pointers to the begin and end of the packet buffer
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    // Get ingress interface index
    __u32 ingress_ifindex = ctx->ifindex;

    // Check if packet is an ARP packet
    // Interpret the first part of the packet as an ethernet header
     struct ethhdr *eth = data;
     if (data + sizeof(*eth) > data_end) {
        // The packet is malformed
        return TC_ACT_SHOT;
     }
    if(eth->h_proto == htons(ETH_P_ARP)){
        // Get pointer to the ARP header
        struct arphdr *arph = (struct arphdr*)((void*)eth + sizeof(struct ethhdr));
        if ( (void*)arph + sizeof(struct arphdr) > data_end){
            return TC_ACT_SHOT;
        }

        // ARP reply frame
        struct arp_reply_frame *arp_reply;
        struct arp_reply_frame *arp_buffer = data;

        // Get target and sender IP
        __be32 target_ip = arph->ar_tip;
        __be32 sender_ip = arph->ar_sip;

        // Check if it is an ARP request
        if(arph->ar_op == htons(ARPOP_REQUEST)){
            // bpf_trace_printk("handling arp request");
            // ARP request
            // Check if the reply for target IP is in the cache
            arp_reply = arp_cache.lookup(&target_ip);
            if(arp_reply){
                // Cache hit: respond with cached reply
                // bpf_trace_printk("arp cache hit: redirecting to interface %d",ingress_ifindex);
                *arp_buffer = *arp_reply;
                return bpf_redirect(ingress_ifindex,0);
            }
            
        } else if (arph->ar_op == htons(ARPOP_REPLY)){
            // bpf_trace_printk("handling arp reply");
            // ARP reply
            // Add reply to cache
            arp_cache.update(&sender_ip,arp_buffer);
        }

    }

    // Session parameters
    struct session session_key = {};

    int success = get_packet_session(data,data_end,&session_key);

    if(!success){
        // Error during the creation of session key
        return TC_ACT_SHOT;
    }

    swap_session_params(&session_key);

    // Redirect packet to correct frontend
    // Check if session is present in session table
    __u32 hash = jhash((const void *)&session_key, sizeof(struct session), JHASH_INITVAL);

    struct session_interfaces new_interfaces = {};
    struct session_interfaces *interfaces = sessions.lookup(&session_key);

    if(!interfaces){
        // Session is not present in the table
        // Calculate index of frontend interface
        
        // Get num of frontend interfaces
        unsigned int zero = 0;
        __u32 *n_frontends = num_frontends.lookup(&zero);

        if(!n_frontends){
            return TC_ACT_SHOT;
        }

        // Calculate frontend index
        __u32 frontend_index = hash % (*n_frontends);

        // Get egress interface index
        __u32 *egress_ifindex = frontends_interfaces.lookup(&frontend_index);

        if(!egress_ifindex){
            return TC_ACT_SHOT;
        }

        // Create a new entry
        new_interfaces.frontend = *egress_ifindex;
        new_interfaces.backend = ingress_ifindex;
        interfaces = sessions.lookup_or_try_init(&session_key,&new_interfaces);

        if(!interfaces){
            return TC_ACT_SHOT;
        }

    } 

    // Redirect to correct frontend
    // bpf_trace_printk("redirecting to interface: %d", interfaces->frontend);
    return bpf_redirect(interfaces->frontend,0);
}