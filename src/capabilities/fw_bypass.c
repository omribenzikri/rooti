#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/bug.h>
#include "fw_bypass.h"
#include "../utils.h"
#include "../config.h"

static inline bool rooti_subnet_contains(subnet_addr_t *subnet_addr, unsigned long addr)
{
    return (subnet_addr->prefix & subnet_addr->mask) == (addr & subnet_addr->mask);
}

static inline bool rooti_matching_addresses(struct iphdr *ip_header, struct rooti_net_rule *rule)
{
    return rooti_subnet_contains(&rule->saddr, ntohl(ip_header->saddr)) && 
           rooti_subnet_contains(&rule->daddr, ntohl(ip_header->daddr));
}

static inline bool rooti_matching_protocol(struct iphdr *ip_header, struct rooti_net_rule *rule)
{
    return ip_header->protocol == rule->protocol;
}

static inline bool rooti_matching_tcp_ports(struct tcphdr *tcp_header, struct rooti_net_rule *rule)
{
    return (rule->sport == 0 || rule->sport == ntohs(tcp_header->source)) &&
           (rule->dport == 0 || rule->dport == ntohs(tcp_header->dest));
}

static inline bool rooti_matching_udp_ports(struct udphdr *udp_header, struct rooti_net_rule *rule)
{
    return (rule->sport == 0 || rule->sport == ntohs(udp_header->source)) &&
           (rule->dport == 0 || rule->dport == ntohs(udp_header->dest));
}

static bool rooti_matching_rule(struct sk_buff *skb, struct rooti_net_rule *rule)
{
    struct iphdr *ip_header = ip_hdr(skb);
    struct tcphdr *tcp_header;
    struct udphdr *udp_header;

    if (!rooti_matching_addresses(ip_header, rule)) return false;
    if (!rooti_matching_protocol(ip_header, rule)) return false;

    switch(ip_header->protocol) {
    case IPPROTO_TCP:
        tcp_header = tcp_hdr(skb);
        if (!rooti_matching_tcp_ports(tcp_header, rule)) {
            return false;
        }
        break;
    case IPPROTO_UDP:
        udp_header = udp_hdr(skb);
        if (!rooti_matching_udp_ports(udp_header, rule)) {
            return false;
        }
        break;
    }
    return true;
}

static unsigned int rooti_netfilter_hook(void *priv, struct sk_buff *skb, 
                                         const struct nf_hook_state *state)
{
    struct rooti_net_rule *rule;

    // We don't deal with non-IPv4 packets
    if (ntohs(skb->protocol) != ETH_P_IP) return NF_ACCEPT;
    
    for (int i = 0; i < ROOTI_NET_POLICY.len; i++) {
        rule = &ROOTI_NET_POLICY.rules[i];
        if (!rooti_matching_rule(skb, rule)) {
            continue;
        }
        switch (rule->action) {
        case ROOTI_PACKET_DROP:
            return NF_DROP;
        case ROOTI_PACKET_ACCEPT:
            // Forcefully send the packet out to the wire / to the user
            state->okfn(state->net, state->sk, skb);
            return NF_STOLEN;
        default:
            BUG();
        }
    }

    switch (ROOTI_NET_POLICY.type) {
    case ROOTI_NET_POLICY_WHITELIST:
        return NF_DROP;
    case ROOTI_NET_POLICY_BLACKLIST:
        return NF_ACCEPT;
    default:
        BUG();
    }
}

static struct nf_hook_ops rooti_inbound_nf_hook = {
    .hook = rooti_netfilter_hook,
    .hooknum = NF_INET_LOCAL_IN,
    .pf = PF_INET,
    .priority = NF_IP_PRI_FIRST
};

static struct nf_hook_ops rooti_outbound_nf_hook = {
    .hook = rooti_netfilter_hook,
    .hooknum = NF_INET_LOCAL_OUT,
    .pf = PF_INET,
    .priority = NF_IP_PRI_FIRST
};

int rooti_install_fw_bypass_hooks()
{
    int err;

    err = nf_register_net_hook(&init_net, &rooti_inbound_nf_hook);
    if (err) {
        ROOTI_DEBUG("nf_register_net_hook() failed: %d", err);
        return err;
    }

    err = nf_register_net_hook(&init_net, &rooti_outbound_nf_hook);
    if (err) {
        ROOTI_DEBUG("nf_register_net_hook() failed: %d", err);
        return err;
    }

    return 0;
}

void rooti_uninstall_fw_bypass_hooks()
{
    nf_unregister_net_hook(&init_net, &rooti_inbound_nf_hook);
    nf_unregister_net_hook(&init_net, &rooti_outbound_nf_hook);
}