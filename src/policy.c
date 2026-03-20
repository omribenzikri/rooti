#include <linux/bug.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include "policy.h"

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

static bool rooti_packet_matches_rule(struct sk_buff *skb, struct rooti_net_rule *rule)
{
    struct iphdr *ip_header;
    struct tcphdr *tcp_header;
    struct udphdr *udp_header;

    // We don't deal with non-IPv4 packets
    if (ntohs(skb->protocol) != ETH_P_IP) return false;

    ip_header = ip_hdr(skb);

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

bool rooti_match_packet(struct sk_buff *skb, const struct rooti_net_policy *policy,
                        enum rooti_net_rule_action *action)
{
    struct rooti_net_rule *rule;
    
    for (int i = 0; i < policy->len; i++) {
        rule = &policy->rules[i];
        if (rooti_packet_matches_rule(skb, rule)) {
            *action = rule->action;
            return true;
        }
    }

    switch (policy->type) {
    case ROOTI_NET_POLICY_WHITELIST:
        *action = ROOTI_PACKET_DROP;
         break;
    case ROOTI_NET_POLICY_BLACKLIST:
        *action = ROOTI_PACKET_ACCEPT;
        break;
    default:
        BUG();
    }

    return false;
}