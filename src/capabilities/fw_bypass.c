#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include "fw_bypass.h"

static unsigned int rooti_netfilter_hook(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
    struct iphdr *ip_header;

    // We don't deal with non-IP packets
    if (skb->protocol != htons(ETH_P_IP)) return NF_ACCEPT;
    ip_header = ip_hdr(skb);

    if (ip_header->protocol == IPPROTO_ICMP) {
        return NF_DROP;
    }
    return NF_ACCEPT;
}

struct nf_hook_ops rooti_netfilter_hook_ops = {
    .hook = rooti_netfilter_hook,
    .hooknum = NF_INET_LOCAL_OUT,
    .pf = PF_INET,
    .priority = NF_IP_PRI_FIRST
};