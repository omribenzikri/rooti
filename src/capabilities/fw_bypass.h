#ifndef _ROOTI_FW_BYPASS_H
#define _ROOTI_FW_BYPASS_H

#include <linux/netfilter.h>

// Specifies what to do when a packet matches a rule
enum rooti_net_rule_action {
    ROOTI_PACKET_DROP,
    ROOTI_PACKET_ACCEPT
};

// Specifies what to do with unmatched traffic
enum rooti_net_policy_type {
    ROOTI_NET_POLICY_WHITELIST, // drop unmatched packets
    ROOTI_NET_POLICY_BLACKLIST  // accept unmatched packets
};

// IPv4 subnet address
typedef struct {
    unsigned long prefix;
    unsigned long mask;
} subnet_addr_t;

// Single network rule to match packets against
struct rooti_net_rule {
    subnet_addr_t saddr;
    subnet_addr_t daddr;
    unsigned char protocol;
    unsigned short sport;
    unsigned short dport;
    enum rooti_net_rule_action action;
};

// Network policy to enfore
struct rooti_net_policy {
    enum rooti_net_policy_type type;
    struct rooti_net_rule *rules;
    size_t len;
};

int rooti_install_fw_bypass_hooks(void);
void rooti_uninstall_fw_bypass_hooks(void);

#endif