#ifndef _ROOTI_CONFIG_TYPES_H
#define _ROOTI_CONFIG_TYPES_H

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
    unsigned long addr;
    unsigned long mask;
} subnet_t;

// Single network rule to match packets against
struct rooti_net_rule {
    subnet_t saddr;
    subnet_t daddr;
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

#endif