#ifndef _ROOTI_NET_POLICY_H
#define _ROOTI_NET_POLICY_H

#include <linux/skbuff.h>

// Specifies what to do when a packet matches a rule
enum rooti_net_rule_action {
    ROOTI_PACKET_DROP,
    ROOTI_PACKET_ACCEPT
};

// Specifies what to do with unmatched packets
enum rooti_net_policy_type {
    ROOTI_NET_POLICY_WHITELIST,     // drop unmatched packets
    ROOTI_NET_POLICY_BLACKLIST      // accept unmatched packets
};

typedef struct {
    unsigned long prefix;
    unsigned long mask;
} subnet_addr_t;

struct rooti_net_rule {
    subnet_addr_t saddr;
    subnet_addr_t daddr;
    unsigned char protocol;
    unsigned short sport;
    unsigned short dport;
    enum rooti_net_rule_action action;
};

struct rooti_net_policy {
    enum rooti_net_policy_type type;
    struct rooti_net_rule *rules;
    size_t len;
};

bool rooti_match_packet(struct sk_buff *skb, const struct rooti_net_policy *policy,
                        enum rooti_net_rule_action *action);

#endif
