#ifndef _ROOTI_CONFIG_H
#define _ROOTI_CONFIG_H

#include <linux/types.h>
#include <linux/filter.h>
#include "policy.h"

#define INIT_ARRAY(array_raw) { .ptr = array_raw, .len = ARRAY_SIZE(array_raw) }

typedef struct { const char **ptr; size_t len; } string_array_t;
typedef struct { const unsigned long *ptr; size_t len; } ulong_array_t;

struct rooti_config {
    string_array_t hidden_files;
    string_array_t hidden_files_prefixes;
    string_array_t hidden_files_suffixes;
    string_array_t hidden_users;
    ulong_array_t hidden_tcp_ports;
    ulong_array_t hidden_udp_ports;
#ifndef ROOTI_CONFIG_PCAP_FILTER_METHOD_PROG
    struct rooti_net_policy pcap_policy;
#else
    struct sock_fprog_kern pcap_fprog;
#endif
    struct rooti_net_policy firewall_policy;
};

extern const struct rooti_config rooti_config;

#endif
