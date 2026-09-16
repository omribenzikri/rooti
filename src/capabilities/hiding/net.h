#ifndef _ROOTI_HIDING_NET_H
#define _ROOTI_HIDING_NET_H

#include <linux/socket.h>
#include <linux/filter.h>
#include "../../config.h"

#ifdef ROOTI_PCAP_FILTER_METHOD_PROG
int rooti_inject_packet_filter(struct sock *sock, struct sock_fprog __user *user_fprog);
int rooti_overwrite_packet_filter(struct sock *sock);
#endif

#endif
