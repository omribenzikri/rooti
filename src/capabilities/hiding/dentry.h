#ifndef _ROOTI_HIDING_DENTRY_H
#define _ROOTI_HIDING_DENTRY_H

#include <linux/types.h>
#include <linux/dirent.h>

size_t rooti_hide_dir_entries(struct linux_dirent64 *user_buf, size_t count, bool is_proc_dir);

#endif
