#include <linux/slab.h>
#include <linux/mutex.h>
#include <linux/list.h>
#include "process.h"
#include "../../utils.h"

DEFINE_MUTEX(rooti_proc_tracking_mutex);

int rooti_track_proc(pid_t pid, struct rooti_tracked_proc **dest, struct list_head *list)
{
    struct rooti_tracked_proc *tracked_proc = kzalloc(sizeof(*tracked_proc), GFP_KERNEL);
    if (tracked_proc == NULL) {
        ROOTI_DEBUG("failed to allocate memory");
        return -ENOMEM;
    }
    tracked_proc->pid = pid;
    INIT_LIST_HEAD(&tracked_proc->head);

    mutex_lock(&rooti_proc_tracking_mutex);
    list_add_tail_rcu(&tracked_proc->head, list);
    mutex_unlock(&rooti_proc_tracking_mutex);

    *dest = tracked_proc;
    return 0;
}

int rooti_track_proc_attr(pid_t pid, enum rooti_proc_attr attr, struct list_head *list)
{
    struct rooti_tracked_proc *tracked_proc = rooti_search_tracked_proc(pid, list);
    int err;

    if (tracked_proc == NULL) {
        err = rooti_track_proc(pid, &tracked_proc, list);
        if (err) {
            return err;
        }
    }

    set_bit(attr, &tracked_proc->attrs);
    return 0;
}

void rooti_untrack_proc(struct rooti_tracked_proc *tracked_proc)
{
    mutex_lock(&rooti_proc_tracking_mutex);
    list_del_rcu(&tracked_proc->head);
    mutex_unlock(&rooti_proc_tracking_mutex);
    synchronize_rcu();
    kfree(tracked_proc);
}

void rooti_untrack_proc_attr(pid_t pid, enum rooti_proc_attr attr, struct list_head *list)
{
    struct rooti_tracked_proc *tracked_proc = rooti_search_tracked_proc(pid, list);
    if (tracked_proc == NULL) return;

    clear_bit(attr, &tracked_proc->attrs);
    if (tracked_proc->attrs == 0) {
        rooti_untrack_proc(tracked_proc);
    }
} 

struct rooti_tracked_proc *rooti_search_tracked_proc(pid_t pid, struct list_head *list)
{
    struct rooti_tracked_proc *curr_record = NULL;
    struct rooti_tracked_proc *found_record = NULL;

    rcu_read_lock();
    list_for_each_entry_rcu(curr_record, list, head) {
        if (curr_record->pid == pid) {
            found_record = curr_record;
            break;
        }
    }
    rcu_read_unlock();
    return found_record;
}