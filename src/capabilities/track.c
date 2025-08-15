#include <linux/module.h>
#include <linux/types.h>
#include "track.h"
#include "../utils.h"

DEFINE_MUTEX(rooti_track_mutex);


// Append a new tracked file descriptor record into the supplied list
int rooti_track_fd(int fd, struct list_head *list)
{
    // Allocate a new record of an open fd
    struct rooti_tracked_fd *tracked_fd = kmalloc(sizeof(*tracked_fd), GFP_KERNEL);
    if (tracked_fd == NULL) {
        ROOTI_DEBUG("failed to allocate memory");
        return -ENOMEM;
    }
    tracked_fd->pid = current->pid;
    tracked_fd->fd = fd;

    // Initialize a new list node
    INIT_LIST_HEAD(&tracked_fd->head);

    // Append newly created node
    mutex_lock(&rooti_track_mutex);
    list_add_tail_rcu(&tracked_fd->head, list);
    mutex_unlock(&rooti_track_mutex);

    return 0;
}

// Removes the given tracked file descriptor from its list and releases its descriptor
void rooti_untrack_fd(struct rooti_tracked_fd *tracked_fd)
{
    mutex_lock(&rooti_track_mutex);
    list_del_rcu(&tracked_fd->head);
    mutex_unlock(&rooti_track_mutex);
    synchronize_rcu();
    kfree(tracked_fd);
}

/*
    Determines whether the given file descriptor is tracked in the given list, with respect
    to the PID of the current process in execution.
*/
bool rooti_is_tracked_fd(int fd, struct list_head *list)
{
    struct rooti_tracked_fd *record;
    bool found = false;

    rcu_read_lock();
    list_for_each_entry_rcu(record, list, head) {
        if (current->pid == record->pid && fd == record->fd) {
            found = true;
            break;
        }
    }
    rcu_read_unlock();
    return found;
}