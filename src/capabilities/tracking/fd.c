#include <linux/module.h>
#include <linux/types.h>
#include "fd.h"
#include "../../utils.h"

DEFINE_MUTEX(rooti_track_mutex);

int rooti_track_fd(int fd, struct list_head *list)
{
    struct rooti_tracked_fd *tracked_fd = kmalloc(sizeof(*tracked_fd), GFP_KERNEL);
    if (tracked_fd == NULL) {
        ROOTI_DEBUG("failed to allocate memory");
        return -ENOMEM;
    }
    tracked_fd->pid = current->pid;
    tracked_fd->fd = fd;

    INIT_LIST_HEAD(&tracked_fd->head);

    mutex_lock(&rooti_track_mutex);
    list_add_tail_rcu(&tracked_fd->head, list);
    mutex_unlock(&rooti_track_mutex);

    return 0;
}

void rooti_untrack_fd(struct rooti_tracked_fd *tracked_fd)
{
    mutex_lock(&rooti_track_mutex);
    list_del_rcu(&tracked_fd->head);
    mutex_unlock(&rooti_track_mutex);
    synchronize_rcu();
    kfree(tracked_fd);
}

struct rooti_tracked_fd *rooti_search_tracked_fd(int fd, struct list_head *list)
{
    struct rooti_tracked_fd *curr_record = NULL;
    struct rooti_tracked_fd *found_record = NULL;

    rcu_read_lock();
    list_for_each_entry_rcu(curr_record, list, head) {
        if (current->pid == curr_record->pid && fd == curr_record->fd) {
            found_record = curr_record;
            break;
        }
    }
    rcu_read_unlock();
    return found_record;
}


bool rooti_is_tracked_fd(int fd, struct list_head *list)
{
    return rooti_search_tracked_fd(fd, list) != NULL;
}

void rooti_clear_fd_tracking(struct list_head *list)
{
    struct rooti_tracked_fd *record;
    struct rooti_tracked_fd *tmp;

    list_for_each_entry_safe(record, tmp, list, head) {
        ROOTI_DEBUG("I have a record to clear!");
        rooti_untrack_fd(record);
    }
}