#include <linux/module.h>
#include <linux/types.h>
#include "track.h"
#include "../utils.h"

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

    // Append the new record
    INIT_LIST_HEAD(&tracked_fd->head);
    list_add_tail(&tracked_fd->head, list);

    return 0;
}

// Removes the given tracked file descriptor from its list
void rooti_untrack_fd(struct rooti_tracked_fd *tracked_fd)
{
    // Remove the record from the list and release the memory
    list_del(&tracked_fd->head);
    kfree(tracked_fd);
}

/*
    Determines whether the given file descriptor is tracked in the given list, with respect
    to the PID of the current process in execution.
*/
bool rooti_is_tracked_fd(int fd, struct list_head *list)
{
    struct rooti_tracked_fd *record;
    list_for_each_entry(record, list, head) {
        if (current->pid == record->pid && fd == record->fd) {
            return true;
        }
    }
    return false;
}