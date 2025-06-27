#include <linux/module.h>
#include <linux/types.h>
#include "track.h"

int rooti_track_fd(int fd, struct list_head *list)
{
    // Allocate a new record of an open fd
    struct rooti_tracked_fd *tracked_fd = kmalloc(sizeof(*tracked_fd), GFP_KERNEL);
    if (tracked_fd == NULL) {
        printk(KERN_DEBUG "rooti: failed to allocate memory\n");
        return -ENOMEM;
    }
    tracked_fd->pid = current->pid;
    tracked_fd->fd = fd;

    // Append the new record
    INIT_LIST_HEAD(&tracked_fd->head);
    list_add_tail(&tracked_fd->head, list);

    return 0;
}

void rooti_untrack_fd(struct rooti_tracked_fd *tracked_fd)
{
    // Remove the record from the list and release the memory
    list_del(&tracked_fd->head);
    kfree(tracked_fd);
}

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