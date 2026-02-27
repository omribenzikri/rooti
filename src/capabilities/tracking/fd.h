#ifndef _ROOTI_TRACKING_FD_H
#define _ROOTI_TRACKING_FD_H

struct rooti_tracked_fd {
    int fd;
    pid_t pid;
    struct list_head head;
};

int rooti_track_fd(int fd, struct list_head *list);
void rooti_untrack_fd(struct rooti_tracked_fd *tracked_fd);

struct rooti_tracked_fd *rooti_search_tracked_fd(int fd, struct list_head *list);
bool rooti_is_tracked_fd(int fd, struct list_head *list);
void rooti_clear_fd_tracking(struct list_head *list);

#endif