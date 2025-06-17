#ifndef _ROOTI_TRACK_H
#define _ROOTI_TRACK_H

/*
    This struct stores some file descriptor that is of interest to us which was opened
    by some usermode process. This struct would be initialized in a hook for some open-like syscall
    and read in a hook for some read-like or write-like syscall whenever we want to tamper with file I/O.
*/
struct rooti_tracked_fd {
    int fd;                 // file descriptor number
    pid_t pid;              // PID of the owner
    struct list_head head;  // linked list head
};

int rooti_track_fd(int fd, struct list_head *list);
void rooti_untrack_fd(struct rooti_tracked_fd *tracked_fd);
bool rooti_is_tracked_fd(int fd, struct list_head *list);

#endif