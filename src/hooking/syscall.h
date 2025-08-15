#ifndef _ROOTI_HOOKING_SYSCALL_H
#define _ROOTI_HOOKING_SYSCALL_H

// On 64 bit systems, the syscall handler symbols are prefixed with '__x64_'.
#ifdef CONFIG_X86_64
#define ROOTI_SYSCALL_NAME(name) ("__x64_" name)
#else
#define ROOTI_SYSCALL_NAME(name) (name)
#endif

// Shorthand for initializing syscall hook objects
#define ROOTI_SYSCALL_HOOK(_idx, _hook, _orig) \
{ \
    .idx = (_idx), \
    .func = (_hook), \
    .orig = (_orig)  \
}

/*
    Represents a syscall table hook. Installing the hook shall replace the idx's entry in the
    syscall table with the function pointed to by 'func' while saving a reference to the original
    function in 'orig'.
*/ 
struct rooti_syscall_hook {
    unsigned int idx;      // index of the syscall in the kernel syscall table
    void *func;            // pointer to hook function
    void *orig;            // pointer to the original function
};

int rooti_resolve_syscall_table_addr(void);
int rooti_install_syscall_hook(struct rooti_syscall_hook *hook);
int rooti_install_syscall_hooks(struct rooti_syscall_hook *hooks, size_t count);
void rooti_uninstall_syscall_hook(struct rooti_syscall_hook *hook);
void rooti_uninstall_syscall_hooks(struct rooti_syscall_hook *hooks, size_t count);

#endif