#include <linux/kprobes.h>
#include <linux/string.h>
#include "utils.h"

unsigned long (*__kallsyms_lookup_name)(const char *name) = NULL;

/* 
    Since kernel version 5.7.7 - kallsyms_lookup_name() is no longer exported to out-of-tree modules.
    We can work around this by probing the kallsyms_lookup_name() function, which will find us its 
    memory address.
*/
int rooti_resolve_kln_addr()
{
    struct kprobe kp;
    memset(&kp, 0, sizeof(kp));
    kp.symbol_name = "kallsyms_lookup_name";

    int err = register_kprobe(&kp);
    if (err) {
        ROOTI_DEBUG("register_kprobe() failed: %d", err);
        return err;
    }
    __kallsyms_lookup_name = (unsigned long (*)(const char *name))kp.addr;
    unregister_kprobe(&kp);

    return 0;
}