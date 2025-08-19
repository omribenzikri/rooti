#ifndef _ROOTI_UTILS_H
#define _ROOTI_UTILS_H

#include <linux/printk.h>
#include "config.h"

#ifdef ROOTI_DEBUG_LOGGING
#define ROOTI_DEBUG(fmt, ...) printk(KERN_DEBUG "rooti: " fmt "\n", ##__VA_ARGS__)
#else
#define ROOTI_DEBUG(fmt, ...) ((void)0)
#endif

/*
    Reference to the kallsyms_lookup_name() kernel function which is no longer exported. 
    The address of this function pointer should be filled in during initialization
    by rooti_resolve_kln_addr();
*/
extern unsigned long (*__kallsyms_lookup_name)(const char *name);

int rooti_resolve_kln_addr(void);

#endif