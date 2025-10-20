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
    This macro declares a local pointer to a kernel symbol named 'symbol' whose address
    is resolved by using kallsyms_lookup_name(). The generated symbol is the same as 'symbol' with two
    leading underscores. On error, 'error_value' is returned.
*/
#define ROOTI_RESOLVE_SYM_ADDR(type, symbol, error_value)               \
type __##symbol = (type)__kallsyms_lookup_name(#symbol);                \
if (__##symbol == NULL) {                                               \
    ROOTI_DEBUG("unresolved symbol '%s'", #symbol);                     \
    return error_value;                                                 \
}

/*
    Just like the macro above but specifically for function pointers. The function signature is typedef'ed
    as <symbol>_t and is constructed by:  'return_type' and the following variable number of args which
    specify the argument types in order. 
*/
#define ROOTI_RESOLVE_FUNC_ADDR(symbol, error_value, return_type, ...)  \
typedef return_type (*symbol##_t)(__VA_ARGS__);                         \
ROOTI_RESOLVE_SYM_ADDR(symbol##_t, symbol, error_value)

/*
    Reference to the kallsyms_lookup_name() kernel function which is no longer exported. 
    The address of this function pointer should be filled in during initialization
    by rooti_resolve_kln_addr();
*/
extern unsigned long (*__kallsyms_lookup_name)(const char *name);

int rooti_resolve_kln_addr(void);

#endif