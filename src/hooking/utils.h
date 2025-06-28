#ifndef _ROOTI_HOOKING_UTILS_H
#define _ROOTI_HOOKING_UTILS_H

/*
    Reference to the kallsyms_lookup_name() kernel function which is no longer exported. 
    The address of this pointer is resolved by the initialization function in utils.c
*/
extern unsigned long (*__kallsyms_lookup_name)(const char *name);

inline void rooti_force_write_cr0(unsigned long val);
inline void rooti_unprotect_memory(void);
inline void rooti_protect_memory(void);

#endif