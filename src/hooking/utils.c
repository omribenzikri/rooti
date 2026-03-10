#include <asm/paravirt.h>
#include "utils.h"

/*
    Custom utility function for writing into the CR0 register. It is needed as the original function
    from the linux headers prevents us from modifying the write protection bit.
*/
inline void rooti_force_write_cr0(unsigned long val)
{
    unsigned long __force_order;
    asm volatile("mov %0, %%cr0" : "+r"(val), "+m"(__force_order));
}

inline void rooti_unprotect_memory()
{
    rooti_force_write_cr0(read_cr0() & (~0x10000));
}

inline void rooti_protect_memory()
{
    rooti_force_write_cr0(read_cr0() | (0x10000));
}
