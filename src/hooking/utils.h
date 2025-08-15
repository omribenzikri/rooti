#ifndef _ROOTI_HOOKING_UTILS_H
#define _ROOTI_HOOKING_UTILS_H

inline void rooti_force_write_cr0(unsigned long val);
inline void rooti_unprotect_memory(void);
inline void rooti_protect_memory(void);

#endif