#ifndef _ROOTI_UTILS_H
#define _ROOTI_UTILS_H

#include "config.h"

#ifdef ROOTI_DEBUG_LOGGING
#define ROOTI_DEBUG(fmt, ...) printk(KERN_DEBUG "rooti: " fmt "\n", ##__VA_ARGS__)
#else
#define ROOTI_DEBUG(fmt, ...) ((void)0)
#endif

#endif