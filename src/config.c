#include "config.h"

/*
    Unfortunately the linux kernel ARRAY_SIZE macro cannot be used to assign the result of the calculation
    to a constant variable because the linux macro includes some magic __must_be_array() term to catch invalid use
    of the macro, thus making the expression not constant.
*/
#define ROOTI_CONST_ARRAY_SIZE(arr) sizeof(arr) / sizeof(arr[0]);

const char *ROOTI_HIDDEN_FILES[] = {
    "hideme.txt",
    "dontshowme.txt"
};
const size_t ROOTI_HIDDEN_FILES_COUNT = ROOTI_CONST_ARRAY_SIZE(ROOTI_HIDDEN_FILES);

const char *ROOTI_HIDDEN_FILES_PREFIXES[] = {
    "secret",
    "classified"
};
const size_t ROOTI_HIDDEN_FILES_PREFIXES_COUNT = ROOTI_CONST_ARRAY_SIZE(ROOTI_HIDDEN_FILES_PREFIXES);

const char *ROOTI_HIDDEN_FILES_SUFFIXES[] = {
    "secret",
    "classified"
};
const size_t ROOTI_HIDDEN_FILES_SUFFIXES_COUNT = ROOTI_CONST_ARRAY_SIZE(ROOTI_HIDDEN_FILES_SUFFIXES);