#include <linux/array_size.h>
#include "config.h"

const char *ROOTI_HIDDEN_FILES[] = {
    "hideme.txt",
    "dontshowme.txt"
};
const size_t ROOTI_HIDDEN_FILES_COUNT = sizeof(ROOTI_HIDDEN_FILES) /
                                        sizeof(ROOTI_HIDDEN_FILES[0]);

const char *ROOTI_HIDDEN_FILES_PREFIXES[] = {
    "secret",
    "classified"
};
const size_t ROOTI_HIDDEN_FILES_PREFIXES_COUNT = sizeof(ROOTI_HIDDEN_FILES_PREFIXES) /
                                                 sizeof(ROOTI_HIDDEN_FILES_PREFIXES[0]);

const char *ROOTI_HIDDEN_FILES_SUFFIXES[] = {
    "secret",
    "classified"
};
const size_t ROOTI_HIDDEN_FILES_SUFFIXES_COUNT = sizeof(ROOTI_HIDDEN_FILES_SUFFIXES) /
                                                 sizeof(ROOTI_HIDDEN_FILES_SUFFIXES[0]);