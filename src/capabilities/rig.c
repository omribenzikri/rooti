#include <linux/module.h>
#include "rig.h"

int rooti_rig_random_buf(char *user_buf, size_t count)
{
    // Allocate kernel buffer filled with zeros
    char *kernel_buf = kzalloc(count, GFP_KERNEL);
    if (kernel_buf == NULL) {
        printk(KERN_DEBUG "rooti: failed to allocate memory\n");
        return -ENOMEM;
    }
    // Coppy rigged kernel buffer into userspace buffer
    int err = copy_to_user(user_buf, kernel_buf, count);
    if (err > 0) {
        printk(KERN_DEBUG "rooti: copy_to_user() failed\n");
        kfree(kernel_buf);
        return -EFAULT;
    }
    kfree(kernel_buf);
    return 0;
}