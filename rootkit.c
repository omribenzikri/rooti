#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Omri Ben Zikri");
MODULE_DESCRIPTION("Very fun rootkit");
MODULE_VERSION("1.0.0");


// LKM initialization
static int __init mod_init(void)
{
    printk(KERN_INFO "rootkit: init\n");

    return 0;
}

// LKM cleanup
static void __exit mod_exit(void)
{
    printk(KERN_INFO "rootkit: exit\n");
}


module_init(mod_init);
module_exit(mod_exit);