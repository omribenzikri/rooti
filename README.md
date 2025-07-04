Fun Linux LKM rootkit I made for learning more about how the kernel works.

The project is still in a pretty rough shape, but these are the currently supported features:
* Local root privilege-escalation for userspace processes
* Hiding files & directories
* Hiding processes
* Hiding open TCP & UDP ports
* Hiding logged in users
* Hiding the rootkit itself
* Rigging system PRNG utils (/dev/random & /dev/urandom)

The rootkit sports supports a few types of kernel hooks:
* Syscall hooking via syscall table hijacking
* Function hooking via ftrace abuse
* Hooking of function pointers in `struct file_operations` and `struct seq_operations`
