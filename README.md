<p align="center">
    <img src="rooti-logo.png" alt="Rooti Logo" width="350" style="margin: auto">
</p>

## Rooti

Fun Linux LKM rootkit I made for learning more about how the kernel works.<br>
Supports the x86-64 architecture and tested on Linux 6.8.0<br>
**This software is provided for educational and research purposes only**.

The project is still in a pretty rough shape, but these are the currently supported features:
* Local root privilege-escalation for userspace processes
* Hiding files & directories
* Hiding processes
* Hiding open TCP & UDP ports
* Hiding network traffic from sniffers
* Hiding logged in users
* Hiding the module itself
* Rigging system PRNG utils (/dev/random & /dev/urandom)
* Self deletion from within kernel mode

The rootkit supports a few types of kernel hooks:
* Syscall hooking via syscall table hijacking
* Function hooking via ftrace abuse
* Hooking of function pointers in `struct file_operations` and `struct seq_operations`
