Fun Linux LKM rootkit I made for learning more about how the kernel works.

The project is still in a pretty rough shape, but these are the currently supported features:
* Local root privilege-escalation for userspace processes
* Hiding files & directories
* Hiding processes
* Hiding open TCP ports
* Hiding logged in users
* Tampering with system randomness utils (/dev/random & /dev/urandom)
* Hiding the rootkit itself
* Two different methods of syscall hooking - syscall table hijacking (works on older kernels) and ftrace callbacks
