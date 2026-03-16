<p align="center">
    <img src="rooti-logo.png" alt="Rooti Logo" width="350" style="margin: auto">
</p>

## Rooti

Fun Linux LKM rootkit I made for learning more about how the kernel works.<br>
Supports the x86-64 architecture and tested on Linux 6.8.0<br>
**This software is provided for educational and research purposes only**.

These are the currently supported features:
* Privilege escalation to root
* Hiding files & directories
* Hiding processes
* Hiding TCP & UDP connections
* Hiding network packets
* Hiding logged in users
* Hiding the module itself
* Bypassing the local firewall
* Rigging system PRNG utils (/dev/random & /dev/urandom)
* Self unloading from within kernel mode
