MODNAME := rooti.o
SOURCES_C := $(shell find $(src) -type l -name '*.c' -printf '%P\n')
SOURCES_S := $(shell find $(src) -type l -name '*.S' -printf '%P\n')
OBJECTS += $(SOURCES_C:.c=.o) $(SOURCES_S:.S=.o)

obj-m := $(MODNAME)
rooti-objs := $(OBJECTS)
