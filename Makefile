PWD := $(shell pwd)
KDIR := /lib/modules/$(shell uname -r)/build

SOURCE_DIR := src
BUILD_DIR := bin
BUILD_DIR_KBUILD := $(BUILD_DIR)/Kbuild

SOURCES := $(wildcard $(SOURCE_DIR)/*.c)
SOURCES_SYMLINKS = $(subst $(SOURCE_DIR), $(BUILD_DIR), $(SOURCES))

HEADERS := $(wildcard $(SOURCE_DIR)/*.h)
HEADERS_SYMLINKS = $(subst $(SOURCE_DIR), $(BUILD_DIR), $(HEADERS))

all: $(SOURCES_SYMLINKS) $(HEADERS_SYMLINKS) $(BUILD_DIR_KBUILD)
	$(MAKE) -C $(KDIR) M=$(PWD)/$(BUILD_DIR) modules
	rm -f $(SOURCES_SYMLINKS) $(HEADERS_SYMLINKS) $(BUILD_DIR_KBUILD)

$(BUILD_DIR)/%: $(SOURCE_DIR)/% $(BUILD_DIR)
	@ln -sf ../$< $@

$(BUILD_DIR_KBUILD): $(BUILD_DIR)
	cp Kbuild $(BUILD_DIR)

$(BUILD_DIR):
	mkdir -p bin

clean:
	rm -rf $(BUILD_DIR)
