PWD := $(shell pwd)
KDIR := /lib/modules/$(shell uname -r)/build

SOURCE_DIR := src
BUILD_DIR := bin
BUILD_DIR_KBUILD := $(BUILD_DIR)/Kbuild
BUILD_DIR_SUBDIRS = $(subst $(SOURCE_DIR), $(BUILD_DIR), $(shell find $(SOURCE_DIR) -type d))

SOURCES := $(shell find src -type f -name '*.c') $(shell find src -type f -name '*.S')
SOURCES_SYMLINKS = $(subst $(SOURCE_DIR), $(BUILD_DIR), $(SOURCES))

HEADERS := $(shell find src -type f -name '*.h')
HEADERS_SYMLINKS = $(subst $(SOURCE_DIR), $(BUILD_DIR), $(HEADERS))

.ONESHELL:

all: $(SOURCES_SYMLINKS) $(HEADERS_SYMLINKS) $(BUILD_DIR_KBUILD)
	@trap "rm -f $(SOURCES_SYMLINKS) $(HEADERS_SYMLINKS) $(BUILD_DIR_KBUILD)" EXIT INT TERM;
	$(MAKE) -C $(KDIR) M=$(PWD)/$(BUILD_DIR) modules

$(BUILD_DIR)/%: $(SOURCE_DIR)/% $(BUILD_DIR)
	@ln -sf $(PWD)/$< $@

$(BUILD_DIR_KBUILD): $(BUILD_DIR)
	@cp Kbuild $(BUILD_DIR)

$(BUILD_DIR):
	@mkdir -p $(BUILD_DIR_SUBDIRS)

clean:
	rm -rf $(BUILD_DIR)
