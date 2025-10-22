# Define the kernel source directory and module name
KDIR ?= /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)
MODULE_NAME := arm64

# Check for ARM architecture
ARCH := $(shell uname -m)

# Check for ARM architecture and throw an error for non-ARM architectures
ifeq ($(ARCH), armv7l)  # ARMv7 (32-bit)
  # No action needed for ARMv7
else ifeq ($(ARCH), aarch64) # ARM64 (64-bit)
  # No action needed for ARM64
else
  $(error This Makefile is only for ARM architectures. Detected architecture: $(ARCH))
endif

# Specify object files
obj-m := $(MODULE_NAME).o

# Default target
all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

# Clean up generated files
clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean

# Remove module
remove:
	sudo rmmod $(MODULE_NAME)

.PHONY: all clean remove

