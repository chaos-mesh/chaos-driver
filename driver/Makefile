chaos_driver-y += main.o chaos_device.o injection.o ioem.o
obj-m += chaos_driver.o

KERNELRELEASE ?= $(shell uname -r)
KBUILD_PATH ?= /lib/modules/$(KERNELRELEASE)/build
PWD = $(shell pwd)

ccflags-y := ${KBUILD_FLAGS}

all:
	$(MAKE) -C $(KBUILD_PATH) M=$(PWD) modules

clean:
	$(MAKE) -C $(KBUILD_PATH) M=$(PWD) clean
