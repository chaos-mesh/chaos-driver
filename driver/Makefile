chaos_driver-y += main.o chaos_device.o injection.o syscall_tracepoint.o fs_injection.o blk_io_injection.o lazy_list.o ioem.o
obj-m += chaos_driver.o

KVERSION ?= $(shell uname -r)
KBUILD_PATH ?= /lib/modules/$(KVERSION)/build
PWD = $(shell pwd)

ccflags-y := ${KBUILD_FLAGS}

all:
	$(MAKE) -C $(KBUILD_PATH) M=$(PWD) modules

clean:
	$(MAKE) -C $(KBUILD_PATH) M=$(PWD) clean
