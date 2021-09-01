chaos_driver-y += main.o chaos_device.o injection.o syscall_tracepoint.o
obj-m += chaos_driver.o

KVERSION ?= $(shell uname -r)
PWD = $(shell pwd)

ccflags-y := ${KBUILD_FLAGS}

all:
	$(MAKE) -C /lib/modules/$(KVERSION)/build M=$(PWD) modules

test-case:
	$(MAKE) -C /usr/src/linux M=$(PWD) modules

clean:
	$(MAKE) -C /usr/src/linux M=$(PWD) clean
