chaos_driver-y += main.o chaos_device.o
obj-m += chaos_driver.o

KVERSION = $(shell uname -r)
PWD = $(shell pwd)

ccflags-y := ${KBUILD_FLAGS}

all:
	$(MAKE) -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

test-case:
	$(MAKE) -C /usr/src/linux M=$(PWD) modules

clean:
	$(MAKE) -C /usr/src/linux M=$(PWD) clean
