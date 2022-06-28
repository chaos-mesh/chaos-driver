# Chaos Driver

## Install

You can install the Chaos Driver in two ways: install from the package manager, or build manually.

### Packages

#### Arch Linux

If you are using Arch Linux, you can find the package on AUR: [chaos-driver](https://aur.archlinux.org/pkgbase/chaos-driver/). You can install it with the help of any AUR helper. For example:

```bash
yay chaos-driver-dkms
yay kchaos
```

The `chaos-driver-dkms` is the kernel module, and the `kchaos` is the client to communicate with it. After installing the packages, you can load the kernel module through:

```bash
modprobe chaos_driver
```

### Build Manually

#### Client

The client `kchaos` is a normal cgo program. Use the following commands to compile it:

```bash
go build -o ./bin/kchaos ./cmd 
```

#### Kernel Module

Run `make all` to build the kernel module. The `KBUILD_PATH` environment variable should point to the kernel source code or kernel headers, which can be installed through `yum install kernel-devel` or `apt install linux-headers-$(uname -r)` according to your distribution. By default, it's `/lib/modules/$(uname -r)/build`.

After building the kernel module, you could load it by running the following command:

```bash
insmod ./driver/chaos_driver.ko
```

## Usage

### IOEM

Change the io scheduler of target device into the `ioem`. For example:

```bash
echo ioem-mq |sudo tee /sys/block/sda/queue/scheduler
```

If your system don't support multiqueue IO (which is the default for linux < 4.19), please `echo ioem` rather than `echo ioem-mq`.

Then, you can use the client to send commands to the kernel module:

#### Delay

```bash
sudo ./bin/kchaos inject ioem delay --delay 1000000000
```

It will inject 1000000000ns = 1s delay to the device.

```
Jobs: 16 (f=16): [r(16)][3.3%][r=57.2MiB/s,w=0KiB/s][r=14.6k,w=0 IOPS][eta 01m:57s]
Jobs: 16 (f=16): [r(16)][4.1%][r=54.5MiB/s,w=0KiB/s][r=13.0k,w=0 IOPS][eta 01m:56s]
Jobs: 16 (f=16): [r(16)][5.8%][r=55.9MiB/s,w=0KiB/s][r=14.3k,w=0 IOPS][eta 01m:54s] 
Jobs: 16 (f=16): [r(16)][6.6%][r=56.1MiB/s,w=0KiB/s][r=14.4k,w=0 IOPS][eta 01m:53s]
Jobs: 16 (f=16): [r(16)][8.3%][r=54.7MiB/s,w=0KiB/s][r=14.0k,w=0 IOPS][eta 01m:51s] 
# Inject
Jobs: 16 (f=16): [r(16)][9.2%][r=768KiB/s,w=0KiB/s][r=192,w=0 IOPS][eta 01m:49s]   
Jobs: 16 (f=16): [r(16)][10.8%][r=768KiB/s,w=0KiB/s][r=192,w=0 IOPS][eta 01m:47s] 
Jobs: 16 (f=16): [r(16)][12.5%][r=768KiB/s,w=0KiB/s][r=192,w=0 IOPS][eta 01m:45s] 
Jobs: 16 (f=16): [r(16)][14.2%][r=768KiB/s,w=0KiB/s][r=192,w=0 IOPS][eta 01m:43s] 
Jobs: 16 (f=16): [r(16)][15.8%][r=768KiB/s,w=0KiB/s][r=192,w=0 IOPS][eta 01m:41s] 
Jobs: 16 (f=16): [r(16)][17.5%][r=768KiB/s,w=0KiB/s][r=192,w=0 IOPS][eta 01m:39s] 
Jobs: 16 (f=16): [r(16)][19.2%][r=768KiB/s,w=0KiB/s][r=192,w=0 IOPS][eta 01m:37s] 
Jobs: 16 (f=16): [r(16)][20.8%][r=768KiB/s,w=0KiB/s][r=192,w=0 IOPS][eta 01m:35s] 
# Recover
Jobs: 16 (f=16): [r(16)][23.1%][r=23.1MiB/s,w=0KiB/s][r=5902,w=0 IOPS][eta 01m:33s]
Jobs: 16 (f=16): [r(16)][24.2%][r=57.5MiB/s,w=0KiB/s][r=14.7k,w=0 IOPS][eta 01m:31s] 
Jobs: 16 (f=16): [r(16)][26.4%][r=57.6MiB/s,w=0KiB/s][r=14.7k,w=0 IOPS][eta 01m:29s] 
Jobs: 16 (f=16): [r(16)][27.5%][r=57.5MiB/s,w=0KiB/s][r=14.7k,w=0 IOPS][eta 01m:27s] 
Jobs: 16 (f=16): [r(16)][29.2%][r=58.3MiB/s,w=0KiB/s][r=14.9k,w=0 IOPS][eta 01m:25s]
```

#### Note

1. multi-queue scheduler registration is only supported on the kernel newer than 4.0, or the rhel kernel released after RHEL 7.6

#### Warning

1. Injecting too much delay on the root device could make your system blocked. Please make sure you have some emergency methods to make the system come back.
2. Small `period-us` in limit injection will cost a lot of cpu time, and may block the io request of other processes (not selected by the filter) on the same block device. It's always suggested to be set greater than `5000`.

### Syscall Injection

WIP. It's too dangerous to inject long delay in an atomic context, so this function is removed temporarily.

## ROADMAP

### Function

- [x] Inject latency
- [x] Traffic controll of IO
- Package for distributions
    - [x] AUR
    - [ ] Debian
    - [ ] Ubuntu PPA
    - [ ] Fedora
    - [ ] Cent OS

### Test 

#### Compatiblity

- [x] Linux 5.12
- [x] Linux 5.4 (Ubuntu 20.04 latest kernel)
- [x] Linux 4.19 (Debian Buster)
- [x] Linux 4.15 (Ubuntu 18.04)
- [x] Linux 3.10 (CentOS 7.9)
- [x] Linux 3.10 (CentOS 7.6)

#### Function test

- [ ] Inject Latency
    - [x] Basic function
    - [ ] Correlation and jitter
- [x] Traffic controll of IO

### Integrate with Chaos Mesh

- [x] Provide go package
- [ ] Integrate with `chaosd`
- [ ] Integrate with Chaos Mesh

## Kernel Version Support

This module supports kernel >= 3.10, and < 5.16. The kernel removes the `include/elevator.h` in 5.16, which makes it impossible to develop an out of tree elevator module.