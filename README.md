# Chaos Driver

## Build
  
### Build Manually

Run `make all` to build the kernel module. The `KBUILD_PATH` environment variable should point to the kernel source code. By default, it's `/lib/modules/$(uname -r)/build`.

## Usage

After building the kernel module, you could load it by running the following command:

```bash
insmod ./driver/chaos_driver.ko
```

### IOEM

Change the io scheduler of target device into the `ioem`. For example:

```bash
echo ioem-mq |sudo tee /sys/block/sda/queue/scheduler
```

If your system don't support multiqueue IO (which is the default for linux < 4.19), please `echo ioem` rather than `echo ioem-mq`.

Then, you can use the client to send commands to the kernel module:

```bash
sudo ./bin/kchaos inject ioem limit --period-us 1000 --quota 15
```

Then the IOPS of `sda` will be limited to `1000 * 1000 / 1000 * 15 = 15k`, which can be verified by a raw scan through `fio`:

```bash
sudo fio --filename=/dev/sda --direct=1 --rw=randread --bs=4k --ioengine=libaio --iodepth=256 --runtime=120 --numjobs=16 --time_based --group_reporting --name=iops-test-job --eta-newline=1 --readonly

iops-test-job: (g=0): rw=randread, bs=(R) 4096B-4096B, (W) 4096B-4096B, (T) 4096B-4096B, ioengine=libaio, iodepth=256
...
fio-3.7
Starting 16 processes
Jobs: 16 (f=16): [r(16)][3.3%][r=53.8MiB/s,w=0KiB/s][r=13.8k,w=0 IOPS][eta 01m:57s]
Jobs: 16 (f=16): [r(16)][5.0%][r=53.4MiB/s,w=0KiB/s][r=13.7k,w=0 IOPS][eta 01m:55s]
Jobs: 16 (f=16): [r(16)][5.8%][r=56.8MiB/s,w=0KiB/s][r=14.6k,w=0 IOPS][eta 01m:53s]
Jobs: 16 (f=16): [r(16)][7.4%][r=55.5MiB/s,w=0KiB/s][r=14.2k,w=0 IOPS][eta 01m:52s]
Jobs: 16 (f=16): [r(16)][8.3%][r=57.2MiB/s,w=0KiB/s][r=14.6k,w=0 IOPS][eta 01m:50s]
Jobs: 16 (f=16): [r(16)][9.9%][r=55.3MiB/s,w=0KiB/s][r=14.2k,w=0 IOPS][eta 01m:49s]
Jobs: 16 (f=16): [r(16)][10.8%][r=55.5MiB/s,w=0KiB/s][r=14.2k,w=0 IOPS][eta 01m:47s]
```

#### Note

1. multi-queue scheduler registration is only supported on the kernel newer than 4.0, or the rhel kernel released after RHEL 7.6

## Warning

Injecting too much delay on the root device could make your system blocked. Please make sure you have some emergency methods to make the system come back.

## ROADMAP

### Function

- [x] Inject latency
- [x] Traffic controll of IO

### Test 

#### Compatiblity

- [x] Linux 5.12
- [x] Linux 5.4 (Ubuntu 20.04 latest kernel)
- [x] Linux 4.19 (Debian Buster)
- [x] Linux 4.15 (Ubuntu 18.04)
- [x] Linux 3.10 (CentOS 7.9)
- [ ] Linux 3.10 (CentOS 7.2)

#### Function test

- [ ] Inject Latency
    - [x] Basic function
    - [ ] Correlation and jitter
- [x] Traffic controll of IO

### Integrate with Chaos Mesh

- [x] Provide go package
- [ ] Integrate with `chaosd`
- [ ] Integrate with Chaos Mesh
