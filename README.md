# Chaos Driver

## Build
  
### Build Manually

Run `make all` to build the kernel module. The `KBUILD_PATH` environment variable should point to the kernel source code. By default, it's `/lib/modules/$(uname -r)/build`.

## Usage

After building the kernel module, you could load it by running the following command:

```bash
insmod ./driver/chaos_driver.ko
```

Change the io scheduler of target device into the `ioem`. For example:

```bash
echo ioem-mq |sudo tee /sys/block/sda/queue/scheduler
```

If your system don't support multiqueue IO (which is the default for linux < 4.19), please `echo ioem` rather than `echo ioem-mq`.

Then, you can use the client to send commands to the kernel module:

```bash
./bin/kchaos inject ioem --delay 100000 --op 0 --dev_path /dev/sda
```

Then any io request on the `/dev/sda` device will be injected with 100us delay.

## Warning

Injecting too much delay on the root device could make your system blocked. Please make sure you have some emergency methods to make the system come back.

## ROADMAP

### Function

- [x] Inject latency
- [ ] Traffic controll of IO

### Test 

- [x] Linux 5.12
- [x] Linux 5.4 (Ubuntu 20.04 latest kernel)
- [x] Linux 4.19 (Debian Buster)
- [x] Linux 4.15 (Ubuntu 18.04)
- [ ] Linux 3.10 (CentOS 7)

### Integrate with Chaos Mesh

- [x] Provide go package
- [ ] Integrate with `chaosd`
- [ ] Integrate with Chaos Mesh
