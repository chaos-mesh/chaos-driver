# Chaos Driver

## Build

### Through buildkit

The buildkit image is developed to help users to build the chaos driver kernel module automatically.

You could build this image first:

```
docker build ./buildkit -t chaos-driver-buildkit
```

Then, you can run this image to build the kernel module:

```
docker run -it -v $(pwd):/driver chaos-driver-buildkit buildkit --target centos
```

#### Supported Distributions

- Cent OS
  
### Build Manually

Run `make all` to build the kernel module. The `KBUILD_PATH` environment variable should point to the kernel source code. By default, it's `/lib/modules/$(uname -r)/build`.

## Usage

After building the kernel module, you could load it by running the following command:

```bash
insmod ./driver/chaos_driver.ko
```

Then, you can use the client to send commands to the kernel module:

```bash
./target/release/kchaos inject '{"matcher":"blk_io", "dev": "/dev/sda", "injector": "delay", "delay": 10}'
```

Then any io operation on the `/dev/sda` device will be injected with 10us delay.

## Warning

All delays are injected with `udelay`, which is backed by a busy loop, so please take care not to inject too long delays, or the system may be stuck and you have to reboot the machine.