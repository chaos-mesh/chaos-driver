# Chaos Driver

## Usage

The simplest way to use this driver is to build the kernel module, load it and
run the client.

```bash
make all
insmod ./driver/chaos_driver.ko
./target/release/kchaos inject '{"matcher":"bio", "dev": "/dev/sda", "injector": "delay", "delay": 10}'
```

Then the `/dev/sda` device will be injected with a 10 ms delay.

## Build

The buildkit image is prepared to build module on common distributions. You could build this image first:

```
docker build ./buildkit -t chaos-driver-buildkit
```