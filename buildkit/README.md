# Buildkit

The helper container to help users to build and install chaos-driver

## Usage

```bash
# $(pwd)/driver should be the `driver` path under `chaos-driver` source code
docker run -v $(pwd)/driver:/driver -it chaos-driver-buildkit buildkit -t ubuntu-generic -v 170 -k 4.15.0-162-generic
```

- `-b` represents the directory of driver source code. The default value is `/driver`.
- `-t` specifies the distribution. Supported values: `ubuntu-aws`, `ubuntu-generic`, `centos`, `debian`.
- `-v` specifies the kernel version, which is the first number of `uname -v`. If not specified, buildkit will automatically get through `uname -v`.
- `-k` specifies the kernel release version, which can be get through `uname -r`. If not specified, buildkit will automatically get through `uname -r`.

## TODO

- [x] Automatically build for distributions:
    - [x] CentOS7
    - [x] Debian
    - [x] Ubuntu
    - [x] Ubuntu AWS
- [ ] Automatically install modules
