# Chaos Driver

The chaos driver is a kernel module to provide a tool to inject error through some kernel mechanisms. As the tracing problem is isomorphic to the injection problem, it will use a lot of tracing technology to implement.

The injection can be done by the following methods in several different places:

1. `tracepoint`. The typical usage of `tracepoint` is to inject syscall, with the `syscall_enter_probe` and `syscall_exit_probe`.
2. `uprobe`. The `uprobe` is hooked in an offset of an `inode`. When some process `call` the function at that place, the `uprobe` will be triggered. Though the injected function is in userspace, the `uprobe` codes are running in kernel space.
3. `kprobe`
4. `ftrace`

## Overall Structure

One injection can be described with an "event listener" and an "injector". Different kinds of event listener should be equipped with different kinds of injectors, as different events will provide different information, and the injectors could do different things according to these information.

## Userspace Communication

All communication are through `/dev/chaos`, and the `ioctl` system calls. All following sections could be sent with the `ioctl` syscall. For example, the "Add Injection" could be used by calling `ioctl(fd, ADD_INJECTION, void *arg)`, where the `arg` is a `struct add_injection*` described below.

All structs below are fully packed, with no padding. The return number is always zero or positive, when it's negative, it means the opposite of the error number.

### Get Version

The argument will never be read, so it could be nil. The return value will be an integer, which shows the version of loaded module.

### Add Injection

```c
struct chaos_injection {
    __u32 matcher_type;
    void* matcher_arg;
    size_t matcher_arg_size;
    
    __u32 injector_type;
    void* injector_arg;
    size_t injector_arg_size;
}
```

The `matcher_arg` and `injector_arg` will be copied from the userspace, and the driver will use them to construct/store the injection.

```c
struct add_injection {
    struct chaos_injection injection;
}
```

The return value will be the id of the injection, with which you can delete the injection.

### Delete Injection

```c
struct delete_injection {
    __u32 id;
}
```

## TODO

1. There are a lot of lists. However, some of them should use a hash table.