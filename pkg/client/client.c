// Copyright 2021 Chaos Mesh Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

#include <inttypes.h>
#include <sys/ioctl.h>

struct ioem_matcher_arg {
    uint32_t device;

    // 0 means all
    // 1 means write (include write, write_same, write_zeroes)
    // 2 means read
    int op;
} __attribute__((packed));

static struct ioem_matcher_arg ioem_matcher_arg_new(uint32_t device, int op) {
    struct ioem_matcher_arg ret = {
        .device = device,
        .op = op,
    };
    return ret;
}

struct ioem_injector_delay_arg {
    int64_t delay;
    int64_t jitter;
    uint32_t corr;
} __attribute__((packed));

static struct ioem_injector_delay_arg ioem_injector_delay_arg_new(int64_t delay, int64_t jitter, uint32_t corr) {
    struct ioem_injector_delay_arg ret = {
        .delay = delay,
        .jitter= jitter,
        .corr = corr,
    };

    return ret;
}

struct chaos_injection
{
    uint32_t matcher_type;
    void *matcher_arg;

    uint32_t injector_type;
    void *injector_arg;
} __attribute__((packed));

#define CHAOS_IOCTL_MAGIC 0xC1

#define GET_VERSION_NR 0

static int get_version(int fd) {
  return ioctl(fd, _IO(CHAOS_IOCTL_MAGIC, GET_VERSION_NR), 0);
}

#define ADD_INJECTION_NR 1

static int add_injection(int fd, uint32_t matcher_type, void *matcher_arg, uint32_t injector_type, void *injector_arg) {
    struct chaos_injection injection = {
        .matcher_type = matcher_type,
        .matcher_arg = matcher_arg,

        .injector_type = injector_type,
        .injector_arg = injector_arg,
    };

    return ioctl(fd, _IOW(CHAOS_IOCTL_MAGIC, ADD_INJECTION_NR, struct chaos_injection), &injection);
}

#define DELETE_INJECTION_NR 2

static int del_injection(int fd, int id) {
  return ioctl(fd, _IOC(_IOC_WRITE, CHAOS_IOCTL_MAGIC, DELETE_INJECTION_NR, 0x4), id);
}