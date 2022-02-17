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

package client

// #include "./client.c"
import "C"

import (
	"errors"
	"math"
	"os"
	"syscall"
	"unsafe"
)

type Client struct {
	fd int
}

const COMPATIBLE_VERSION = 0x1

var ErrIncompatibleVersion = errors.New("incompatible version")
var ErrFailToGetStat = errors.New("failed to get stat")

func New() (*Client, error) {
	fd, err := syscall.Open("/dev/chaos", syscall.O_RDWR, 0)
	if err != nil {
		return nil, err
	}

	if C.get_version(C.int(fd)) != COMPATIBLE_VERSION {
		return nil, ErrIncompatibleVersion
	}

	return &Client{
		fd: fd,
	}, nil
}

func (c *Client) GetVersion() int {
	version := C.get_version(C.int(c.fd))

	return int(version)
}

func (c *Client) InjectIOEMDelay(devPath string, op int, pidNs uint, delay int64, jitter int64, corr float64) (int, error) {
	dev := C.uint32_t(0)
	if len(devPath) > 0 {
		info, err := os.Stat(devPath)
		if err != nil {
			return 0, err
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok {
			return 0, ErrFailToGetStat
		}

		dev = C.uint32_t(stat.Rdev)
	}

	ioem_injection := C.ioem_matcher_arg_new(C.uint32_t(dev), C.int(op), C.uint(pidNs))
	delay_arg := C.ioem_injector_delay_arg_new(C.int64_t(delay), C.int64_t(jitter), C.uint32_t(math.Floor(corr*math.MaxInt32)))

	id := C.add_injection(C.int(c.fd), 0, unsafe.Pointer(&ioem_injection), 0, unsafe.Pointer(&delay_arg))
	if id < 0 {
		return 0, syscall.Errno(-id)
	}

	return int(id), nil
}

func (c *Client) InjectIOEMLimit(devPath string, op int, pidNs uint, period_us uint64, quota uint64) (int, error) {
	dev := C.uint32_t(0)
	if len(devPath) > 0 {
		info, err := os.Stat(devPath)
		if err != nil {
			return 0, err
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok {
			return 0, ErrFailToGetStat
		}

		dev = C.uint32_t(stat.Rdev)
	}

	ioem_injection := C.ioem_matcher_arg_new(C.uint32_t(dev), C.int(op), C.uint(pidNs))
	limit_arg := C.ioem_injector_limit_arg_new(C.uint64_t(period_us), C.uint64_t(quota))

	id := C.add_injection(C.int(c.fd), 0, unsafe.Pointer(&ioem_injection), 1, unsafe.Pointer(&limit_arg))
	if id < 0 {
		return 0, syscall.Errno(-id)
	}

	return int(id), nil
}

func (c *Client) Recover(id int) error {
	err := C.del_injection(C.int(c.fd), C.int(id))
	if err != 0 {
		return syscall.Errno(err)
	}

	return nil
}
