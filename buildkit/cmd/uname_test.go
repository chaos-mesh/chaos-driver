package cmd

import (
	"testing"

	"golang.org/x/sys/unix"
)

func TestGetKernelRelease(t *testing.T) {
	var release [65]byte
	copy(release[:], "4.15.0-25-generic\x00")
	kr := getKernelRelease(unix.Utsname{
		Release: release,
	})
	if kr != "4.15.0-25-generic" {
		t.Errorf("Expected 4.15.0-25-generic, got %s", kr)
	}
}

func TestGetKernelVersion(t *testing.T) {
	var version [65]byte
	copy(version[:], "#170-Ubuntu SMP Mon Oct 18 11:38:05 UTC 2021\x00")
	kv := getKernelVersion(unix.Utsname{
		Version: version,
	})
	if kv != 170 {
		t.Errorf("Expected 170, got %d", kv)
	}
}
