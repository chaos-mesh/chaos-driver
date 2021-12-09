package cmd

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"strconv"
	"strings"

	"github.com/chaos-mesh/chaos-driver/buildkit/build"
	"github.com/spf13/cobra"
	"golang.org/x/sys/unix"
)

var rootCmd = &cobra.Command{
	Use:   "buildkit",
	Short: "Builtkit is the build script for chaos driver",
	Run: func(cmd *cobra.Command, args []string) {
		target, ok := build.Targets[targetDist]
		if !ok {
			log.Fatalf("target %s is not available", targetDist)
		}

		script, err := target.Script(kernelRelease, buildDir, kernelVersion)
		if err != nil {
			log.Fatal(err)
		}

		err = os.WriteFile("/tmp/build-script.sh", []byte(script), 0644)
		if err != nil {
			log.Fatal(err)
		}

		executor := exec.Command("/bin/bash", "/tmp/build-script.sh")
		executor.Stderr = os.Stderr
		executor.Stdout = os.Stdout
		err = executor.Run()
		if err != nil {
			log.Fatal(err)
		}
	},
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

var targetDist string
var kernelRelease string
var kernelVersion uint16
var buildDir string

func init() {
	rootCmd.PersistentFlags().StringVarP(&targetDist, "target", "t", "", "the target distribution")
	rootCmd.PersistentFlags().StringVarP(&kernelRelease, "kernel", "k", "", "kernel release version, can get through `uname -r`")
	rootCmd.PersistentFlags().Uint16VarP(&kernelVersion, "kernel-version", "v", 0, "kernel version, can get through `uname -v`")
	rootCmd.PersistentFlags().StringVarP(&buildDir, "build-dir", "b", "", "the build directory")

	cobra.OnInitialize(initConfig)
}

func getKernelRelease(u unix.Utsname) string {
	return strings.TrimRight(string(u.Release[:]), "\x00")
}

func getKernelVersion(u unix.Utsname) uint16 {
	versionStr := strings.TrimRight(string(u.Version[:]), "\x00")[1:]
	digit := ""
	for _, c := range versionStr {
		if c >= '0' && c <= '9' {
			digit += string(c)
		} else {
			break
		}
	}
	version, err := strconv.Atoi(digit)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	kernelVersion = uint16(version)

	return kernelVersion
}

func initConfig() {
	utsname := unix.Utsname{}
	unix.Uname(&utsname)

	if kernelRelease == "" {
		kernelRelease = getKernelRelease(utsname)
	}

	if kernelVersion == 0 {
		kernelVersion = getKernelVersion(utsname)
	}

	if buildDir == "" {
		buildDir = "/driver"
	}
}
