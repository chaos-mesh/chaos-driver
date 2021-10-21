package cmd

import (
	"fmt"
	"log"
	"os"
	"os/exec"

	"github.com/chaos-mesh/chaos-driver/buildkit/build"
	"github.com/spf13/cobra"
	"golang.org/x/sys/unix"
)

var rootCmd = &cobra.Command{
	Use:   "buildkit",
	Short: "Builtkit is the build script for chaos driver",
	Run: func(cmd *cobra.Command, args []string) {
		target, ok := build.Targets[target]
		if !ok {
			log.Fatalf("target %s is not available", target)
		}

		script, err := target.Script(kernelVersion, buildDir)
		if err != nil {
			log.Fatal(err)
		}

		err = os.WriteFile("/tmp/build-script.sh", []byte(script), 0644)
		if err != nil {
			log.Fatal(err)
		}

		executor := exec.Command("/bin/bash", "/tmp/build-script.sh")
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

var target string
var kernelVersion string
var buildDir string

func init() {
	cobra.OnInitialize(initConfig)

	rootCmd.PersistentFlags().StringVarP(&target, "target", "t", "", "the target distribution")
	rootCmd.PersistentFlags().StringVarP(&kernelVersion, "kernel", "k", "", "kernel version")
	rootCmd.PersistentFlags().StringVarP(&buildDir, "build-dir", "b", "", "the build directory")
}

func initConfig() {
	if kernelVersion == "" {
		utsname := unix.Utsname{}
		unix.Uname(&utsname)

		kernelVersion = string(utsname.Release[:])
	}

	if buildDir == "" {
		buildDir = "/driver"
	}
}
