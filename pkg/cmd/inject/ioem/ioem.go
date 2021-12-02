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

package ioem

import (
	"fmt"
	"os"

	"github.com/chaos-mesh/chaos-driver/pkg/client"
	"github.com/spf13/cobra"
)

var dev_path string
var op int
var delay, corr int64
var jitter uint32

var Ioem = &cobra.Command{
	Use: "ioem",
	Run: func(cmd *cobra.Command, args []string) {
		c, err := client.New()
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}

		id, err := c.InjectIOEMDelay(dev_path, op, delay, corr, jitter)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}

		fmt.Printf("Injected: %d\n", id)
	},
}

func init() {
	Ioem.Flags().IntVar(&op, "op", 0, "operation filter of the injection. 0 for all, 1 for write, 2 for read")
	Ioem.MarkFlagRequired("op")

	Ioem.Flags().Int64Var(&delay, "delay", 0, "delay of the injection")
	Ioem.MarkFlagRequired("delay")

	Ioem.Flags().Int64Var(&corr, "corr", 0, "correlation of the randominess of latency")
	Ioem.Flags().Uint32Var(&jitter, "jitter", 0, "jitter of the latency")

	Ioem.Flags().StringVar(&dev_path, "dev_path", "", "path of the injected device")
	Ioem.MarkFlagRequired("dev_path")
}