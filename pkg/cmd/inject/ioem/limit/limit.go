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

package limit

import (
	"fmt"
	"os"

	"github.com/chaos-mesh/chaos-driver/pkg/client"
	"github.com/spf13/cobra"
)

var dev_path string
var op int
var period_us, quota uint64

var Limit = &cobra.Command{
	Use: "limit",
	Run: func(cmd *cobra.Command, args []string) {
		c, err := client.New()
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}

		id, err := c.InjectIOEMLimit(dev_path, op, period_us, quota)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}

		fmt.Printf("Injected: %d\n", id)
	},
}

func init() {
	Limit.Flags().IntVar(&op, "op", 0, "operation filter of the injection. 0 for all, 1 for write, 2 for read")
	Limit.Flags().StringVar(&dev_path, "dev_path", "", "path of the injected device")

	Limit.Flags().Uint64Var(&period_us, "period-us", 0, "the period time to reset counter")
	Limit.MarkFlagRequired("period-us")

	Limit.Flags().Uint64Var(&quota, "quota", 0, "the quota of IO during one period")
	Limit.MarkFlagRequired("period-us")
}
