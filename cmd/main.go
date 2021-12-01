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

package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/chaos-mesh/chaos-driver/pkg/cmd/inject"
	"github.com/chaos-mesh/chaos-driver/pkg/cmd/recover"
	"github.com/chaos-mesh/chaos-driver/pkg/cmd/version"
)

var rootCmd = &cobra.Command{
	Short: "kchaos is the client to communicate with chaos driver",
	Run: func(cmd *cobra.Command, args []string) {
		// Do Stuff Here
	},
}

func init() {
	rootCmd.AddCommand(inject.Inject)
	rootCmd.AddCommand(version.Version)
	rootCmd.AddCommand(recover.Recover)
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
