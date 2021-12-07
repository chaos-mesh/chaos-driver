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
	"github.com/chaos-mesh/chaos-driver/pkg/cmd/inject/ioem/delay"
	"github.com/chaos-mesh/chaos-driver/pkg/cmd/inject/ioem/limit"
	"github.com/spf13/cobra"
)

var Ioem = &cobra.Command{
	Use: "ioem",
}

func init() {
	Ioem.AddCommand(delay.Delay)
	Ioem.AddCommand(limit.Limit)
}
