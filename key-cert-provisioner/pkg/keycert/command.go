// Copyright (c) 2026 Tigera, Inc. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package keycert

import (
	"context"

	"github.com/spf13/cobra"
)

// NewCommand returns a cobra command that runs the TLS certificate provisioner.
func NewCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "key-cert-provisioner",
		Short: "Run the TLS certificate provisioner",
		Run: func(cmd *cobra.Command, args []string) {
			Run(context.Background())
		},
	}
}
