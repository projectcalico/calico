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

package datastore

import (
	"github.com/spf13/cobra"
)

// BuildMigrateArgs constructs the args slice expected by the existing
// docopt-based migrate subcommand functions from cobra flag values.
func BuildMigrateArgs(subcommand string, cmd *cobra.Command) []string {
	args := []string{"datastore", "migrate", subcommand}

	if config, _ := cmd.Flags().GetString("config"); config != "" {
		args = append(args, "--config="+config)
	}
	if filename, _ := cmd.Flags().GetString("filename"); filename != "" {
		args = append(args, "--filename="+filename)
	}
	if allowMismatch, _ := cmd.Root().Flags().GetBool("allow-version-mismatch"); allowMismatch {
		args = append(args, "--allow-version-mismatch")
	}
	return args
}
