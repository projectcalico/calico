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

package daemon

import (
	"context"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/projectcalico/calico/pkg/buildinfo"
)

// NewCommand returns a cobra command that runs the Typha datastore fan-out proxy.
func NewCommand() *cobra.Command {
	var configFile string

	cmd := &cobra.Command{
		Use:   "typha",
		Short: "Run the Typha datastore fan-out proxy",
		Run: func(cmd *cobra.Command, args []string) {
			typha := New()
			if err := typha.Run(context.Background(), configFile); err != nil {
				log.WithError(err).Fatal("Typha exited with error")
			}
		},
	}

	cmd.Flags().StringVarP(&configFile, "config-file", "c", DefaultConfigFile, "Config file to load")
	cmd.AddCommand(&cobra.Command{
		Use:   "version",
		Short: "Print version information",
		Run: func(cmd *cobra.Command, args []string) {
			buildinfo.PrintVersion()
		},
	})

	return cmd
}
