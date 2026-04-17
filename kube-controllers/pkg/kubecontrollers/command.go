// Copyright (c) 2025-2026 Tigera, Inc. All rights reserved.
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

package kubecontrollers

import (
	"context"

	"github.com/spf13/cobra"

	"github.com/projectcalico/calico/kube-controllers/pkg/status"
	"github.com/projectcalico/calico/pkg/cmdwrapper"
)

// innerEnvVar marks the inner (controller-running) process when the command
// re-execs itself to provide cmdwrapper-style restart-on-config-change
// semantics. See cmdwrapper.WrapSelf.
const innerEnvVar = "CALICO_KUBE_CONTROLLERS_INNER"

// NewCommand returns a cobra command that runs the Calico Kubernetes controllers.
// The command wraps itself so that when the controller exits with
// cmdwrapper.RestartReturnCode (on a live config change), the outer process
// re-execs the inner process transparently.
func NewCommand() *cobra.Command {
	var cfg Config

	cmd := &cobra.Command{
		Use:   "kube-controllers",
		Short: "Run the Calico Kubernetes controllers",
		Run: func(cmd *cobra.Command, args []string) {
			cmdwrapper.WrapSelf(innerEnvVar, func() {
				Run(context.Background(), cfg)
			})
		},
	}

	cmd.Flags().StringVar(&cfg.StatusFile, "status-file", status.DefaultStatusFile, "File to write status information to")
	cmd.Flags().IntVar(&cfg.HealthPort, "health-port", 0, "Port to serve HTTP health checks on (0 to disable)")

	return cmd
}
