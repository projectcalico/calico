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

package main

import (
	"github.com/spf13/cobra"

	"github.com/projectcalico/calico/kube-controllers/pkg/kubecontrollers"
	"github.com/projectcalico/calico/kube-controllers/pkg/status"
)

func newKubeControllersCommand() *cobra.Command {
	var statusFile string

	cmd := &cobra.Command{
		Use:   "kube-controllers",
		Short: "Run the Calico Kubernetes controllers",
		Run: func(cmd *cobra.Command, args []string) {
			kubecontrollers.Run(statusFile)
		},
	}

	cmd.Flags().StringVar(&statusFile, "status-file", status.DefaultStatusFile, "File to write status information to")

	return cmd
}
