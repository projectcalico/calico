// Copyright (c) 2024 Tigera, Inc. All rights reserved.
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

package commands

import (
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/projectcalico/calico/felix/bpf/tc"
	bpfutils "github.com/projectcalico/calico/felix/bpf/utils"
)

func init() {
	rootCmd.AddCommand(cleanUpCmd)
}

var cleanUpCmd = &cobra.Command{
	Use:   "cleanup",
	Short: "Removes all calico-bpf programs and maps",
	Run: func(cmd *cobra.Command, args []string) {
		if err := cleanup(cmd); err != nil {
			log.WithError(err).Error("Failed to dump NAT maps")
		}
	},
}

func cleanup(cmd *cobra.Command) error {
	tc.CleanUpProgramsAndPins()
	bpfutils.RemoveBPFSpecialDevices()
	return nil
}