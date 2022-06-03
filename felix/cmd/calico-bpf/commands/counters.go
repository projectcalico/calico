// Copyright (c) 2022 Tigera, Inc. All rights reserved.
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
	"fmt"

	"github.com/projectcalico/calico/felix/bpf/counters"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

func init() {
	countersCmd.AddCommand(countersDumpCmd)
	countersCmd.AddCommand(countersFlushCmd)
	rootCmd.AddCommand(countersCmd)

	countersDumpCmd.Flags().String("iface", "", "Interface name")
	countersFlushCmd.Flags().String("iface", "", "Interface name")
}

var countersDumpCmd = &cobra.Command{
	Use:   "dump",
	Short: "dumps counters",
	Run: func(cmd *cobra.Command, args []string) {
		iface, err := cmd.Flags().GetString("iface")
		if err != nil {
			log.WithError(err).Error("Failed to parse interface name. Will dump all counters")
			iface = ""
		}

		if err = dumpCounters(iface); err != nil {
			log.WithError(err).Error("Failed to dump counter map.")
		}
	},
}

var countersFlushCmd = &cobra.Command{
	Use:   "flush",
	Short: "flush counters",
	Run: func(cmd *cobra.Command, args []string) {
		iface, err := cmd.Flags().GetString("iface")
		if err != nil {
			log.WithError(err).Error("Failed to parse interface name. Will dump flush counters")
			iface = ""
		}

		if err := flushCounters(iface); err != nil {
			log.WithError(err).Error("Failed to flush counter map.")
		}
	},
}

// countersCmd represents the counters command
var countersCmd = &cobra.Command{
	Use:   "counters",
	Short: "Show and reset counters",
}

func dumpCounters(iface string) error {
	fmt.Printf("iface: %s\n", iface)
	bpfCounters := counters.NewCounters(iface, "ingress")
	values, err := bpfCounters.Read()
	if err != nil {
		return fmt.Errorf("Failed to read bpf counters: %v", err)
	}

	for _, c := range values {
		fmt.Println(c)
	}

	return nil
}

func flushCounters(iface string) error {
	fmt.Printf("iface: %s\n", iface)
	fmt.Println("Not yet implemented.")
	return nil
}
