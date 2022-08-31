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
	"net"
	"os"

	"github.com/projectcalico/calico/felix/bpf"
	"github.com/projectcalico/calico/felix/bpf/counters"

	"github.com/olekukonko/tablewriter"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

// countersCmd represents the counters command
var countersCmd = &cobra.Command{
	Use:   "counters",
	Short: "Show and reset counters",
}

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
		iface := parseFlags(cmd)
		if iface == "" {
			doForAllInterfaces(cmd, "dump", dumpInterface)
		} else {
			if err := dumpInterface(cmd, iface); err != nil {
				log.WithError(err).Error("Failed to dump counter map.")
			}
		}
	},
}

var countersFlushCmd = &cobra.Command{
	Use:   "flush",
	Short: "flush counters",
	Run: func(cmd *cobra.Command, args []string) {
		iface := parseFlags(cmd)
		if iface == "" {
			doForAllInterfaces(cmd, "flush", flushInterface)
		} else {
			if err := flushInterface(cmd, iface); err != nil {
				log.WithError(err).Error("Failed to flush counter map.")
			}
		}
	},
}

func parseFlags(cmd *cobra.Command) string {
	iface, err := cmd.Flags().GetString("iface")
	if err != nil {
		log.WithError(err).Error("Failed to parse interface name.")
	}
	return iface
}

func doForAllInterfaces(cmd *cobra.Command, action string, fn func(cmd *cobra.Command, iface string) error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		log.WithError(err).Error("failed to get list of interfaces.")
		return
	}
	for _, i := range interfaces {
		err = fn(cmd, i.Name)
		if err != nil {
			log.Errorf("Failed to %s interface %s", action, i.Name)
			continue
		}
	}
}

func dumpInterface(cmd *cobra.Command, iface string) error {
	if iface == "" {
		return fmt.Errorf("empty interface name")
	}

	bpfCounters := counters.NewCounters(iface)
	values, err := bpfCounters.Read()
	if err != nil {
		return fmt.Errorf("Failed to read bpf counters. iface=%s err=%v", iface, err)
	}

	table := tablewriter.NewWriter(os.Stdout)
	table.SetCaption(true, fmt.Sprintf("dumped %s counters.", iface))
	table.SetHeader([]string{"CATEGORY", "TYPE", "INGRESS", "EGRESS", "XDP"})

	var rows [][]string
	for _, c := range counters.Descriptions() {
		newRow := []string{c.Category, c.Caption}
		// Now add value related to each hook, i.e. ingress, egress and XDP
		for index := range bpf.Hooks {
			newRow = append(newRow, fmt.Sprintf("%v", values[index][c.Counter]))
		}
		rows = append(rows, newRow)
	}
	table.AppendBulk(rows)
	table.SetAutoMergeCells(true)
	table.SetAutoMergeCellsByColumnIndex([]int{0})
	table.Render()
	return nil
}

func flushInterface(cmd *cobra.Command, iface string) error {
	bpfCounters := counters.NewCounters(iface)
	err := bpfCounters.Flush()
	if err != nil {
		return fmt.Errorf("Failed to flush bpf counters for interface=%s", iface)
	}
	log.Infof("Successfully flushed bpf counters for interface=%s", iface)
	return nil
}
