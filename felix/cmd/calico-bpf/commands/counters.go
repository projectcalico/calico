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

	"github.com/olekukonko/tablewriter"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/projectcalico/calico/felix/bpf/counters"
	"github.com/projectcalico/calico/felix/bpf/hook"
	"github.com/projectcalico/calico/felix/bpf/maps"
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
		m := counters.Map()
		if err := m.Open(); err != nil {
			log.WithError(err).Error("Failed to open counter map.")
			return
		}
		defer m.Close()

		if iface == "" {
			doForAllInterfaces("dump", dumpInterface)
		} else {
			i, err := net.InterfaceByName(iface)
			if err != nil {
				log.WithError(err).Errorf("No such interface: %s", iface)
				return
			}
			if err := dumpInterface(m, i); err != nil {
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
		m := counters.Map()
		if err := m.Open(); err != nil {
			log.WithError(err).Error("Failed to open counter map.")
			return
		}
		defer m.Close()

		if iface == "" {
			doForAllInterfaces("flush", flushInterface)
		} else {
			i, err := net.InterfaceByName(iface)
			if err != nil {
				log.WithError(err).Errorf("No such interface: %s", iface)
				return
			}
			if err := flushInterface(m, i); err != nil {
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

func doForAllInterfaces(action string, fn func(maps.Map, *net.Interface) error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		log.WithError(err).Error("failed to get list of interfaces.")
		return
	}

	m := counters.Map()
	if err := m.Open(); err != nil {
		log.WithError(err).Error("Failed to open counter map.")
		return
	}
	defer m.Close()

	for _, i := range interfaces {
		err = fn(m, &i)
		if err != nil {
			log.WithError(err).Errorf("Failed to %s interface %s", action, i.Name)
			continue
		}
	}
}

func dumpInterface(m maps.Map, iface *net.Interface) error {
	values := make([][]uint64, len(hook.All))
	for _, hook := range hook.All {
		val, err := counters.Read(m, iface.Index, hook)
		if err != nil {
			continue
		}
		if len(val) < counters.MaxCounterNumber {
			return fmt.Errorf("failed to read enough data from bpf counters. iface=%v hook=%s", iface.Name, hook)
		}
		values[hook] = val
	}

	table := tablewriter.NewWriter(os.Stdout)
	table.SetCaption(true, fmt.Sprintf("dumped %s counters.", iface.Name))
	table.SetHeader([]string{"CATEGORY", "TYPE", "INGRESS", "EGRESS", "XDP"})

	var rows [][]string
	for _, c := range counters.Descriptions() {
		newRow := []string{c.Category, c.Caption}
		// Now add value related to each hook, i.e. ingress, egress and XDP
		for hook := range hook.All {
			if values[hook] == nil {
				newRow = append(newRow, "N/A")
			} else {
				newRow = append(newRow, fmt.Sprintf("%v", values[hook][c.Counter]))
			}
		}
		rows = append(rows, newRow)
	}
	table.AppendBulk(rows)
	table.SetAutoMergeCells(true)
	table.SetAutoMergeCellsByColumnIndex([]int{0})
	table.Render()
	return nil
}

func flushInterface(m maps.Map, iface *net.Interface) error {
	for _, hook := range hook.All {
		err := counters.Flush(m, iface.Index, hook)
		if err != nil {
			log.Infof("Failed to flush bpf counters for interface=%s hook=%s err=%v", iface.Name, hook, err)
		} else {
			log.Infof("Successfully flushed counters map for interface=%s hook=%s", iface.Name, hook)
		}
	}
	return nil
}
