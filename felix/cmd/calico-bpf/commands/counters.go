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

	"github.com/projectcalico/calico/felix/bpf/counters"

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
	countersDumpCmd.Flags().Bool("all", false, "All interfaces")
	countersFlushCmd.Flags().String("iface", "", "Interface name")
	countersFlushCmd.Flags().Bool("all", false, "All interfaces")
}

var countersDumpCmd = &cobra.Command{
	Use:   "dump",
	Short: "dumps counters",
	Run: func(cmd *cobra.Command, args []string) {
		iface, all := parseFlags(cmd)
		if all || iface == "" {
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
		iface, all := parseFlags(cmd)
		if all || iface == "" {
			doForAllInterfaces(cmd, "flush", flushInterface)
		} else {
			if err := flushInterface(cmd, iface); err != nil {
				log.WithError(err).Error("Failed to flush counter map.")
			}
		}
	},
}

func parseFlags(cmd *cobra.Command) (string, bool) {
	all, err := cmd.Flags().GetBool("all")
	if err != nil {
		log.WithError(err).Error("Failed to parse --all flag.")
	}
	iface, err := cmd.Flags().GetString("iface")
	if err != nil {
		log.WithError(err).Error("Failed to parse interface name.")
	}
	return iface, all
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
	values := make(map[string][]uint32)

	cmd.Printf("===== Interface: %s =====\n", iface)
	for _, hook := range counters.Hooks {
		val, err := bpfCounters.Read(hook)
		if err != nil {
			return fmt.Errorf("Failed to read bpf counters. hook=%s err=%v", hook, err)
		}
		if len(val) < counters.MaxCounterNumber {
			return fmt.Errorf("Failed to read enough data from bpf counters. hook=%s", hook)
		}

		values[hook] = val
	}

	cmd.Printf("\t\t\t\t\tingress\t\tegress\n")
	cmd.Printf("Total packets: \t\t\t\t%d\t\t%d\n",
		values["ingress"][counters.TotalPackets], values["egress"][counters.TotalPackets])

	cmd.Printf("Accepted by failsafe: \t\t\t%d\t\t%d\n",
		values["ingress"][counters.AcceptedByFailsafe], values["egress"][counters.AcceptedByPolicy])
	cmd.Printf("Accepted by policy: \t\t\t%d\t\t%d\n",
		values["ingress"][counters.AcceptedByPolicy], values["egress"][counters.AcceptedByPolicy])

	cmd.Printf("Dropped by policy: \t\t\t%d\t\t%d\n",
		values["ingress"][counters.DroppedByPolicy], values["egress"][counters.DroppedByPolicy])
	cmd.Printf("Dropped short packets: \t\t\t%d\t\t%d\n",
		values["ingress"][counters.DroppedShortPacket], values["egress"][counters.DroppedShortPacket])
	cmd.Printf("Dropped incorrect checksum: \t\t%d\t\t%d\n",
		values["ingress"][counters.DroppedFailedCSUM], values["egress"][counters.DroppedFailedCSUM])
	cmd.Printf("Dropped Packets with IP options: \t%d\t\t%d\n",
		values["ingress"][counters.DroppedIPOptions], values["egress"][counters.DroppedIPOptions])
	cmd.Printf("Dropped malformed IP packets: \t\t%d\t\t%d\n",
		values["ingress"][counters.DroppredIPMalformed], values["egress"][counters.DroppredIPMalformed])
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
