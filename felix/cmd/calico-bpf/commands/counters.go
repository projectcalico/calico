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

		if err = dumpCounters(cmd, iface); err != nil {
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
			log.WithError(err).Error("Failed to parse interface name.")
			return
		}
		if iface == "" {
			log.Error("Empty interface name.")
			return
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

func dumpCounters(cmd *cobra.Command, iface string) error {
	if iface != "" {
		return dumpIfaceCounters(cmd, iface)
	} else {
		interfaces, err := net.Interfaces()
		if err != nil {
			return fmt.Errorf("failed to get list of interfaces. err=%v", err)
		}
		for _, i := range interfaces {
			err = dumpIfaceCounters(cmd, i.Name)
			if err != nil {
				log.Errorf("Failed to dump %v counters", i.Name)
				continue
			}
		}
	}
	return nil
}

func dumpIfaceCounters(cmd *cobra.Command, iface string) error {
	if iface == "" {
		return fmt.Errorf("empty interface name")
	}
	bpfCounters := counters.NewCounters(iface)
	ingressValues, err := bpfCounters.ReadIngress()
	if err != nil {
		return fmt.Errorf("Failed to read bpf ingress counters: %v", err)
	}
	if len(ingressValues) < counters.MaxCounterNumber {
		return fmt.Errorf("Failed to read enough data from bpf ingress counters")
	}

	egressValues, err := bpfCounters.ReadEgress()
	if err != nil {
		return fmt.Errorf("Failed to read bpf egress counters: %v", err)
	}
	if len(egressValues) < counters.MaxCounterNumber {
		return fmt.Errorf("Failed to read enough data from bpf egress counters")
	}

	cmd.Printf("===== Interface: %s =====\n", iface)
	for _, hook := range []string{"Ingress", "Egress", "XDP"} {
		cmd.Printf("%s:\n", hook)
		cmd.Printf("\tTotal Packets: %d\n", ingressValues[counters.TotalPackets])
		cmd.Printf("\tShort Packets: %d\n", ingressValues[counters.ErrShortPacket])
	}
	return nil
}

func flushCounters(iface string) error {
	bpfCounters := counters.NewCounters(iface)
	err := bpfCounters.FlushIngress()
	if err != nil {
		return fmt.Errorf("Failed to flush ingress bpf counters for interface %s. err=%v", iface, err)
	}
	log.Infof("Successfully flushed ingress counters map for interface %s", iface)

	err = bpfCounters.FlushEgress()
	if err != nil {
		return fmt.Errorf("Failed to flush egress bpf counters for interface %s. err=%v", iface, err)
	}
	log.Infof("Successfully flushed egress counters map for interface %s", iface)
	return nil
}
