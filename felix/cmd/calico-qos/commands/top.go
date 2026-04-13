// Copyright (c) 2025 Tigera, Inc. All rights reserved.
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
	"os"
	"sort"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"
	"github.com/vishvananda/netlink"
)

var (
	topInterval time.Duration
	topNIC      string
)

var topCmd = &cobra.Command{
	Use:   "top",
	Short: "Live view of QoS bandwidth usage per workload interface",
	RunE:  runTop,
}

func init() {
	topCmd.Flags().DurationVarP(&topInterval, "interval", "i", 1*time.Second, "Refresh interval")
	topCmd.Flags().StringVar(&topNIC, "nic", "", "Host NIC to monitor (e.g. eth0). Auto-detected if not set.")
	rootCmd.AddCommand(topCmd)
}

type ifaceSnapshot struct {
	Name         string
	IngressBytes uint64
	EgressBytes  uint64
	IngressRate  uint64 // configured cap in bits/sec
	EgressRate   uint64
}

func takeSnapshot() map[string]*ifaceSnapshot {
	ifaces, err := listCalicoInterfaces()
	if err != nil {
		return nil
	}

	snapshots := make(map[string]*ifaceSnapshot, len(ifaces))
	for _, name := range ifaces {
		ingress, egress, err := ReadPodStats(name)
		if err != nil {
			continue
		}
		snap := &ifaceSnapshot{Name: name}
		if ingress != nil {
			snap.IngressBytes = ingress.Bytes
			snap.IngressRate = ingress.Rate
		}
		if egress != nil {
			snap.EgressBytes = egress.Bytes
			snap.EgressRate = egress.Rate
		}
		// Only include interfaces that have at least one TBF qdisc.
		if ingress != nil || egress != nil {
			snapshots[name] = snap
		}
	}
	return snapshots
}

type ifaceRate struct {
	Name        string
	IngressBps  uint64 // current throughput in bits/sec
	EgressBps   uint64
	IngressCap  uint64 // configured cap in bits/sec
	EgressCap   uint64
	TotalBps    uint64
}

func runTop(cmd *cobra.Command, args []string) error {
	// Detect host NIC if not specified.
	if topNIC == "" {
		topNIC = detectDefaultNIC()
	}
	nicSpeed := readNICSpeed(topNIC)

	prev := takeSnapshot()
	var prevNICRx, prevNICTx uint64
	if topNIC != "" {
		prevNICRx, prevNICTx, _ = readNICStats(topNIC)
	}

	time.Sleep(topInterval)

	for {
		curr := takeSnapshot()
		var currNICRx, currNICTx uint64
		if topNIC != "" {
			currNICRx, currNICTx, _ = readNICStats(topNIC)
		}

		dt := topInterval.Seconds()

		// Compute NIC throughput.
		var nicRxBps, nicTxBps uint64
		if topNIC != "" && prevNICRx > 0 {
			nicRxBps = uint64(float64(currNICRx-prevNICRx) * 8 / dt)
			nicTxBps = uint64(float64(currNICTx-prevNICTx) * 8 / dt)
		}

		// Compute per-interface rates.
		var rates []ifaceRate
		for name, c := range curr {
			p, ok := prev[name]
			if !ok {
				continue
			}
			var inBps, egBps uint64
			if c.IngressBytes > p.IngressBytes {
				inBps = uint64(float64(c.IngressBytes-p.IngressBytes) * 8 / dt)
			}
			if c.EgressBytes > p.EgressBytes {
				egBps = uint64(float64(c.EgressBytes-p.EgressBytes) * 8 / dt)
			}
			rates = append(rates, ifaceRate{
				Name:       name,
				IngressBps: inBps,
				EgressBps:  egBps,
				IngressCap: c.IngressRate,
				EgressCap:  c.EgressRate,
				TotalBps:   inBps + egBps,
			})
		}

		sort.Slice(rates, func(i, j int) bool {
			return rates[i].TotalBps > rates[j].TotalBps
		})

		// Clear screen and print.
		fmt.Print("\033[H\033[2J")

		if topNIC != "" {
			nicTotal := nicRxBps + nicTxBps
			if nicSpeed > 0 {
				pct := float64(nicTotal) / float64(nicSpeed) * 100
				fmt.Printf("HOST NIC: %s  %s/%s (%.0f%%)\n\n",
					topNIC,
					FormatBits(nicTotal),
					FormatBits(nicSpeed),
					pct,
				)
			} else {
				fmt.Printf("HOST NIC: %s  RX: %s  TX: %s\n\n",
					topNIC,
					FormatBits(nicRxBps),
					FormatBits(nicTxBps),
				)
			}
		}

		w := tabwriter.NewWriter(os.Stdout, 0, 4, 3, ' ', 0)
		fmt.Fprintln(w, "INTERFACE\tINGRESS\tEGRESS\tTOTAL\tINGRESS CAP\tEGRESS CAP")

		var totalIn, totalEg uint64
		for _, r := range rates {
			inCap := "-"
			if r.IngressCap > 0 {
				inCap = FormatBits(r.IngressCap)
			}
			egCap := "-"
			if r.EgressCap > 0 {
				egCap = FormatBits(r.EgressCap)
			}
			fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\n",
				r.Name,
				FormatBits(r.IngressBps),
				FormatBits(r.EgressBps),
				FormatBits(r.TotalBps),
				inCap,
				egCap,
			)
			totalIn += r.IngressBps
			totalEg += r.EgressBps
		}

		fmt.Fprintf(w, "\nTOTAL\t%s\t%s\t%s\t\t\n",
			FormatBits(totalIn),
			FormatBits(totalEg),
			FormatBits(totalIn+totalEg),
		)
		w.Flush()

		prev = curr
		prevNICRx = currNICRx
		prevNICTx = currNICTx

		time.Sleep(topInterval)
	}
}

// detectDefaultNIC returns the interface used for the default route.
func detectDefaultNIC() string {
	routes, err := netlink.RouteList(nil, netlink.FAMILY_V4)
	if err != nil {
		return ""
	}
	for _, r := range routes {
		if r.Dst == nil {
			// Default route.
			link, err := netlink.LinkByIndex(r.LinkIndex)
			if err != nil {
				continue
			}
			return link.Attrs().Name
		}
	}
	return ""
}
