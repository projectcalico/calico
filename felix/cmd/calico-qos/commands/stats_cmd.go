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
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"
)

var showAll bool

var statsCmd = &cobra.Command{
	Use:   "stats [interface-name]",
	Short: "Show QoS qdisc stats for an interface, or --all for every shaped interface",
	Args:  cobra.MaximumNArgs(1),
	RunE:  runStats,
}

func init() {
	statsCmd.Flags().BoolVar(&showAll, "all", false, "Show stats for all interfaces that have TBF qdiscs")
	rootCmd.AddCommand(statsCmd)
}

func runStats(cmd *cobra.Command, args []string) error {
	if showAll {
		return runStatsAll()
	}
	if len(args) == 0 {
		return fmt.Errorf("interface name required (or use --all)")
	}
	return runStatsSingle(args[0])
}

func runStatsSingle(ifaceName string) error {
	ingress, egress, err := ReadPodStats(ifaceName)
	if err != nil {
		return fmt.Errorf("failed to read qdisc stats: %w", err)
	}

	fmt.Printf("INTERFACE: %s\n\n", ifaceName)

	w := tabwriter.NewWriter(os.Stdout, 0, 4, 3, ' ', 0)
	fmt.Fprintln(w, "DIRECTION\tBYTES\tPACKETS\tDROPS\tOVERLIMITS\tBACKLOG\tCAP")

	if ingress != nil {
		fmt.Fprintf(w, "Ingress\t%s\t%d\t%d\t%d\t%d\t%s\n",
			FormatBytes(ingress.Bytes),
			ingress.Packets,
			ingress.Drops,
			ingress.Overlimits,
			ingress.Backlog,
			FormatBits(ingress.Rate),
		)
	} else {
		fmt.Fprintf(w, "Ingress\t-\t-\t-\t-\t-\t-\n")
	}

	if egress != nil {
		fmt.Fprintf(w, "Egress\t%s\t%d\t%d\t%d\t%d\t%s\n",
			FormatBytes(egress.Bytes),
			egress.Packets,
			egress.Drops,
			egress.Overlimits,
			egress.Backlog,
			FormatBits(egress.Rate),
		)
	} else {
		fmt.Fprintf(w, "Egress\t-\t-\t-\t-\t-\t-\n")
	}

	return w.Flush()
}

func runStatsAll() error {
	ifaces, err := listAllInterfaces()
	if err != nil {
		return fmt.Errorf("failed to list interfaces: %w", err)
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 4, 3, ' ', 0)
	fmt.Fprintln(w, "INTERFACE\tDIRECTION\tBYTES\tPACKETS\tDROPS\tOVERLIMITS\tBACKLOG\tCAP")

	found := false
	for _, name := range ifaces {
		// Skip IFB devices — their stats are already reported as the
		// egress row of the corresponding cali*/tap* interface.
		if strings.HasPrefix(name, "bwcali") {
			continue
		}
		ingress, egress, _ := ReadPodStats(name)
		if ingress == nil && egress == nil {
			continue
		}
		found = true
		ifLabel := name
		if ingress != nil {
			fmt.Fprintf(w, "%s\tIngress\t%s\t%d\t%d\t%d\t%d\t%s\n",
				ifLabel,
				FormatBytes(ingress.Bytes),
				ingress.Packets,
				ingress.Drops,
				ingress.Overlimits,
				ingress.Backlog,
				FormatBits(ingress.Rate),
			)
			ifLabel = ""
		}
		if egress != nil {
			fmt.Fprintf(w, "%s\tEgress\t%s\t%d\t%d\t%d\t%d\t%s\n",
				ifLabel,
				FormatBytes(egress.Bytes),
				egress.Packets,
				egress.Drops,
				egress.Overlimits,
				egress.Backlog,
				FormatBits(egress.Rate),
			)
		}
	}

	if !found {
		fmt.Println("No interfaces with TBF qdiscs found.")
		return nil
	}

	return w.Flush()
}
