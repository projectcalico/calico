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
	"text/tabwriter"

	"github.com/spf13/cobra"
)

var statsCmd = &cobra.Command{
	Use:   "stats <interface-name>",
	Short: "Show QoS qdisc stats for a workload interface (e.g. cali12345678)",
	Args:  cobra.ExactArgs(1),
	RunE:  runStats,
}

func init() {
	rootCmd.AddCommand(statsCmd)
}

func runStats(cmd *cobra.Command, args []string) error {
	ifaceName := args[0]

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
