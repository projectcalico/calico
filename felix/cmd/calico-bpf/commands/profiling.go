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
	"fmt"
	"net"

	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/jedib0t/go-pretty/v6/text"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/projectcalico/calico/felix/bpf/maps"
	"github.com/projectcalico/calico/felix/bpf/profiling"
)

// profilingCmd represents the profiling command
var profilingCmd = &cobra.Command{
	Use:   "profiling",
	Short: "Show and reset profiling data",
}

func init() {
	profilingCmd.AddCommand(profilingE2ECmd)
	rootCmd.AddCommand(profilingCmd)
}

var profilingE2ECmd = &cobra.Command{
	Use:   "e2e",
	Short: "Shows average e2e latency for every interface since last query",
	Run:   e2eLatency,
}

func e2eLatency(cmd *cobra.Command, args []string) {
	m := profiling.Map()
	if err := m.Open(); err != nil {
		log.WithError(err).Error("Failed to open profiling map.")
		return
	}
	defer m.Close()

	data := make(map[profiling.Key]profiling.Value)

	err := m.Iter(func(k, v []byte) maps.IteratorAction {
		key := profiling.KeyFromBytes(k)

		switch key.Kind {
		case 0, 1, 2, 3:
			// nothing
		default:
			return maps.IterNone
		}

		var val profiling.Value

		for i := 0; i < maps.NumPossibleCPUs(); i++ {
			x := profiling.ValueFromBytes(v[i*profiling.ValueSize:])
			val.Time += x.Time
			val.Samples += x.Samples
		}

		data[key] = val

		return maps.IterDelete
	})

	if err != nil {
		log.WithError(err).Error("Failed to read profiling map")
	}

	ifaces, err := net.Interfaces()
	if err != nil {
		log.WithError(err).Error("Failed to list network interfaces")
	}

	t := table.NewWriter()
	t.SetOutputMirror(cmd.OutOrStdout())
	t.AppendHeader(table.Row{"IFACE", "INGRESS new", "#", "INGRESS est", "#", "EGRESS new", "#", "EGRESS est", "#"})
	t.SetColumnConfigs([]table.ColumnConfig{
		{Number: 1, AutoMerge: true},
		{Number: 2, Align: text.AlignRight},
		{Number: 3, Align: text.AlignRight},
		{Number: 4, Align: text.AlignRight},
		{Number: 5, Align: text.AlignRight},
		{Number: 6, Align: text.AlignRight},
		{Number: 7, Align: text.AlignRight},
		{Number: 8, Align: text.AlignRight},
		{Number: 9, Align: text.AlignRight},
	})

	for _, i := range ifaces {
		k := profiling.Key{
			Ifindex: i.Index,
		}

		r := table.Row{i.Name}
		hit := false

		for kind := range 4 {
			k.Kind = kind
			v, ok := data[k]
			if !ok {
				r = append(r, "---", "---")
				continue
			}

			hit = true

			if v.Samples != 0 {
				r = append(r, fmt.Sprintf("%.3f ns", float64(v.Time)/float64(v.Samples)), v.Samples)
			} else {
				r = append(r, "---", "0")
			}
		}

		if hit {
			t.AppendRow(r)
		}
	}

	t.Render()
}
