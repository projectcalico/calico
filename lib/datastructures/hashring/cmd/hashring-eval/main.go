// Copyright (c) 2026 Tigera, Inc. All rights reserved.

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

// hashring-eval reports load distribution and lookup cost for the
// hashring package across a sweep of (members, replicas, probes)
// configurations. Run with `go run ./lib/datastructures/hashring/cmd/hashring-eval`.
package main

import (
	"flag"
	"fmt"
	"math"
	"os"
	"sort"
	"time"

	"github.com/projectcalico/calico/lib/datastructures/hashring"
)

type config struct {
	members  int
	replicas int
	probes   int
}

func main() {
	keys := flag.Int("keys", 100000, "number of lookup keys to test per config")
	customN := flag.Int("n", 0, "if > 0, only test this member count (default: sweep)")
	flag.Parse()

	if *keys < 1 {
		fmt.Fprintf(os.Stderr, "-keys must be >= 1\n")
		os.Exit(2)
	}
	if *customN < 0 {
		fmt.Fprintf(os.Stderr, "-n must be >= 0\n")
		os.Exit(2)
	}

	memberCounts := []int{100, 1000}
	if *customN > 0 {
		memberCounts = []int{*customN}
	}

	// Configs chosen to compare equal R*P budgets (load-balance
	// budget is roughly the product) at different R/P splits.
	rpPairs := [][2]int{
		{1, 1}, // bare CH baseline
		{10, 1}, {1, 10}, {3, 3},
		{100, 1}, {1, 100}, {10, 10},
		{1000, 1}, {1, 1000}, {32, 32},
	}

	for _, n := range memberCounts {
		fmt.Printf("\n=== members=%d  keys=%d ===\n", n, *keys)
		fmt.Printf("%-10s %-10s %-12s %-10s %-10s %-10s %-10s %-12s %-12s\n",
			"replicas", "probes", "ring_size", "min/mean", "max/mean", "stddev", "p99/mean", "insert_ns", "lookup_ns")
		for _, rp := range rpPairs {
			cfg := config{members: n, replicas: rp[0], probes: rp[1]}
			report(cfg, *keys)
		}
	}
}

func report(cfg config, numKeys int) {
	r := hashring.New[string](hashring.WithReplicas(cfg.replicas), hashring.WithProbes(cfg.probes))

	// Time the insert phase.
	insertStart := time.Now()
	for i := range cfg.members {
		k := fmt.Sprintf("member-%d", i)
		r.Insert(k, k)
	}
	insertElapsed := time.Since(insertStart)

	// Warm the lookup path (first Lookup pays the sort).
	_, _ = r.Lookup("warmup")

	// Time and count Lookup ownership.
	counts := make(map[string]int, cfg.members)
	lookupStart := time.Now()
	for i := range numKeys {
		v, _ := r.Lookup(fmt.Sprintf("k-%d", i))
		counts[v]++
	}
	lookupElapsed := time.Since(lookupStart)

	// Per-member ownership stats.
	ownership := make([]float64, 0, cfg.members)
	for i := range cfg.members {
		k := fmt.Sprintf("member-%d", i)
		ownership = append(ownership, float64(counts[k]))
	}
	sort.Float64s(ownership)

	mean := float64(numKeys) / float64(cfg.members)
	lo := ownership[0]
	hi := ownership[len(ownership)-1]
	p99 := ownership[int(float64(len(ownership))*0.99)]
	variance := 0.0
	for _, o := range ownership {
		d := o - mean
		variance += d * d
	}
	stddev := math.Sqrt(variance / float64(len(ownership)))

	insertPer := time.Duration(int64(insertElapsed) / int64(cfg.members))
	lookupPer := time.Duration(int64(lookupElapsed) / int64(numKeys))

	fmt.Printf("%-10d %-10d %-12d %-10.3f %-10.3f %-10.1f %-10.3f %-12s %-12s\n",
		cfg.replicas, cfg.probes, cfg.members*cfg.replicas,
		lo/mean, hi/mean, stddev, p99/mean,
		insertPer, lookupPer)
}
