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
// configurations. lib/datastructures is its own module, so run from
// inside it:
//
//	cd lib/datastructures && go run ./hashring/cmd/hashring-eval
package main

import (
	"flag"
	"fmt"
	"math"
	"os"
	"sort"
	"time"

	"github.com/zeebo/xxh3"

	"github.com/projectcalico/calico/lib/datastructures/hashring"
)

// rendezvousRing is a throwaway HRW (Highest Random Weight)
// implementation for side-by-side comparison with the ring. For
// each Lookup it hashes (key, member) for every member and returns
// the member with the highest hash. No data structure beyond the
// member list, O(N) per Lookup, perfect distribution (no virtual-
// node clustering possible).
type rendezvousRing struct {
	members []string
	scratch []byte
}

func (r *rendezvousRing) Insert(m string) {
	r.members = append(r.members, m)
}

func (r *rendezvousRing) Lookup(key string) string {
	var bestMember string
	var bestHash uint64
	for i, m := range r.members {
		r.scratch = append(r.scratch[:0], key...)
		r.scratch = append(r.scratch, 0)
		r.scratch = append(r.scratch, m...)
		h := xxh3.Hash(r.scratch)
		if i == 0 || h > bestHash {
			bestHash = h
			bestMember = m
		}
	}
	return bestMember
}

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

	memberCounts := []int{50, 500, 5000, 50000}
	if *customN > 0 {
		memberCounts = []int{*customN}
	}

	// 3x3 sweep over (replicas, probes). R controls per-member
	// ring memory; P controls per-Lookup CPU. Both contribute to
	// the imbalance budget roughly as R*P.
	rpPairs := [][2]int{
		{1, 1}, {1, 10}, {1, 20},
		{10, 1}, {10, 10}, {10, 20},
		{100, 1}, {100, 10}, {100, 20},
	}

	for _, n := range memberCounts {
		mean := float64(*keys) / float64(n)
		fmt.Printf("\n=== members=%d  keys=%d  (mean=%.2f per member) ===\n", n, *keys, mean)
		fmt.Printf("%-10s %-10s %-12s %-10s %-10s %-10s %-10s %-12s %-12s\n",
			"replicas", "probes", "ring_size", "min/mean", "max/mean", "stddev", "p99/mean", "insert_ns", "lookup_ns")
		fMin, fMax, fSD, fP99 := poissonFloor(n, *keys)
		fmt.Printf("%-10s %-10s %-12s %-10.3f %-10.3f %-10.1f %-10.3f %-12s %-12s\n",
			"-", "-", "-", fMin, fMax, fSD, fP99, "-", "-")
		for _, rp := range rpPairs {
			cfg := config{members: n, replicas: rp[0], probes: rp[1]}
			report(cfg, *keys)
		}
		reportRendezvous(n, *keys)
	}
}

func reportRendezvous(members, numKeys int) {
	r := &rendezvousRing{}

	insertStart := time.Now()
	for i := range members {
		r.Insert(fmt.Sprintf("member-%d", i))
	}
	insertElapsed := time.Since(insertStart)

	counts := make(map[string]int, members)
	lookupStart := time.Now()
	for i := range numKeys {
		v := r.Lookup(fmt.Sprintf("k-%d", i))
		counts[v]++
	}
	lookupElapsed := time.Since(lookupStart)

	ownership := make([]float64, 0, members)
	for i := range members {
		k := fmt.Sprintf("member-%d", i)
		ownership = append(ownership, float64(counts[k]))
	}
	sort.Float64s(ownership)

	mean := float64(numKeys) / float64(members)
	lo := ownership[0]
	hi := ownership[len(ownership)-1]
	p99 := ownership[int(float64(len(ownership))*0.99)]
	variance := 0.0
	for _, o := range ownership {
		d := o - mean
		variance += d * d
	}
	stddev := math.Sqrt(variance / float64(len(ownership)))

	insertPer := time.Duration(int64(insertElapsed) / int64(members))
	lookupPer := time.Duration(int64(lookupElapsed) / int64(numKeys))

	fmt.Printf("%-10s %-10s %-12d %-10.3f %-10.3f %-10.1f %-10.3f %-12s %-12s\n",
		"rendezv", "-", members,
		lo/mean, hi/mean, stddev, p99/mean,
		insertPer, lookupPer)
}

// poissonFloor returns the theoretical metrics that an *ideal* (uniform
// random) assignment of `keys` items to `members` bins would yield. It's
// the lower bound on imbalance any consistent-hashing algorithm can hit
// — anything an actual algorithm reports below the floor is sampling
// luck; anything above the floor is ring-quality cost.
//
// Approximations used:
//   - Each bin is Poisson(lambda=keys/members).
//   - Max via Gumbel: E[max] ~ lambda + sqrt(2*lambda*ln(members)).
//   - Min symmetric, floored at zero when E[empty bins] >= 0.5.
//   - p99 from the Poisson 99% quantile ~ lambda + 2.326*sqrt(lambda).
//   - stddev = sqrt(lambda).
func poissonFloor(members, numKeys int) (minMean, maxMean, stddev, p99Mean float64) {
	lambda := float64(numKeys) / float64(members)
	if lambda <= 0 {
		return
	}
	stddev = math.Sqrt(lambda)
	spread := math.Sqrt(2 * lambda * math.Log(float64(members)))
	maxMean = (lambda + spread) / lambda
	if float64(members)*math.Exp(-lambda) >= 0.5 {
		minMean = 0
	} else {
		minMean = math.Max(0, (lambda-spread)/lambda)
	}
	p99Mean = (lambda + 2.326*math.Sqrt(lambda)) / lambda
	return
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
