// Copyright (c) 2026 Tigera, Inc. All rights reserved.
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

package nftables_test

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/prometheus/procfs"
	"github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/felix/environment"
	"github.com/projectcalico/calico/felix/generictables"
	"github.com/projectcalico/calico/felix/ipsets"
	"github.com/projectcalico/calico/felix/logutils"
	"github.com/projectcalico/calico/felix/nftables"
	"github.com/projectcalico/calico/felix/rules"
)

// These benchmarks isolate the nftables programming path - render plus the nft
// transaction to the kernel - so we can measure the cost of a change without
// standing up a cluster.  They program a real "calico" table in the host's
// network namespace, so they must run as root (CAP_NET_ADMIN), same as the
// routetable benchmarks.
//
// The scale knobs (IP sets, members per set, policy chains, rules per chain)
// map onto the dimensions the higher-level k8sfv scale runs drive from real
// policy, so a finding here is reproducible there.  Felix's IP sets come from
// policy selectors (label selectors over pods/namespaces, network sets, named
// ports), not from Kubernetes services - those are kube-proxy's job and live in
// its own table.  So the large specs below model policies that select across
// many endpoints, which is where Felix's IP set and rule load actually comes
// from.

type scaleSpec struct {
	name string

	numIPSets     int
	membersPerSet int
	numPolicies   int
	rulesPerChain int
}

// scaleSpecs is a deliberately modest first sweep.  The dimensions can be
// turned up towards the k8sfv headline scales (10k+ policies, 250k members)
// once we trust the numbers; start small so the suite stays runnable.
var scaleSpecs = []scaleSpec{
	{name: "100sets_100chains", numIPSets: 100, membersPerSet: 20, numPolicies: 100, rulesPerChain: 10},
	{name: "500sets_500chains", numIPSets: 500, membersPerSet: 50, numPolicies: 500, rulesPerChain: 10},
	{name: "2000sets_2000chains", numIPSets: 2000, membersPerSet: 100, numPolicies: 2000, rulesPerChain: 10},
}

// BenchmarkResync measures the cost of a full resync against an already-correct
// dataplane: read the current state back, diff it against the desired state,
// and reconcile.  This is the periodic-refresh cost and the analogue of
// BenchmarkResync in felix/routetable.
func BenchmarkResync(b *testing.B) {
	for _, s := range scaleSpecs {
		b.Run(s.name, func(b *testing.B) {
			table, ipv := newRealTable(b)
			buildState(table, ipv, s)
			table.ApplyUpdates(nil)
			table.Apply()

			b.ReportAllocs()
			rec := record(b, s, "resync")
			b.ResetTimer()

			for range b.N {
				table.InvalidateDataplaneCache("bench")
				table.QueueResync()
				table.ApplyUpdates(nil)
				table.Apply()
			}

			b.StopTimer()
			rec.finish()
		})
	}
}

// BenchmarkDeltaUpdate measures the incremental write cost: each iteration
// churns a single IP set's membership and reprograms.  This is the steady-state
// case - a pod coming or going - rather than a full resync.
func BenchmarkDeltaUpdate(b *testing.B) {
	for _, s := range scaleSpecs {
		b.Run(s.name, func(b *testing.B) {
			table, ipv := newRealTable(b)
			buildState(table, ipv, s)
			table.ApplyUpdates(nil)
			table.Apply()
			// The first Apply() programs the whole table, which invalidates the
			// dataplane cache. Apply once more so the cache is settled before we
			// start timing - we want the steady-state delta cost, not the one-off
			// reload that follows the initial program.
			table.Apply()

			b.ReportAllocs()
			rec := record(b, s, "delta")
			b.ResetTimer()

			// Toggle one member of set 0 in and out so each iteration is a real
			// add or remove rather than a no-op.
			churn := intToIP(172<<24 | 16<<16)
			for i := range b.N {
				if i%2 == 0 {
					table.AddMembers("s000000", []string{churn})
				} else {
					table.RemoveMembers("s000000", []string{churn})
				}
				table.ApplyUpdates(nil)
				table.Apply()
			}

			b.StopTimer()
			rec.finish()
		})
	}
}

// BenchmarkChainUpdate measures the incremental cost of changing a single policy
// chain's rules and reprogramming, in steady state (no forced resync).
func BenchmarkChainUpdate(b *testing.B) {
	for _, s := range scaleSpecs {
		b.Run(s.name, func(b *testing.B) {
			table, ipv := newRealTable(b)
			buildState(table, ipv, s)
			table.ApplyUpdates(nil)
			table.Apply()
			// Settle the cache before timing (see BenchmarkDeltaUpdate).
			table.Apply()

			b.ReportAllocs()
			rec := record(b, s, "chain_update")
			b.ResetTimer()

			// Toggle one rule's destination port on a single chain so each
			// iteration is a real change to that chain and nothing else.
			chainName := "cali-pi-000000"
			setName := ipv.NameForMainIPSet("s000000")
			for i := range b.N {
				port := uint16(2000 + i%2)
				table.UpdateChain(&generictables.Chain{
					Name: chainName,
					Rules: []generictables.Rule{
						{
							Match:  nftables.Match().Protocol("tcp").SourceIPSet(setName).DestPorts(port),
							Action: nftables.ReturnAction{},
						},
					},
				})
				table.Apply()
			}

			b.StopTimer()
			rec.finish()
		})
	}
}

// benchTableName is a dedicated, benchmark-only table. We deliberately avoid
// "calico" so a run can never touch a real Calico dataplane on this host.
const benchTableName = "calico-bench"

// newRealTable builds an NftablesTable wired to the real kernel via knftables.
// It skips (rather than fails) when its prerequisites aren't met (not root, or
// no nft binary) so a plain "go test" on a dev box doesn't error - the benchmark
// is only meaningful with kernel access.
func newRealTable(b *testing.B) (*nftables.NftablesTable, *ipsets.IPVersionConfig) {
	if os.Getuid() != 0 {
		b.Skip("Must run as root: programs the real nftables dataplane.")
	}
	if _, err := exec.LookPath("nft"); err != nil {
		b.Skip("nft binary not found; skipping nftables dataplane benchmark.")
	}
	logutils.ConfigureEarlyLogging()
	logrus.SetLevel(logrus.WarnLevel)

	// Start clean and tidy up after ourselves - we program a real table in the
	// host's network namespace.
	deleteBenchTable()
	b.Cleanup(deleteBenchTable)

	// required=false so we return nil (and skip) rather than panic if the
	// knftables client can't be created, e.g. the kernel lacks nftables support.
	table := nftables.NewTable(
		benchTableName,
		4,
		rules.RuleHashPrefix,
		environment.NewFeatureDetector(nil),
		nftables.TableOptions{
			OpRecorder: logutils.NewSummarizer("bench"),
		},
		false,
	)
	if table == nil {
		b.Skip("nftables not available on this host; skipping benchmark.")
	}
	ipv := ipsets.NewIPVersionConfig(ipsets.IPFamilyV4, ipsets.IPSetNamePrefix, nil, nil)
	return table, ipv
}

func deleteBenchTable() {
	// May not exist yet on the first call; ignore the error.
	_ = exec.Command("nft", "delete", "table", "ip", benchTableName).Run()
}

// buildState queues the desired state onto the table: numIPSets hash:ip sets,
// and numPolicies chains each holding rulesPerChain rules that match on a source
// IP set and TCP destination port.  Each chain is jumped to from filter-FORWARD
// so it is referenced and therefore programmed.
func buildState(table *nftables.NftablesTable, ipv *ipsets.IPVersionConfig, s scaleSpec) {
	ipCounter := uint32(10 << 24)
	setNames := make([]string, s.numIPSets)
	for i := range s.numIPSets {
		setID := fmt.Sprintf("s%06d", i)
		setNames[i] = ipv.NameForMainIPSet(setID)
		members := make([]string, s.membersPerSet)
		for j := range s.membersPerSet {
			members[j] = intToIP(ipCounter)
			ipCounter++
		}
		table.AddOrReplaceIPSet(
			ipsets.IPSetMetadata{
				SetID:   setID,
				Type:    ipsets.IPSetTypeHashIP,
				MaxSize: 1 << 20,
			},
			members,
		)
	}

	jumps := make([]generictables.Rule, s.numPolicies)
	for p := range s.numPolicies {
		chainName := fmt.Sprintf("cali-pi-%06d", p)
		policyRules := make([]generictables.Rule, s.rulesPerChain)
		for r := range s.rulesPerChain {
			setName := setNames[(p*s.rulesPerChain+r)%s.numIPSets]
			policyRules[r] = generictables.Rule{
				Match: nftables.Match().
					Protocol("tcp").
					SourceIPSet(setName).
					DestPorts(uint16(1000 + r)),
				Action: nftables.ReturnAction{},
			}
		}
		table.UpdateChain(&generictables.Chain{Name: chainName, Rules: policyRules})
		jumps[p] = generictables.Rule{
			Match:  nftables.Match(),
			Action: nftables.JumpAction{Target: chainName},
		}
	}
	table.InsertOrAppendRules("filter-FORWARD", jumps)
}

func intToIP(v uint32) string {
	return fmt.Sprintf("%d.%d.%d.%d", byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
}

// perfArtifactsEnvVar names a directory to write per-measurement results into,
// as hack/perf JSON docs (see hack/perf/README.md). It is unset for ordinary
// `go test` runs - we only emit when a CI job asks for it, which keeps dev runs
// out of the long-term trend store. The CI job then runs send-perf-results
// against the directory to push the docs to Lens.
const (
	perfArtifactsEnvVar = "NFT_BENCH_PERF_ARTIFACTS_DIR"
	perfFamily          = "benchmark_data_nft_dataplane"
)

// recorder measures a benchmark loop and, on finish, reports per-op metrics to
// testing.B and (if enabled) writes a hack/perf doc for it. Start it immediately
// before b.ResetTimer() and finish it immediately after b.StopTimer().
type recorder struct {
	b     *testing.B
	spec  scaleSpec
	phase string

	proc      procfs.Proc
	startCPU  float64
	startWall time.Time
	startMem  runtime.MemStats
}

func record(b *testing.B, s scaleSpec, phase string) *recorder {
	proc, _ := procfs.NewProc(os.Getpid())
	stat, _ := proc.Stat()
	r := &recorder{
		b:         b,
		spec:      s,
		phase:     phase,
		proc:      proc,
		startCPU:  stat.CPUTime(),
		startWall: time.Now(),
	}
	runtime.ReadMemStats(&r.startMem)
	return r
}

func (r *recorder) finish() {
	wallNsPerOp := float64(time.Since(r.startWall).Nanoseconds()) / float64(r.b.N)

	var endMem runtime.MemStats
	runtime.ReadMemStats(&endMem)
	bytesPerOp := float64(endMem.TotalAlloc-r.startMem.TotalAlloc) / float64(r.b.N)
	allocsPerOp := float64(endMem.Mallocs-r.startMem.Mallocs) / float64(r.b.N)

	// CPU time diverges from wall-clock once the nft path blocks on the kernel,
	// so report both.
	runtime.GC()
	stat, _ := r.proc.Stat()
	cpuNsPerOp := (stat.CPUTime() - r.startCPU) / float64(r.b.N) * 1e9

	r.b.ReportMetric(float64(r.spec.numIPSets), "ipsets")
	r.b.ReportMetric(float64(r.spec.numIPSets*r.spec.membersPerSet), "members")
	r.b.ReportMetric(float64(r.spec.numPolicies), "chains")
	r.b.ReportMetric(float64(r.spec.numPolicies*r.spec.rulesPerChain), "rules")
	r.b.ReportMetric(cpuNsPerOp, "ncpu/op")

	r.writePerfDoc(wallNsPerOp, cpuNsPerOp, bytesPerOp, allocsPerOp)
}

func (r *recorder) writePerfDoc(wallNsPerOp, cpuNsPerOp, bytesPerOp, allocsPerOp float64) {
	dir := os.Getenv(perfArtifactsEnvVar)
	if dir == "" {
		return
	}
	doc := map[string]any{
		"test_name":         "nft_dataplane",
		"dataplane":         "nftables",
		"phase":             r.phase,
		"scale_ipsets":      r.spec.numIPSets,
		"scale_set_members": r.spec.numIPSets * r.spec.membersPerSet,
		"scale_chains":      r.spec.numPolicies,
		"scale_rules":       r.spec.numPolicies * r.spec.rulesPerChain,
		"wall_ns_per_op":    wallNsPerOp,
		"cpu_ns_per_op":     cpuNsPerOp,
		"bytes_per_op":      bytesPerOp,
		"allocs_per_op":     allocsPerOp,
		"ok":                true,
	}
	familyDir := filepath.Join(dir, perfFamily)
	if err := os.MkdirAll(familyDir, 0o755); err != nil {
		r.b.Logf("perf: failed to create %s: %v", familyDir, err)
		return
	}
	data, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		r.b.Logf("perf: failed to marshal doc: %v", err)
		return
	}
	path := filepath.Join(familyDir, fmt.Sprintf("%s_%s.json", r.phase, r.spec.name))
	if err := os.WriteFile(path, data, 0o644); err != nil {
		r.b.Logf("perf: failed to write %s: %v", path, err)
	}
}
