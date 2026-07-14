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

package ut_test

import (
	"encoding/json"
	"fmt"
	"os"
	"path"
	"sort"
	"strings"
	"testing"

	. "github.com/onsi/gomega"
	"golang.org/x/sys/unix"

	"github.com/projectcalico/calico/felix/bpf/bpfdefs"
	"github.com/projectcalico/calico/felix/bpf/libbpf"
	"github.com/projectcalico/calico/felix/bpf/utils"
)

// verifierStatsReportPath is relative to the test's working directory
// (felix/bpf/ut inside the UT container), resolving to felix/report/ which the
// ut-bpf make target creates and which persists via the repo mount.
const verifierStatsReportPath = "../../report/bpf-verifier-stats.json"

// TestVerifierStats loads every production BPF object and records per-program
// verifier cost (verified_insns), post-verifier image size (xlated) and JITed
// image size. It is informational: there is no committed baseline and no
// threshold. verified_insns needs kernel >=5.16 and reads 0 on older kernels
// (see felix/design/bpf-tests.md); the test tolerates zeros and never asserts
// on counts, only on load success.
func TestVerifierStats(t *testing.T) {
	RegisterTestingT(t)

	bpffs, err := utils.MaybeMountBPFfs()
	Expect(err).NotTo(HaveOccurred())
	Expect(bpffs).To(Equal("/sys/fs/bpf"))

	report := verifierStatsReport{Kernel: kernelRelease()}

	// allProductionObjectFiles is sorted, so objects land in the report in
	// name order, giving stable JSON diffs across runs.
	for _, objFile := range allProductionObjectFiles() {
		t.Run(objFile, func(t *testing.T) {
			RegisterTestingT(t)
			stat := collectObjectStats(t, path.Join(bpfdefs.ObjectDir, objFile), objFile)
			report.Objects = append(report.Objects, stat)
			report.TotalVerifiedInsns += stat.TotalVerifiedInsns
		})
	}

	writeVerifierStatsReport(t, report)
	logVerifierStatsTable(t, report)
}

// collectObjectStats opens and loads a single object then records stats for
// each of its programs. A load failure fails the subtest, matching
// TestPrecompiledBinariesAreLoadable.
func collectObjectStats(t *testing.T, file, objName string) objectStat {
	obj, err := libbpf.OpenObject(file)
	Expect(err).NotTo(HaveOccurred(), fmt.Sprintf("failed to open object %s", file))
	defer func() { _ = obj.Close() }()

	err = obj.Load()
	Expect(err).NotTo(HaveOccurred(), fmt.Sprintf("failed to load object %s", file))

	stat := objectStat{Object: objName}
	prog, err := obj.FirstProgram()
	Expect(err).NotTo(HaveOccurred(), fmt.Sprintf("failed to get first program of %s", file))
	for prog != nil {
		if fd := prog.FD(); fd < 0 {
			// Program present in the ELF but not loaded (e.g. autoload
			// disabled): no verifier stats to record. Loadability is the
			// concern of TestPrecompiledBinariesAreLoadable, not this test.
			t.Logf("skipping program %q in %s: not loaded", prog.Name(), objName)
		} else {
			info, err := libbpf.GetProgInfo(fd)
			Expect(err).NotTo(HaveOccurred(), fmt.Sprintf("failed to get info for program %q in %s", prog.Name(), file))
			stat.Programs = append(stat.Programs, progStat{
				Name:          prog.Name(),
				VerifiedInsns: info.VerifiedInsns,
				XlatedInsns:   info.XlatedProgLen / 8,
				JitedBytes:    info.JitedProgLen,
			})
			stat.TotalVerifiedInsns += uint64(info.VerifiedInsns)
		}

		prog, err = prog.NextProgram()
		Expect(err).NotTo(HaveOccurred(), fmt.Sprintf("failed to iterate programs of %s", file))
	}

	sort.Slice(stat.Programs, func(i, j int) bool {
		return stat.Programs[i].Name < stat.Programs[j].Name
	})
	return stat
}

func writeVerifierStatsReport(t *testing.T, report verifierStatsReport) {
	data, err := json.MarshalIndent(report, "", "  ")
	Expect(err).NotTo(HaveOccurred())
	err = os.WriteFile(verifierStatsReportPath, data, 0o644)
	Expect(err).NotTo(HaveOccurred(), fmt.Sprintf("failed to write %s", verifierStatsReportPath))
	t.Logf("Wrote verifier stats to %s", verifierStatsReportPath)
}

// logVerifierStatsTable prints a human-readable summary: top programs by
// verified_insns, per-object totals, and the grand total.
func logVerifierStatsTable(t *testing.T, report verifierStatsReport) {
	type row struct {
		object string
		prog   progStat
	}
	var rows []row
	for _, o := range report.Objects {
		for _, p := range o.Programs {
			rows = append(rows, row{object: o.Object, prog: p})
		}
	}
	sort.Slice(rows, func(i, j int) bool {
		return rows[i].prog.VerifiedInsns > rows[j].prog.VerifiedInsns
	})

	const topN = 40
	var b strings.Builder
	fmt.Fprintf(&b, "\nBPF verifier stats (kernel %s)\n", report.Kernel)
	fmt.Fprintf(&b, "Top %d programs by verified_insns:\n", topN)
	fmt.Fprintf(&b, "%12s %12s %12s  %s\n", "VERIFIED", "XLATED", "JITED_B", "PROGRAM (OBJECT)")
	for i, r := range rows {
		if i >= topN {
			break
		}
		fmt.Fprintf(&b, "%12d %12d %12d  %s (%s)\n",
			r.prog.VerifiedInsns, r.prog.XlatedInsns, r.prog.JitedBytes, r.prog.Name, r.object)
	}

	objByTotal := make([]objectStat, len(report.Objects))
	copy(objByTotal, report.Objects)
	sort.Slice(objByTotal, func(i, j int) bool {
		return objByTotal[i].TotalVerifiedInsns > objByTotal[j].TotalVerifiedInsns
	})
	fmt.Fprintf(&b, "\nPer-object totals (verified_insns):\n")
	for _, o := range objByTotal {
		fmt.Fprintf(&b, "%12d  %s\n", o.TotalVerifiedInsns, o.Object)
	}

	fmt.Fprintf(&b, "\nGrand total verified_insns: %d across %d objects\n",
		report.TotalVerifiedInsns, len(report.Objects))
	t.Log(b.String())
}

func kernelRelease() string {
	var uts unix.Utsname
	if err := unix.Uname(&uts); err != nil {
		return "unknown"
	}
	return unix.ByteSliceToString(uts.Release[:])
}

// verifierStatsReport is the on-disk schema. Slices (not maps) with sorted
// contents keep JSON output deterministic for diffing between experiments.
type verifierStatsReport struct {
	Kernel             string       `json:"kernel"`
	TotalVerifiedInsns uint64       `json:"totalVerifiedInsns"`
	Objects            []objectStat `json:"objects"`
}

type objectStat struct {
	Object             string     `json:"object"`
	TotalVerifiedInsns uint64     `json:"totalVerifiedInsns"`
	Programs           []progStat `json:"programs"`
}

type progStat struct {
	Name          string `json:"name"`
	VerifiedInsns uint32 `json:"verifiedInsns"`
	XlatedInsns   uint32 `json:"xlatedInsns"`
	JitedBytes    uint32 `json:"jitedBytes"`
}
