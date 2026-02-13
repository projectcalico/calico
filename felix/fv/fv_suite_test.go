// Copyright (c) 2020 Tigera, Inc. All rights reserved.
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

package fv_test

import (
	"bytes"
	"errors"
	"fmt"
	"hash/fnv"
	"os"
	"runtime/metrics"
	"strconv"
	"testing"
	"time"

	. "github.com/onsi/ginkgo/v2"
	"github.com/onsi/ginkgo/v2/reporters"
	"github.com/onsi/ginkgo/v2/types"
	"github.com/onsi/gomega"
	"github.com/onsi/gomega/format"
	"github.com/prometheus/procfs"
	"golang.org/x/sys/unix"
	"golang.org/x/text/language"
	"golang.org/x/text/message"

	"github.com/projectcalico/calico/felix/fv/connectivity"
	"github.com/projectcalico/calico/felix/fv/infrastructure"
	"github.com/projectcalico/calico/libcalico-go/lib/testutils"
)

var (
	reportPath string
	realStdout = os.Stdout
)

func init() {
	testutils.HookLogrusForGinkgo()

	// Avoid truncating diffs when Equals assertions fail.
	format.TruncatedDiff = false
}

func TestFv(t *testing.T) {
	gomega.RegisterFailHandler(Fail)
	err := configureManualSharding()
	if err != nil {
		t.Fatalf("Failed to configure manual sharding: %v", err)
	}
	// OS_RELEASE is set by run-batches. On ubuntu, it looks like 24.04.
	osRel := os.Getenv("OS_RELEASE")
	extraSuffix := os.Getenv("EXTRA_REPORT_SUFFIX")
	descSuffix := osRel
	fileSuffix := osRel
	if BPFMode() {
		fileSuffix += "_bpf"
		descSuffix += " BPF"
	} else {
		descSuffix += " non-BPF"
	}
	if NFTMode() {
		fileSuffix += "_nft"
		descSuffix += " (nftables)"
	} else {
		fileSuffix += "_ipt"
		descSuffix += " (iptables)"
	}
	if extraSuffix != "" {
		descSuffix += " " + extraSuffix
	}
	suiteConfig, reporterConfig := GinkgoConfiguration()
	reportPath = fmt.Sprintf("../report/felix_fv_%s.xml", fileSuffix)
	reporterConfig.JUnitReport = ""
	RunSpecs(t, "FV: Felix "+descSuffix, suiteConfig, reporterConfig)
}

var _ = BeforeEach(func() {
	_, _ = fmt.Fprintf(realStdout, "\nFV-TEST-START: %s", CurrentSpecReport().FullText())
})

var _ = JustAfterEach(func() {
	if CurrentSpecReport().Failed() {
		_, _ = fmt.Fprintf(realStdout, "\n")
	}
})

var _ = AfterEach(func() {
	defer connectivity.UnactivatedCheckers.Clear()
	if CurrentSpecReport().Failed() {
		// If the test has already failed, ignore any connectivity checker leak.
		return
	}
	gomega.Expect(connectivity.UnactivatedCheckers.Len()).To(gomega.BeZero(),
		"Test bug: ConnectivityChecker was created but not activated.")
})

var stopMonitorC = make(chan struct{})
var procFS procfs.FS

var _ = BeforeSuite(func() {
	// Set up monitoring of the VM's overall state.  Since CI VMs are relatively
	// small, this can be very helpful to spot if a test failure was due to
	// running low on RAM/disk etc.
	var err error
	// Using Prometheus' library because we already import it indirectly.
	procFS, err = procfs.NewFS("/proc")
	gomega.Expect(err).NotTo(gomega.HaveOccurred())
	go func() {
		for {
			select {
			case <-stopMonitorC:
				logStats()
				return
			case <-time.After(time.Second * 20):
				// Periodically log the overall state of the VM.
				logStats()
			}
		}
	}()
})

func configureManualSharding() error {
	currentBatch, err := strconv.Atoi(os.Getenv("FV_BATCH"))
	if err != nil {
		return err
	}
	totalBatches, err := strconv.Atoi(os.Getenv("FV_NUM_BATCHES"))
	if err != nil {
		return err
	}

	if totalBatches <= 1 || currentBatch <= 0 {
		return errors.New("invalid FV_BATCH or FV_NUM_BATCHES environment variable")
	}

	fmt.Printf("[SHARD-INIT] Manual Sharding Active: Running Batch %d of %d\n", currentBatch, totalBatches)

	BeforeEach(func() {
		specReport := CurrentSpecReport()
		hash := hashString(specReport.FullText())
		assignedBatch := (hash % uint32(totalBatches)) + 1
		if int(assignedBatch) != currentBatch {
			Skip(fmt.Sprintf("️[SHARD-SKIP] Test assigned to batch %d (Current: %d)", assignedBatch, currentBatch))
		} else {
			fmt.Printf("️[SHARD-RUN] Batch %d executing: %s\n", currentBatch, specReport.LeafNodeText)
		}
	})

	return nil
}

func hashString(s string) uint32 {
	h := fnv.New32a()
	h.Write([]byte(s))
	return h.Sum32()
}

func logStats() {
	p := message.NewPrinter(language.English)

	// Load average, i.e. the number of processes waiting for CPU time,
	// averaged over 1/5/15 min.
	la, err := procFS.LoadAvg()
	var buf bytes.Buffer
	buf.WriteString("\nSTATS: ")
	if err == nil {
		_, _ = p.Fprintf(&buf, "LoadAvg=%.2f/%.2f/%.2f ", la.Load1, la.Load5, la.Load15)
	} else {
		_, _ = p.Fprintf(&buf, "LoadAvg=ERR(%v) ", err)
	}

	// Memory usage.
	mem, err := procFS.Meminfo()
	if err == nil {
		myRSS := "ERR"
		myPID := os.Getpid()
		proc, err := procFS.Proc(myPID)
		if err == nil {
			pStat, err := proc.Stat()
			if err == nil {
				myRSS = formatBytes(uint64(pStat.RSS) * uint64(os.Getpagesize()))
			}
		}

		sample := []metrics.Sample{
			{Name: "/memory/classes/heap/objects:bytes"},
		}
		metrics.Read(sample)

		_, _ = p.Fprintf(&buf, "MemTotal/Free+Cache/Avail/ProcRSS/Heap=%s/%s/%s/%s/%s ",
			formatKB(*mem.MemTotal), formatKB(*mem.MemFree+*mem.Cached+*mem.Buffers), formatKB(*mem.MemAvailable),
			myRSS, formatBytes(sample[0].Value.Uint64()))
	} else {
		_, _ = p.Fprintf(&buf, "Mem=ERR(%v) ", err)
	}

	// Root filesystem usage.
	var stat unix.Statfs_t
	err = unix.Statfs("/", &stat)
	if err == nil {
		avail := formatBytes(stat.Bavail * uint64(stat.Bsize))
		percent := float64(stat.Bavail) * 100 / float64(stat.Blocks)
		_, _ = p.Fprintf(&buf, "RootFSFree=%s(%.1f%%) ", avail, percent)
	} else {
		_, _ = p.Fprintf(&buf, "RootFSFree=ERR(%v) ", err)
	}
	buf.WriteByte('\n')
	_, _ = realStdout.Write(buf.Bytes())
}

func formatKB(b uint64) string {
	return formatBytes(b * 1024)
}

func formatBytes(b uint64) string {
	switch true {
	case b < 1024:
		return fmt.Sprintf("%dB", b)
	case b < 1024*1024:
		return fmt.Sprintf("%.1fKiB", float64(b)/1024)
	case b < 1024*1024*1024:
		return fmt.Sprintf("%.1fMiB", float64(b)/1024/1024)
	default:
		return fmt.Sprintf("%.1fGiB", float64(b)/1024/1024/1024)
	}
}

var _ = AfterSuite(func() {
	for i, k8sInfra := range infrastructure.K8sInfra {
		if k8sInfra != nil {
			infrastructure.TearDownK8sInfra(k8sInfra)
			infrastructure.K8sInfra[i] = nil
		}
	}
	infrastructure.RemoveTLSCredentials()
	close(stopMonitorC)
})

var _ = ReportAfterSuite("Clean Report Generator", func(report Report) {
	cleanSpecs := []SpecReport{}
	skippedOrPendingCount := 0

	for _, spec := range report.SpecReports {
		// Filter skipped or pending tests
		if spec.State == types.SpecStateSkipped || spec.State == types.SpecStatePending {
			skippedOrPendingCount++
			continue
		}

		// Strip logs for passed tests to save space
		if spec.State == types.SpecStatePassed {
			spec.CapturedGinkgoWriterOutput = ""
			spec.CapturedStdOutErr = ""
		}

		cleanSpecs = append(cleanSpecs, spec)
	}

	// Update the report object with the filtered list
	report.SpecReports = cleanSpecs
	fmt.Printf("\n[REPORT-CLEANER] Removed %d skipped or pending specs. Saving report with %d specs.\n", skippedOrPendingCount, len(cleanSpecs))

	if reportPath != "" {
		if err := reporters.GenerateJUnitReport(report, reportPath); err != nil {
			fmt.Printf("[REPORT-CLEANER] Error generating JUnit report: %v\n", err)
		} else {
			fmt.Printf("[REPORT-CLEANER] JUnit report saved to: %s\n", reportPath)
		}
	}
})
