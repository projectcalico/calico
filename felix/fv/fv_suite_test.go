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

//go:build fvtests

package fv_test

import (
	"bytes"
	"fmt"
	"os"
	"runtime/metrics"
	"testing"
	"time"

	"github.com/prometheus/procfs"
	"golang.org/x/sys/unix"
	"golang.org/x/text/language"
	"golang.org/x/text/message"

	"github.com/projectcalico/calico/felix/fv/connectivity"

	"github.com/onsi/gomega/format"

	. "github.com/onsi/ginkgo"
	"github.com/onsi/ginkgo/reporters"
	. "github.com/onsi/gomega"

	"github.com/projectcalico/calico/felix/fv/infrastructure"
	"github.com/projectcalico/calico/libcalico-go/lib/testutils"
)

var realStdout = os.Stdout

func init() {
	testutils.HookLogrusForGinkgo()

	// Avoid truncating diffs when Equals assertions fail.
	format.TruncatedDiff = false
}

func TestFv(t *testing.T) {
	RegisterFailHandler(Fail)
	reportName := "fv_suite"
	if NFTMode() {
		reportName = "fv_nft_suite"
	}
	junitReporter := reporters.NewJUnitReporter(fmt.Sprintf("../report/%s.xml", reportName))
	RunSpecsWithDefaultAndCustomReporters(t, "FV Suite", []Reporter{junitReporter})
}

var _ = BeforeEach(func() {
	_, _ = fmt.Fprintf(realStdout, "\nFV-TEST-START: %s", CurrentGinkgoTestDescription().FullTestText)
})

var _ = JustAfterEach(func() {
	if CurrentGinkgoTestDescription().Failed {
		_, _ = fmt.Fprintf(realStdout, "\n")
	}
})

var _ = AfterEach(func() {
	defer connectivity.UnactivatedCheckers.Clear()
	if CurrentGinkgoTestDescription().Failed {
		// If the test has already failed, ignore any connectivity checker leak.
		return
	}
	Expect(connectivity.UnactivatedCheckers.Len()).To(BeZero(),
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
	Expect(err).NotTo(HaveOccurred())
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
