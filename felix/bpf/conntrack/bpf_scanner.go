// Copyright (c) 2024 Tigera, Inc. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package conntrack

import (
	"encoding/binary"
	"fmt"
	"path"
	"sync"
	"unsafe"

	"github.com/prometheus/client_golang/prometheus"
	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/felix/bpf"
	"github.com/projectcalico/calico/felix/bpf/bpfdefs"
	"github.com/projectcalico/calico/felix/bpf/libbpf"
)

type BPFLogLevel string

const (
	BPFLogLevelDebug BPFLogLevel = "debug"
	BPFLogLevelNone  BPFLogLevel = "no_log"
)

var (
	registerOnce sync.Once

	gaugeVecConntrackEntries = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "felix_bpf_conntrack_entries_seen",
		Help: "Number of entries seen in the conntrack table at the last GC sweep, grouped by type.",
	}, []string{"type"})
	counterVecConntrackEntriesDeleted = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "felix_bpf_conntrack_entries_deleted",
		Help: "Cumulative number of entries deleted from the conntrack table, grouped by type.",
	}, []string{"type"})
	summaryCleanerExecTime = prometheus.NewSummary(prometheus.SummaryOpts{
		Name: "felix_bpf_conntrack_cleaner_seconds",
		Help: "Time taken to run the conntrack cleaner BPF program.",
	})
)

func registerConntrackMetrics() {
	registerOnce.Do(func() {
		prometheus.MustRegister(
			gaugeVecConntrackEntries,
			counterVecConntrackEntriesDeleted,
			summaryCleanerExecTime,
		)
	})
}

// BPFProgLivenessScanner is a scanner that uses a BPF program to scan the
// conntrack table for expired entries.  The BPF program does the entry
// deletion, taking care to delete forward and reverse NAT entries together,
// thus minimising the window where only one entry is present.
//
// Note: the tests for this object are largely in the bpf/ut package, since
// we require a privileged environment to test the BPF program.
type BPFProgLivenessScanner struct {
	ipVersion int
	timeouts  Timeouts
	logLevel  BPFLogLevel

	bpfExpiryProgram *libbpf.Obj
}

func NewBPFProgLivenessScanner(
	ipVersion int,
	timeouts Timeouts,
	bpfLogLevel BPFLogLevel,
) (*BPFProgLivenessScanner, error) {
	if ipVersion != 4 && ipVersion != 6 {
		return nil, fmt.Errorf("invalid IP version: %d", ipVersion)
	}
	if bpfLogLevel != BPFLogLevelDebug && bpfLogLevel != BPFLogLevelNone {
		return nil, fmt.Errorf("invalid BPF log level: %s", bpfLogLevel)
	}
	s := &BPFProgLivenessScanner{
		ipVersion: ipVersion,
		timeouts:  timeouts,
		logLevel:  bpfLogLevel,
	}
	_, err := s.ensureBPFExpiryProgram()
	if err != nil {
		return nil, err
	}
	registerConntrackMetrics()
	return s, nil
}

func (s *BPFProgLivenessScanner) ensureBPFExpiryProgram() (*libbpf.Obj, error) {
	if s.bpfExpiryProgram != nil {
		return s.bpfExpiryProgram, nil
	}

	// Load the BPF program.  We only build the co-re version because CT cleanup
	// needs a newer than co-re.
	binaryToLoad := path.Join(bpfdefs.ObjectDir,
		fmt.Sprintf("conntrack_cleanup_%s_co-re_v%d.o", s.logLevel, s.ipVersion))
	ctMapParams := MapParams
	if s.ipVersion == 6 {
		ctMapParams = MapParamsV6
	}

	ctCleanupData := &libbpf.CTCleanupGlobalData{
		CreationGracePeriod: s.timeouts.CreationGracePeriod,
		TCPSynSent:          s.timeouts.TCPSynSent,
		TCPEstablished:      s.timeouts.TCPEstablished,
		TCPFinsSeen:         s.timeouts.TCPFinsSeen,
		TCPResetSeen:        s.timeouts.TCPResetSeen,
		UDPTimeout:          s.timeouts.UDPTimeout,
		GenericTimeout:      s.timeouts.GenericTimeout,
		ICMPTimeout:         s.timeouts.ICMPTimeout}

	obj, err := bpf.LoadObject(binaryToLoad, ctCleanupData, ctMapParams.VersionedName())
	if err != nil {
		return nil, fmt.Errorf("error loading %s: %w", binaryToLoad, err)
	}
	s.bpfExpiryProgram = obj
	return s.bpfExpiryProgram, nil
}

func (s *BPFProgLivenessScanner) IterationStart() {
	err := s.RunBPFExpiryProgram()
	if err != nil {
		log.WithError(err).Error("Failed to run conntrack cleanup BPF program.  Conntrack entries may leak.")
	}
}

func (s *BPFProgLivenessScanner) Check(
	keyInterface KeyInterface,
	valueInterface ValueInterface,
	get EntryGet,
) ScanVerdict {
	return ScanVerdictOK
}

func (s *BPFProgLivenessScanner) IterationEnd() {

}

// CleanupContext is the result of running the BPF cleanup program.
//
// WARNING: this struct needs to match struct ct_iter_ctx in
// conntrack_cleanup.c.
type CleanupContext struct {
	StartTime uint64
	EndTime   uint64

	NumKVsSeenNormal     uint64
	NumKVsSeenNATForward uint64
	NumKVsSeenNATReverse uint64

	NumKVsDeletedNormal     uint64
	NumKVsDeletedNATForward uint64
	NumKVsDeletedNATReverse uint64
}

type RunOpt func(result *CleanupContext)

func WithStartTime(t uint64) RunOpt {
	return func(ctx *CleanupContext) {
		ctx.StartTime = t
	}
}

func (s *BPFProgLivenessScanner) RunBPFExpiryProgram(opts ...RunOpt) error {
	program, err := s.ensureBPFExpiryProgram()
	if err != nil {
		return fmt.Errorf("failed to load BPF program: %w", err)
	}
	fd, err := program.ProgramFD("conntrack_cleanup")
	if err != nil {
		return fmt.Errorf("failed to look up BPF program section: %w", err)
	}

	var cr CleanupContext
	for _, opt := range opts {
		opt(&cr)
	}
	// The BPF program returns its context/result in the packet buffer, size it accordingly.
	var programInput [unsafe.Sizeof(cr)]byte
	_, err = binary.Encode(programInput[:], binary.LittleEndian, cr)
	if err != nil {
		return fmt.Errorf("failed to encode cleanup program input: %w", err)
	}

	result, err := bpf.RunBPFProgram(bpf.ProgFD(fd), programInput[:], 1)
	if err != nil {
		return fmt.Errorf("failed to run cleanup program: %w", err)
	}

	// Output "packet" is returned in its own buffer.  Decode it.
	_, err = binary.Decode(result.DataOut, binary.LittleEndian, &cr)
	if err != nil {
		return fmt.Errorf("failed to parse cleanup program result: %w", err)
	}
	log.WithFields(log.Fields{
		"timeTaken": result.Duration,
		"stats":     cr,
	}).Debug("Conntrack cleanup result.")

	// Record stats...
	summaryCleanerExecTime.Observe(result.Duration.Seconds())

	gaugeVecConntrackEntries.WithLabelValues("total").Set(float64(
		cr.NumKVsSeenNormal + cr.NumKVsSeenNATForward + cr.NumKVsSeenNATReverse))
	gaugeVecConntrackEntries.WithLabelValues("normal").Set(float64(cr.NumKVsSeenNormal))
	gaugeVecConntrackEntries.WithLabelValues("nat_forward").Set(float64(cr.NumKVsSeenNATForward))
	gaugeVecConntrackEntries.WithLabelValues("nat_reverse").Set(float64(cr.NumKVsSeenNATReverse))

	counterVecConntrackEntriesDeleted.WithLabelValues("total").Add(float64(
		cr.NumKVsDeletedNormal + cr.NumKVsDeletedNATForward + cr.NumKVsDeletedNATReverse))
	counterVecConntrackEntriesDeleted.WithLabelValues("normal").Add(float64(cr.NumKVsDeletedNormal))
	counterVecConntrackEntriesDeleted.WithLabelValues("nat_forward").Add(float64(cr.NumKVsDeletedNATForward))
	counterVecConntrackEntriesDeleted.WithLabelValues("nat_reverse").Add(float64(cr.NumKVsDeletedNATReverse))

	return nil
}

func (s *BPFProgLivenessScanner) Close() error {
	err := s.bpfExpiryProgram.Close()
	s.bpfExpiryProgram = nil
	return err
}

var _ EntryScannerSynced = (*BPFProgLivenessScanner)(nil)
