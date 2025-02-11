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
	"github.com/projectcalico/calico/felix/bpf/conntrack/timeouts"
	"github.com/projectcalico/calico/felix/bpf/libbpf"
)

var (
	registerOnce           sync.Once
	summaryCleanerExecTime = prometheus.NewSummary(prometheus.SummaryOpts{
		Name: "felix_bpf_conntrack_cleaner_seconds",
		Help: "Time taken to run the conntrack cleaner BPF program.",
	})
)

func registerConntrackMetrics() {
	registerOnce.Do(func() {
		prometheus.MustRegister(
			summaryCleanerExecTime,
		)
	})
}

type BPFLogLevel string

const (
	BPFLogLevelDebug BPFLogLevel = "debug"
	BPFLogLevelNone  BPFLogLevel = "no_log"
)

// BPFProgCleaner uses a BPF program to scan the
// conntrack table for expired entries.  The BPF program does the entry
// deletion, taking care to delete forward and reverse NAT entries together,
// thus minimising the window where only one entry is present.
//
// Note: the tests for this object are largely in the bpf/ut package, since
// we require a privileged environment to test the BPF program.
type BPFProgCleaner struct {
	ipVersion int
	timeouts  timeouts.Timeouts
	logLevel  BPFLogLevel

	bpfExpiryProgram *libbpf.Obj
}

func NewBPFProgCleaner(
	ipVersion int,
	timeouts timeouts.Timeouts,
	bpfLogLevel BPFLogLevel,
) (Cleaner, error) {
	if ipVersion != 4 && ipVersion != 6 {
		return nil, fmt.Errorf("invalid IP version: %d", ipVersion)
	}
	if bpfLogLevel != BPFLogLevelDebug && bpfLogLevel != BPFLogLevelNone {
		return nil, fmt.Errorf("invalid BPF log level: %s", bpfLogLevel)
	}
	s := &BPFProgCleaner{
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

func (s *BPFProgCleaner) ensureBPFExpiryProgram() (*libbpf.Obj, error) {
	if s.bpfExpiryProgram != nil {
		return s.bpfExpiryProgram, nil
	}

	// Load the BPF program.  We only build the co-re version because CT cleanup
	// needs a newer than co-re.
	binaryToLoad := path.Join(bpfdefs.ObjectDir,
		fmt.Sprintf("conntrack_cleanup_%s_co-re_v%d.o", s.logLevel, s.ipVersion))

	ctCleanupData := &libbpf.CTCleanupGlobalData{
		CreationGracePeriod: s.timeouts.CreationGracePeriod,
		TCPSynSent:          s.timeouts.TCPSynSent,
		TCPEstablished:      s.timeouts.TCPEstablished,
		TCPFinsSeen:         s.timeouts.TCPFinsSeen,
		TCPResetSeen:        s.timeouts.TCPResetSeen,
		UDPTimeout:          s.timeouts.UDPTimeout,
		GenericTimeout:      s.timeouts.GenericTimeout,
		ICMPTimeout:         s.timeouts.ICMPTimeout}

	var obj *libbpf.Obj
	var err error
	if log.GetLevel() < log.DebugLevel {
		obj, err = bpf.LoadObjectWithLogBuffer(binaryToLoad, ctCleanupData, make([]byte, 1<<20))
	} else {
		obj, err = bpf.LoadObject(binaryToLoad, ctCleanupData)
	}
	if err != nil {
		return nil, fmt.Errorf("error loading %s: %w", binaryToLoad, err)
	}
	s.bpfExpiryProgram = obj
	return s.bpfExpiryProgram, nil
}

// CleanupContext is the result of running the BPF cleanup program.
//
// WARNING: this struct needs to match struct ct_iter_ctx in
// conntrack_cleanup.c.
type CleanupContext struct {
	StartTime uint64
	EndTime   uint64

	NumKVsCleaned uint64
}

type RunOpt func(result *CleanupContext)

func WithStartTime(t uint64) RunOpt {
	return func(ctx *CleanupContext) {
		ctx.StartTime = t
	}
}

func (s *BPFProgCleaner) Run(opts ...RunOpt) (*CleanupContext, error) {
	program, err := s.ensureBPFExpiryProgram()
	if err != nil {
		return nil, fmt.Errorf("failed to load BPF program: %w", err)
	}
	fd, err := program.ProgramFD("conntrack_cleanup")
	if err != nil {
		return nil, fmt.Errorf("failed to look up BPF program section: %w", err)
	}

	var cr CleanupContext
	for _, opt := range opts {
		opt(&cr)
	}
	// The BPF program returns its context/result in the packet buffer, size it accordingly.
	var programInput [unsafe.Sizeof(cr)]byte
	_, err = binary.Encode(programInput[:], binary.LittleEndian, cr)
	if err != nil {
		return nil, fmt.Errorf("failed to encode cleanup program input: %w", err)
	}

	result, err := bpf.RunBPFProgram(bpf.ProgFD(fd), programInput[:], 1)
	if err != nil {
		return nil, fmt.Errorf("failed to run cleanup program: %w", err)
	}

	// Output "packet" is returned in its own buffer.  Decode it.
	_, err = binary.Decode(result.DataOut, binary.LittleEndian, &cr)
	if err != nil {
		return nil, fmt.Errorf("failed to parse cleanup program result: %w", err)
	}
	log.WithFields(log.Fields{
		"timeTaken": result.Duration,
		"stats":     cr,
	}).Debug("Conntrack cleanup result.")

	summaryCleanerExecTime.Observe(result.Duration.Seconds())
	return &cr, nil
}

func (s *BPFProgCleaner) Close() error {
	err := s.bpfExpiryProgram.Close()
	s.bpfExpiryProgram = nil
	return err
}
