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
	"strings"
	"unsafe"

	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/felix/bpf"
	"github.com/projectcalico/calico/felix/bpf/bpfdefs"
	"github.com/projectcalico/calico/felix/bpf/libbpf"
	"github.com/projectcalico/calico/felix/bpf/maps"
)

type BPFLogLevel string

const (
	BPFLogLevelDebug BPFLogLevel = "debug"
	BPFLogLevelNone  BPFLogLevel = "no_log"
)

// BPFProgLivenessScanner is a scanner that uses a BPF program to scan the
// conntrack table for expired entries.  The BPF program does the entry
// deletion, taking care to delete forward and reverse NAT entries together,
// thus minimising the window where only one entry is present.
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
	return s, nil
}

func (s *BPFProgLivenessScanner) ensureBPFExpiryProgram() (*libbpf.Obj, error) {
	if s.bpfExpiryProgram != nil {
		return s.bpfExpiryProgram, nil
	}

	binaryToLoad := path.Join(bpfdefs.ObjectDir,
		fmt.Sprintf("conntrack_cleanup_%s_v%d.o", s.logLevel, s.ipVersion))
	obj, err := libbpf.OpenObject(binaryToLoad)
	if err != nil {
		return nil, fmt.Errorf("failed to load conntrack cleanup BPF program: %w", err)
	}

	success := false
	defer func() {
		if !success {
			err := obj.Close()
			if err != nil {
				log.WithError(err).Error("Error closing BPF object.")
			}
		}
	}()

	ctMapParams := MapParams
	if s.ipVersion == 6 {
		ctMapParams = MapParamsV6
	}
	pinnedCTMap := false
	for m, err := obj.FirstMap(); m != nil && err == nil; m, err = m.NextMap() {
		// In case of global variables, libbpf creates an internal map <prog_name>.rodata
		// The values are read only for the BPF programs, but can be set to a value from
		// userspace before the program is loaded.
		mapName := m.Name()
		if m.IsMapInternal() {
			if strings.HasPrefix(mapName, ".rodata") {
				continue
			}

			err := libbpf.CTCleanupSetGlobals(
				m,
				s.timeouts.CreationGracePeriod,
				s.timeouts.TCPPreEstablished,
				s.timeouts.TCPEstablished,
				s.timeouts.TCPFinsSeen,
				s.timeouts.TCPResetSeen,
				s.timeouts.UDPLastSeen,
				s.timeouts.GenericIPLastSeen,
				s.timeouts.ICMPLastSeen,
			)
			if err != nil {
				return nil, fmt.Errorf("error setting global variables for map %s: %w", mapName, err)
			}
			continue
		}

		if size := maps.Size(mapName); size != 0 {
			log.WithField("mapName", mapName).Info("Resizing map")
			if err := m.SetSize(size); err != nil {
				return nil, fmt.Errorf("error resizing map %s: %w", mapName, err)
			}
		}

		if mapName == ctMapParams.VersionedName()  {
			log.Debugf("Pinning map %s k %d v %d", mapName, m.KeySize(), m.ValueSize())
			pinDir := bpf.MapPinDir(m.Type(), mapName, "", 0)
			if err := m.SetPinPath(path.Join(pinDir, mapName)); err != nil {
				return nil, fmt.Errorf("error pinning map %s k %d v %d: %w", mapName, m.KeySize(), m.ValueSize(), err)
			}
			pinnedCTMap = true
		}
	}

	if !pinnedCTMap {
		// Panic here because it indicates a coding error that we want to
		// catch in testing.
		log.Panic("Bug: failed to find/pin conntrack map.")
	}

	if err := obj.Load(); err != nil {
		return nil, fmt.Errorf("error loading conntrack expiry program: %w", err)
	}

	success = true
	s.bpfExpiryProgram = obj
	return s.bpfExpiryProgram, nil
}

func (s *BPFProgLivenessScanner) IterationStart() {
	err := s.runBPFExpiryProgram()
	if err != nil {
		log.WithError(err).Error("Failed to run conntrack cleanup BPF program.  Conntrack entries may leak.")
	}
}

func (s *BPFProgLivenessScanner) Check(keyInterface KeyInterface, valueInterface ValueInterface, get EntryGet) ScanVerdict {
	return ScanVerdictOK
}

func (s *BPFProgLivenessScanner) IterationEnd() {

}

// CleanupResult is the result of running the BPF cleanup program.
//
// WARNING: this struct needs to match struct ct_iter_ctx in
// conntrack_cleanup.c.
type CleanupResult struct {
	StartTime  uint64
	NumSeen    uint64
	NumExpired uint64
	EndTime    uint64
}

func (s *BPFProgLivenessScanner) runBPFExpiryProgram() error {
	program, err := s.ensureBPFExpiryProgram()
	if err != nil {
		return fmt.Errorf("failed to load BPF program: %w", err)
	}
	fd, err := program.ProgramFD("conntrack_cleanup")
	if err != nil {
		return fmt.Errorf("failed to look up BPF program section: %w", err)
	}

	// The BPF program returns its result in the packet buffer, size it accordingly.
	var cr CleanupResult
	var dummyPayload [unsafe.Sizeof(cr)]byte
	result, err := bpf.RunBPFProgram(bpf.ProgFD(fd), dummyPayload[:], 1)
	if err != nil {
		return fmt.Errorf("failed to run cleanup program: %w", err)
	}

	// Output "packet" is returned in its own buffer.  Decode it.
	_, err = binary.Decode(result.DataOut, binary.LittleEndian, &cr)
	if err != nil {
		return fmt.Errorf("failed to parse cleanup program result: %w", err)
	}
	log.WithFields(log.Fields{
		"timeTaken":  result.Duration,
		"numSeen":    cr.NumSeen,
		"numExpired": cr.NumExpired,
	}).Debug("Conntrack cleanup result.")

	return nil
}

var _ EntryScannerSynced = (*BPFProgLivenessScanner)(nil)
