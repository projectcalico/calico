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

package conntrack

import (
	"fmt"
	"os"
	"path"
	"strings"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/felix/bpf"
	"github.com/projectcalico/calico/felix/bpf/bpfdefs"
	"github.com/projectcalico/calico/felix/bpf/libbpf"
	"github.com/projectcalico/calico/felix/bpf/maps"
	"github.com/projectcalico/calico/felix/jitter"
)

// ScanVerdict represents the set of values returned by EntryScan
type ScanVerdict int

const (
	// ScanVerdictOK means entry is fine and should remain
	ScanVerdictOK ScanVerdict = iota
	// ScanVerdictDelete means entry should be deleted
	ScanVerdictDelete

	// ScanPeriod determines how often we iterate over the conntrack table.
	ScanPeriod = 10 * time.Second
)

// EntryGet is a function prototype provided to EntryScanner in case it needs to
// evaluate other entries to make a verdict
type EntryGet func(KeyInterface) (ValueInterface, error)

// EntryScanner is a function prototype to be called on every entry by the scanner
type EntryScanner interface {
	Check(KeyInterface, ValueInterface, EntryGet) ScanVerdict
}

// EntryScannerSynced is a scanner synchronized with the iteration start/end.
type EntryScannerSynced interface {
	EntryScanner
	IterationStart()
	IterationEnd()
}

// Scanner iterates over a provided conntrack map and call a set of EntryScanner
// functions on each entry in the order as they were passed to NewScanner. If
// any of the EntryScanner returns ScanVerdictDelete, it deletes the entry, does
// not call any other EntryScanner and continues the iteration.
//
// It provides a delete-save iteration over the conntrack table for multiple
// evaluation functions, to keep their implementation simpler.
type Scanner struct {
	ctMap          maps.Map
	keyFromBytes   func([]byte) KeyInterface
	valueFromBytes func([]byte) ValueInterface
	scanners       []EntryScanner

	wg       sync.WaitGroup
	stopCh   chan struct{}
	stopOnce sync.Once
}

// NewScanner returns a scanner for the given conntrack map and the set of
// EntryScanner. They are executed in the provided order on each entry.
func NewScanner(ctMap maps.Map, kfb func([]byte) KeyInterface, vfb func([]byte) ValueInterface,
	scanners ...EntryScanner) *Scanner {

	return &Scanner{
		ctMap:          ctMap,
		keyFromBytes:   kfb,
		valueFromBytes: vfb,
		scanners:       scanners,
		stopCh:         make(chan struct{}),
	}
}

// Scan executes a scanning iteration
func (s *Scanner) Scan() {
	// Run the BPF-based expiry first.
	err := s.runBPFExpiryProgram()
	if err != nil {
		log.WithError(err).Error("Failed to run BPF program.")
	}

	s.iterStart()
	defer s.iterEnd()

	debug := log.GetLevel() >= log.DebugLevel

	err = s.ctMap.Iter(func(k, v []byte) maps.IteratorAction {
		ctKey := s.keyFromBytes(k)
		ctVal := s.valueFromBytes(v)

		if debug {
			log.WithFields(log.Fields{
				"key":   ctKey,
				"entry": ctVal,
			}).Debug("Examining conntrack entry")
		}

		for _, scanner := range s.scanners {
			if verdict := scanner.Check(ctKey, ctVal, s.get); verdict == ScanVerdictDelete {
				if debug {
					log.Debug("Deleting conntrack entry.")
				}
				return maps.IterDelete
			}
		}
		return maps.IterNone
	})

	if err != nil {
		log.WithError(err).Warn("Failed to iterate over conntrack map")
	}
}

func (s *Scanner) get(k KeyInterface) (ValueInterface, error) {
	v, err := s.ctMap.Get(k.AsBytes())

	if err != nil {
		return nil, err
	}

	return s.valueFromBytes(v), nil
}

// Start the periodic scanner
func (s *Scanner) Start() {
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()

		log.Debug("Conntrack scanner thread started")
		defer log.Debug("Conntrack scanner thread stopped")

		ticker := jitter.NewTicker(ScanPeriod, 100*time.Millisecond)

		for {
			s.Scan()

			select {
			case <-ticker.C:
				log.Debug("Conntrack cleanup timer popped")
			case <-s.stopCh:
				log.Debug("Conntrack cleanup got stop signal")
				return
			}
		}
	}()
}

func (s *Scanner) iterStart() {
	for _, scanner := range s.scanners {
		if synced, ok := scanner.(EntryScannerSynced); ok {
			synced.IterationStart()
		}
	}
}

func (s *Scanner) iterEnd() {
	for i := len(s.scanners) - 1; i >= 0; i-- {
		scanner := s.scanners[i]
		if synced, ok := scanner.(EntryScannerSynced); ok {
			synced.IterationEnd()
		}
	}
}

// Stop stops the Scanner and waits for it finishing.
func (s *Scanner) Stop() {
	s.stopOnce.Do(func() {
		close(s.stopCh)
		s.wg.Wait()
	})
}

// AddUnlocked adds an additional EntryScanner to a non-running Scanner
func (s *Scanner) AddUnlocked(scanner EntryScanner) {
	s.scanners = append(s.scanners, scanner)
}

func (s *Scanner) runBPFExpiryProgram() error {
	binaryToLoad := path.Join(bpfdefs.ObjectDir, "conntrack_cleanup_debug_v4.o")

	_, err := os.Stat(binaryToLoad)
	if err != nil {
		log.WithError(err).Panic("FIXME error from stat")
	}
	obj, err := libbpf.OpenObject(binaryToLoad)
	if err != nil {
		log.WithError(err).Panic("FIXME failed to load binary")
	}

	for m, err := obj.FirstMap(); m != nil && err == nil; m, err = m.NextMap() {
		// In case of global variables, libbpf creates an internal map <prog_name>.rodata
		// The values are read only for the BPF programs, but can be set to a value from
		// userspace before the program is loaded.
		mapName := m.Name()
		if m.IsMapInternal() {
			if strings.HasPrefix(mapName, ".rodata") {
				continue
			}

			// FIXME use real timeouts.
			err := libbpf.CTCleanupSetGlobals(m, libbpf.ConntrackTimeouts(DefaultTimeouts()))
			if err != nil {
				return fmt.Errorf("error setting global variables for map %s: %w", mapName, err)
			}
			continue
		}

		log.WithField("mapName", mapName).Info("Resizing map")
		if size := maps.Size(mapName); size != 0 {
			if err := m.SetSize(size); err != nil {
				return fmt.Errorf("error resizing map %s: %w", mapName, err)
			}
		}

		log.Debugf("Pinning map %s k %d v %d", mapName, m.KeySize(), m.ValueSize())
		pinDir := bpf.MapPinDir(m.Type(), mapName, "", 0)
		if err := m.SetPinPath(path.Join(pinDir, mapName)); err != nil {
			return fmt.Errorf("error pinning map %s k %d v %d: %w", mapName, m.KeySize(), m.ValueSize(), err)
		}
	}

	defer func() {
		_ = obj.Close()
	}()

	if err := obj.Load(); err != nil {
		return fmt.Errorf("error loading program: %w", err)
	}

	fd, err := obj.ProgramFD("conntrack_cleanup")
	if err != nil {
		return fmt.Errorf("failed to look up section: %w", err)
	}

	result, err := bpf.RunBPFProgram(bpf.ProgFD(fd), make([]byte, 1000), 1)
	if err != nil {
		return fmt.Errorf("failed to run cleanup program: %w", err)
	}
	log.WithField("cleanupResult", result.RC).Infof("Ran conntrack cleanup program (%v).", result.Duration)

	return nil
}
