// Copyright (c) 2020-2025 Tigera, Inc. All rights reserved.
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
	"strings"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/felix/bpf/conntrack/timeouts"
	"github.com/projectcalico/calico/felix/bpf/maps"
	"github.com/projectcalico/calico/felix/jitter"
)

var (
	conntrackCounterSweeps = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "felix_bpf_conntrack_sweeps",
		Help: "Number of contrack table sweeps made so far",
	})
	conntrackGaugeUsed = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "felix_bpf_conntrack_used",
		Help: "Number of entries seen in the conntrack table at the last GC sweep, grouped by type.",
	}, []string{"type"})
	conntrackGaugeCleaned = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "felix_bpf_conntrack_cleaned",
		Help: "Cumulative number of entries deleted from the conntrack table, grouped by type.",
	}, []string{"type"})
	conntrackGaugeSweepDuration = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "felix_bpf_conntrack_sweep_duration",
		Help: "Conntrack sweep execution time (ns)",
	})
	conntrackGuageMapSize = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "felix_bpf_conntrack_map_size",
		Help: "Size of the conntrack map (total capacity).",
	})
)

func init() {
	prometheus.MustRegister(conntrackCounterSweeps)
	prometheus.MustRegister(conntrackGaugeUsed)
	prometheus.MustRegister(conntrackGaugeCleaned)
	prometheus.MustRegister(conntrackGaugeSweepDuration)
	prometheus.MustRegister(conntrackGuageMapSize)
}

// ScanVerdict represents the set of values returned by EntryScan
type ScanVerdict int

const (
	// ScanVerdictOK means entry is fine and should remain
	ScanVerdictOK ScanVerdict = iota
	// ScanVerdictDelete means entry should be deleted
	ScanVerdictDelete
)

type CounterType int

const (
	// SeenNormal represents connections seen in the normal (forward) direction.
	SeenNormal CounterType = iota
	// SeenNATForward represents connections seen in the forward NAT direction.
	SeenNATForward
	// SeenNATReverse represents connections seen in the reverse NAT direction.
	SeenNATReverse
	// DeletedNormal represents normal connections that have been deleted.
	DeletedNormal
	// DeletedNATForward represents forward NAT connections that have been deleted.
	DeletedNATForward
	// DeletedNATReverse represents reverse NAT connections that have been deleted.
	DeletedNATReverse

	// numCounters is an unexported constant that holds the total number of counter types.
	// This is a useful trick to automatically size the array.
	numCounters
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
	ctMap                        maps.Map
	keyFromBytes                 func([]byte) KeyInterface
	valueFromBytes               func([]byte) ValueInterface
	scanners                     []EntryScanner
	liveEntries                  int
	higherCount                  int
	maxEntries                   int
	autoScale                    bool
	configChangedRestartCallback func()
	counters                     [numCounters]uint64

	wg       sync.WaitGroup
	stopCh   chan struct{}
	stopOnce sync.Once
}

// NewScanner returns a scanner for the given conntrack map and the set of
// EntryScanner. They are executed in the provided order on each entry.
func NewScanner(ctMap maps.Map, kfb func([]byte) KeyInterface, vfb func([]byte) ValueInterface,
	configChangedRestartCallback func(),
	autoScalingMode string,
	scanners ...EntryScanner) *Scanner {

	return &Scanner{
		ctMap:                        ctMap,
		keyFromBytes:                 kfb,
		valueFromBytes:               vfb,
		scanners:                     scanners,
		stopCh:                       make(chan struct{}),
		liveEntries:                  ctMap.Size(),
		maxEntries:                   ctMap.Size(),
		autoScale:                    strings.ToLower(autoScalingMode) == "doubleiffull",
		configChangedRestartCallback: configChangedRestartCallback,
	}
}

func (s *Scanner) incrementSeenCounters(ctType uint8) {
	switch ctType {
	case TypeNormal:
		s.counters[SeenNormal]++
	case TypeNATForward:
		s.counters[SeenNATForward]++
	case TypeNATReverse:
		s.counters[SeenNATReverse]++
	default:
		return
	}
}

func (s *Scanner) incrementDeletedCounters(ctType uint8) {
	switch ctType {
	case TypeNormal:
		s.counters[DeletedNormal]++
	case TypeNATForward:
		s.counters[DeletedNATForward]++
	case TypeNATReverse:
		s.counters[DeletedNATReverse]++
	default:
		return
	}
}

func (s *Scanner) totalUsed() uint64 {
	return s.counters[SeenNormal] + s.counters[SeenNATForward] + s.counters[SeenNATReverse]
}

func (s *Scanner) totalDeleted() uint64 {
	return s.counters[DeletedNormal] + s.counters[DeletedNATForward] + s.counters[DeletedNATReverse]
}

func (s *Scanner) resetCounters() {
	s.counters = [numCounters]uint64{}
}

// Scan executes a scanning iteration
func (s *Scanner) Scan() {
	s.iterStart()
	defer s.iterEnd()

	start := time.Now()

	debug := log.GetLevel() >= log.DebugLevel

	log.Debug("Starting conntrack scanner iteration")
	err := s.ctMap.Iter(func(k, v []byte) maps.IteratorAction {
		ctKey := s.keyFromBytes(k)
		ctVal := s.valueFromBytes(v)

		s.incrementSeenCounters(ctVal.Type())

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
				s.incrementDeletedCounters(ctVal.Type())
				return maps.IterDelete
			}
		}
		return maps.IterNone
	})

	if err != nil {
		log.WithError(err).Warn("Failed to iterate over conntrack map")
		return
	}

	used := s.totalUsed()
	cleaned := s.totalDeleted()

	// Update counters
	conntrackCounterSweeps.Inc()
	conntrackGaugeSweepDuration.Set(float64(time.Since(start)))
	conntrackGaugeUsed.WithLabelValues("total").Set(float64(used))
	conntrackGaugeUsed.WithLabelValues("normal").Set(float64(s.counters[SeenNormal]))
	conntrackGaugeUsed.WithLabelValues("nat_forward").Set(float64(s.counters[SeenNATForward]))
	conntrackGaugeUsed.WithLabelValues("nat_reverse").Set(float64(s.counters[SeenNATReverse]))

	conntrackGaugeCleaned.WithLabelValues("total").Add(float64(cleaned))
	conntrackGaugeCleaned.WithLabelValues("normal").Add(float64(s.counters[DeletedNormal]))
	conntrackGaugeCleaned.WithLabelValues("nat_forward").Add(float64(s.counters[DeletedNATForward]))
	conntrackGaugeCleaned.WithLabelValues("nat_reverse").Add(float64(s.counters[DeletedNATReverse]))
	conntrackGuageMapSize.Set(float64(s.maxEntries))

	if !s.autoScale {
		return
	}

	newLiveEntries := int(used - cleaned)
	if s.liveEntries > newLiveEntries {
		s.higherCount++
	} else {
		s.higherCount = 0
	}
	s.liveEntries = newLiveEntries

	full := float64(newLiveEntries) / float64(s.maxEntries)
	log.Debugf("full %f, total %d, totalDeleted %d", full, used, cleaned)

	// If the ct map keeps filling up and gets over 85% full or if it hits 90%
	// no matter what, resize the map.
	if s.higherCount >= 3 && full > 0.85 || full > 0.90 {
		if err := s.writeNewSizeFile(); err != nil {
			log.WithError(err).Warn("Failed to start resizing conntrack map when running out of space")
		} else {
			if s.configChangedRestartCallback != nil {
				log.Warnf("The eBPF conntrack table is becoming full. To prevent connections from failing, "+
					"resizing from %d to %d entries. Restarting Felix to apply the new size.", s.maxEntries, 2*s.maxEntries)
				s.configChangedRestartCallback()
			}
		}
	}
}

func (s *Scanner) writeNewSizeFile() error {
	// Make sure directory exists.
	if err := os.MkdirAll("/var/lib/calico", os.ModePerm); err != nil {
		return fmt.Errorf("failed to create directory /var/lib/calico: %s", err)
	}

	newSize := 2 * s.ctMap.Size()

	// Write the new map size to disk so that restarts will pick it up.
	filename := "/var/lib/calico/bpf_ct_map_size"
	log.Debugf("Writing %d to "+filename, newSize)
	if err := os.WriteFile(filename, []byte(fmt.Sprintf("%d", newSize)), 0o644); err != nil {
		return fmt.Errorf("unable to write to %s: %w", filename, err)
	}
	return nil
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

		ticker := jitter.NewTicker(timeouts.ScanPeriod, 100*time.Millisecond)

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
	log.Debug("Calling IterationStart on all scanners")
	s.resetCounters()
	for _, scanner := range s.scanners {
		if synced, ok := scanner.(EntryScannerSynced); ok {
			synced.IterationStart()
		}
	}
}

func (s *Scanner) iterEnd() {
	log.Debug("Calling IterationEnd on all scanners")
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

// AddFirstUnlocked adds an additional EntryScanner to a non-running Scanner as
// the first scanner to be called.
func (s *Scanner) AddFirstUnlocked(scanner EntryScanner) {
	s.scanners = append([]EntryScanner{scanner}, s.scanners...)
}
