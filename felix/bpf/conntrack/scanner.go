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
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/felix/bpf/conntrack/cleanupv1"
	"github.com/projectcalico/calico/felix/bpf/conntrack/timeouts"
	v4 "github.com/projectcalico/calico/felix/bpf/conntrack/v4"
	"github.com/projectcalico/calico/felix/bpf/maps"
	"github.com/projectcalico/calico/felix/cachingmap"
	"github.com/projectcalico/calico/felix/jitter"
)

var (
	conntrackCounterSweeps = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "felix_bpf_conntrack_sweeps",
		Help: "Number of contrack table sweeps made so far",
	})
	conntrackGaugeUsed = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "felix_bpf_conntrack_used",
		Help: "Number of used entries visited during a conntrack table sweep",
	})
	conntrackGaugeCleaned = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "felix_bpf_conntrack_cleaned",
		Help: "Number of entries cleaned during a conntrack table sweep",
	})
	conntrackCounterCleaned = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "felix_bpf_conntrack_cleaned_total",
		Help: "Total number of entries cleaned during conntrack table sweeps, " +
			"incremented for each clean individualy",
	})
	conntrackGaugeSweepDuration = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "felix_bpf_conntrack_sweep_duration",
		Help: "Conntrack sweep execution time (ns)",
	})
	conntrackGaugeMaglevTotal = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "felix_bpf_conntrack_maglev_entries_total",
		Help: "Total number of Maglev entries in conntrack table broken down by IP version, and, whether destination backend is remote (we're acting as a frontend) or local (we're the backend node).",
	}, []string{"destination", "ip_family"})
	dummyKeyV6 = NewKeyV6(0, net.IPv6zero, 0, net.IPv6zero, 0)
	dummyKey   = NewKey(0, net.IPv4zero, 0, net.IPv4zero, 0)
)

func init() {
	prometheus.MustRegister(conntrackCounterSweeps)
	prometheus.MustRegister(conntrackGaugeUsed)
	prometheus.MustRegister(conntrackGaugeCleaned)
	prometheus.MustRegister(conntrackCounterCleaned)
	prometheus.MustRegister(conntrackGaugeSweepDuration)
	prometheus.MustRegister(conntrackGaugeMaglevTotal)
}

// ScanVerdict represents the set of values returned by EntryScan
type ScanVerdict int

const (
	// ScanVerdictOK means entry is fine and should remain
	ScanVerdictOK ScanVerdict = iota
	// ScanVerdictDelete means entry should be deleted
	ScanVerdictDelete
	ScanVerdictDeleteImmediate // Delete without adding to cleanup map
)

const cleanupBatchSize int = 1000

// EntryGet is a function prototype provided to EntryScanner in case it needs to
// evaluate other entries to make a verdict
type EntryGet func(KeyInterface) (ValueInterface, error)

// EntryScanner is a function prototype to be called on every entry by the scanner
type EntryScanner interface {
	Check(KeyInterface, ValueInterface, EntryGet) (ScanVerdict, int64)
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
	ctCleanupMap                 *cachingmap.CachingMap[KeyInterface, cleanupv1.ValueInterface]
	keyFromBytes                 func([]byte) KeyInterface
	valueFromBytes               func([]byte) ValueInterface
	scanners                     []EntryScanner
	liveEntries                  int
	higherCount                  int
	maxEntries                   int
	autoScale                    bool
	configChangedRestartCallback func()
	bpfCleaner                   Cleaner
	versionHelper                ipVersionHelper
	revNATKeyToFwdNATInfo        map[KeyInterface]cleanupv1.ValueInterface
	ipFamily                     int

	conntrackGaugeMaglevToLocalBackend  prometheus.Gauge
	conntrackGaugeMaglevToRemoteBackend prometheus.Gauge

	wg       sync.WaitGroup
	stopCh   chan struct{}
	stopOnce sync.Once
}

// NewScanner returns a scanner for the given conntrack map and the set of
// EntryScanner. They are executed in the provided order on each entry.
func NewScanner(ctMap maps.Map, kfb func([]byte) KeyInterface, vfb func([]byte) ValueInterface,
	configChangedRestartCallback func(),
	autoScalingMode string, ctCleanupMap maps.MapWithExistsCheck,
	ipVersion int,
	bpfCleaner Cleaner,
	scanners ...EntryScanner) *Scanner {

	s := &Scanner{
		ctMap:                        ctMap,
		keyFromBytes:                 kfb,
		valueFromBytes:               vfb,
		scanners:                     scanners,
		stopCh:                       make(chan struct{}),
		liveEntries:                  ctMap.Size(),
		maxEntries:                   ctMap.Size(),
		autoScale:                    strings.ToLower(autoScalingMode) == "doubleiffull",
		configChangedRestartCallback: configChangedRestartCallback,
		bpfCleaner:                   bpfCleaner,
		ipFamily:                     ipVersion,
		// revNATKeyToFwdNATInfo stores the opposite direction of the mapping of the cleanup bpf map.
		// <reverseNATKey> => <forwardNATKey>:<forwardEntryTimeStamp>:<reverseEntryTimestamp>
		revNATKeyToFwdNATInfo: make(map[KeyInterface]cleanupv1.ValueInterface),
	}

	if bpfCleaner != nil {
		switch ipVersion {
		case 4:
			s.ctCleanupMap = cachingmap.New[KeyInterface, cleanupv1.ValueInterface](ctCleanupMap.GetName(),
				maps.NewTypedMap[KeyInterface, cleanupv1.ValueInterface](ctCleanupMap, kfb, CleanupValueFromBytes))
			s.versionHelper = ipv4Helper{}
		case 6:
			s.ctCleanupMap = cachingmap.New[KeyInterface, cleanupv1.ValueInterface](ctCleanupMap.GetName(),
				maps.NewTypedMap[KeyInterface, cleanupv1.ValueInterface](ctCleanupMap, kfb, CleanupValueV6FromBytes))
			s.versionHelper = ipv6Helper{}
		default:
			return nil

		}
	}

	var err error

	s.conntrackGaugeMaglevToLocalBackend, err = conntrackGaugeMaglevTotal.GetMetricWithLabelValues("local", strconv.Itoa(s.ipFamily))
	if err != nil {
		log.WithError(err).Panic("Couldn't init (local) Maglev conntrack metric gauge")
	}

	s.conntrackGaugeMaglevToRemoteBackend, err = conntrackGaugeMaglevTotal.GetMetricWithLabelValues("remote", strconv.Itoa(s.ipFamily))
	if err != nil {
		log.WithError(err).Panic("Couldn't get (remote) Maglev conntrack metric gauge")
	}

	return s
}

func (s *Scanner) updateCleanupMap(key, revKey KeyInterface, ts, rev_ts uint64) {
	val := s.versionHelper.newCleanupValue(revKey.AsBytes(), ts, rev_ts)
	s.ctCleanupMap.Desired().Set(key, val)
}

func (s *Scanner) handleNATEntries(key KeyInterface, val ValueInterface, rev_ts uint64) {
	ts := uint64(val.LastSeen())
	if val.Type() == TypeNATForward {
		revKey := val.ReverseNATKey()
		// If reverse key is not present in the conntrack map,
		// timestamp returned from the scanner will match the
		// same as that of entry's ts. Just go ahead with deletion.
		if ts == rev_ts {
			dummy := s.versionHelper.dummyKey()
			s.updateCleanupMap(key, dummy, ts, rev_ts)
			return
		}
		_, ok := s.revNATKeyToFwdNATInfo[revKey]
		if !ok {
			// Reverse entry not seen by the scanner. Don't queue it up for deletion.
			// Wait to see if the scanner sees the reverse entry.
			// Store the mapping from reverse key to the forward key and the timestamps.
			s.revNATKeyToFwdNATInfo[revKey] = s.versionHelper.newCleanupValue(key.AsBytes(), ts, rev_ts)
		} else {
			// Reverse entry already seen.
			delete(s.revNATKeyToFwdNATInfo, revKey)
			s.updateCleanupMap(key, revKey, ts, rev_ts)
			return
		}
	} else if val.Type() == TypeNATReverse {
		revVal, ok := s.revNATKeyToFwdNATInfo[key]
		if ok {
			// Reverse key already in the map. Must be from the forward entry.
			delete(s.revNATKeyToFwdNATInfo, key)
			// Get the forward NAT key and timestamp from the map and update the
			// cleanup bpf map.
			fwdKey := revVal.OtherNATKey()
			fwdTS := revVal.Timestamp()
			s.updateCleanupMap(fwdKey, key, fwdTS, ts)
		} else {
			dummy := s.versionHelper.dummyKey()
			s.revNATKeyToFwdNATInfo[key] = s.versionHelper.newCleanupValue(dummy.AsBytes(), ts, uint64(0))
		}
	}
}

// Scan executes a scanning iteration
func (s *Scanner) Scan() {
	s.iterStart()
	defer s.iterEnd()

	start := time.Now()

	debug := log.GetLevel() >= log.DebugLevel

	used := 0
	cleaned := 0
	numExpired := 0
	maglevEntriesToLocal, maglevEntriesToRemote := 0, 0

	if s.ctCleanupMap != nil {
		s.ctCleanupMap.Desired().DeleteAll()
	}
	log.Debug("Starting conntrack scanner iteration")
	err := s.ctMap.Iter(func(k, v []byte) maps.IteratorAction {
		ctKey := s.keyFromBytes(k)
		ctVal := s.valueFromBytes(v)
		ctFlags := ctVal.Flags()

		used++
		conntrackCounterCleaned.Inc()

		if debug {
			log.WithFields(log.Fields{
				"key":   ctKey,
				"entry": ctVal,
			}).Debug("Examining conntrack entry")
		}

		if ctFlags&v4.FlagMaglev != 0 {
			if ctFlags&v4.FlagExtLocal != 0 {
				log.Debug("Conntrack is local maglev connection. Incrementing maglev entries counter")
				maglevEntriesToLocal++
			} else if ctFlags&v4.FlagNATNPFwd != 0 {
				log.Debug("Conntrack is remote maglev connection. Incrementing maglev entries counter")
				maglevEntriesToRemote++
			}
		}

		for _, scanner := range s.scanners {
			verdict, ts := scanner.Check(ctKey, ctVal, s.get)
			switch verdict {
			case ScanVerdictOK:
				// Entry is fine, continue to next scanner.
				continue
			case ScanVerdictDelete, ScanVerdictDeleteImmediate:
				// Entry should be deleted.
				numExpired++
			}
			if debug {
				log.Debug("Deleting conntrack entry.")
			}
			// Fall back to userspace cleaner, when the bpf cleaner
			// fails to load.
			if s.bpfCleaner == nil {
				cleaned++
				return maps.IterDelete
			}
			if verdict == ScanVerdictDeleteImmediate {
				cleaned++
				if debug {
					log.WithFields(log.Fields{
						"key":   ctKey,
						"entry": ctVal,
					}).Debug("Deleting conntrack entry immediately.")
				}
				// Delete without adding to cleanup map.
				return maps.IterDelete
			}
			// NAT entry has expired.
			if ctVal.Type() != TypeNormal {
				s.handleNATEntries(ctKey, ctVal, uint64(ts))
				continue
			}
			dummy := s.versionHelper.dummyKey()
			s.updateCleanupMap(ctKey, dummy, uint64(ts), uint64(ts))
		}
		if numExpired > 0 && numExpired%cleanupBatchSize == 0 {
			cleaned += s.runBPFCleaner()
		}
		return maps.IterNone
	})

	// There can be forward or reverse entries in the map.
	// We have scanned the entire map.
	// Lets add it to the cleanup map.
	if len(s.revNATKeyToFwdNATInfo) > 0 {
		keysProcessed := 0
		for k, v := range s.revNATKeyToFwdNATInfo {
			// This is a forward entry and we haven't seen the rev entry.
			// Maybe deleted by LRU
			keysProcessed++
			revKey := v.OtherNATKey()
			ts := v.Timestamp()
			revTS := v.RevTimestamp()
			if revKey != s.versionHelper.dummyKey() {
				s.updateCleanupMap(revKey, k, ts, revTS)
			} else {
				s.updateCleanupMap(k, revKey, ts, revTS)
			}
			delete(s.revNATKeyToFwdNATInfo, k)
			if keysProcessed%cleanupBatchSize == 0 {
				// Run the bpf cleaner
				cleaned += s.runBPFCleaner()
			}
		}
	}

	if err != nil {
		log.WithError(err).Warn("Failed to iterate over conntrack map")
		return
	}

	// Run the bpf cleaner to process the remaining entries in the cleanup map.
	cleaned += s.runBPFCleaner()

	log.WithField("value", maglevEntriesToLocal).Debug("Setting local maglev conntrack entries gauge")
	s.conntrackGaugeMaglevToLocalBackend.Set(float64(maglevEntriesToLocal))
	log.WithField("value", maglevEntriesToRemote).Debug("Setting remote maglev conntrack entries gauge")
	s.conntrackGaugeMaglevToRemoteBackend.Set(float64(maglevEntriesToRemote))

	conntrackCounterSweeps.Inc()
	conntrackGaugeUsed.Set(float64(used))
	conntrackGaugeCleaned.Set(float64(cleaned))
	conntrackGaugeSweepDuration.Set(float64(time.Since(start)))
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

func (s *Scanner) runBPFCleaner() int {
	// Run the BPF cleanup program.
	if s.bpfCleaner != nil {
		if err := s.ctCleanupMap.ApplyAllChanges(); err != nil {
			log.WithError(err).Warn("Failed to write updates to conntrack cleanup BPF map.")
		}
		cr, err := s.bpfCleaner.Run()
		if err != nil {
			log.WithError(err).Warn("Failed to run bpf conntrack cleaner.")
		}
		s.ctCleanupMap.Desired().DeleteAll()
		s.ctCleanupMap.Dataplane().DeleteAll()
		return int(cr.NumKVsCleaned)
	}
	return 0
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

func (s *Scanner) Close() {
	if s.bpfCleaner != nil {
		s.bpfCleaner.Close()
	}
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

type Cleaner interface {
	Run(opts ...RunOpt) (*CleanupContext, error)
	Close() error
}

type ipVersionHelper interface {
	newCleanupValue(revKeyBytes []byte, ts, rev_ts uint64) cleanupv1.ValueInterface
	dummyKey() KeyInterface
}

type ipv4Helper struct{}

func (h ipv4Helper) newCleanupValue(revKeyBytes []byte, ts, rev_ts uint64) cleanupv1.ValueInterface {
	return cleanupv1.NewValue(revKeyBytes, ts, rev_ts)
}

func (h ipv4Helper) dummyKey() KeyInterface {
	return dummyKey
}

type ipv6Helper struct{}

func (h ipv6Helper) newCleanupValue(revKeyBytes []byte, ts, rev_ts uint64) cleanupv1.ValueInterface {
	return cleanupv1.NewValueV6(revKeyBytes, ts, rev_ts)
}

func (h ipv6Helper) dummyKey() KeyInterface {
	return dummyKeyV6
}
