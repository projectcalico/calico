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

package conntrack

import (
	"net"

	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"

	ctv4 "github.com/projectcalico/calico/felix/bpf/conntrack/v4"
	"github.com/projectcalico/calico/felix/bpf/maps"
	"github.com/projectcalico/calico/felix/bpf/qos"
)

// ConnLimitPodInfo describes a pod with connection limits configured.
type ConnLimitPodInfo struct {
	IfIndex         uint32
	HasIngressLimit bool
	HasEgressLimit  bool
}

// ConnLimitPodInfoProvider is a function that returns the current set of
// connection-limited pods, keyed by their IP address (as a 4-byte or 16-byte string).
type ConnLimitPodInfoProvider func() map[string]ConnLimitPodInfo

type connlimitKey struct {
	ifindex   uint32
	direction uint16
}

// ConnLimitScanner is an EntryScannerSynced that periodically recounts active
// TCP connections per interface+direction using the BPF CT map and writes the
// true count to the cali_qos_conn BPF map. This corrects any drift from LRU
// eviction or connection close without explicit decrement.
//
// The BPF dataplane increments the count on new TCP SYN. This scanner
// periodically recounts all established connections and overwrites the count,
// serving as the sole decrement mechanism (connections that close or time out
// simply aren't counted on the next scan).
// connLimitScannerRunEveryN downsamples the scanner relative to the parent CT
// scan loop. With timeouts.ScanPeriod = 10s and N = 3 the scanner does a real
// recount roughly every 30s; the intervening 2 iterations early-return in
// IterationStart / Check / IterationEnd. The scanner only exists as a drift
// safety net for silent CT-entry purges (half-close, idle TCPEstablished,
// network partition), so a ~30s recovery window is adequate.
const connLimitScannerRunEveryN = 3

// connLimitQoSMap is the subset of the cali_qos_conn BPF map API that the
// scanner needs. Narrowed from maps.MapWithUpdateWithFlags so tests can
// supply a small fake without taking a dependency on the full Map interface
// (avoids an import cycle with felix/bpf/mock, which itself depends on
// conntrack). The scanner only touches the connection-limit map — packet-
// rate state lives in a separate cali_qos map that the scanner never
// reads or writes; this is what prevents the lost-update race that
// motivated the split (see qos.h).
type connLimitQoSMap interface {
	Get(k []byte) ([]byte, error)
	BatchUpdate(ks, vs [][]byte, flags uint64) (int, error)
}

type ConnLimitScanner struct {
	qosMap     connLimitQoSMap
	getPodInfo ConnLimitPodInfoProvider
	podInfo    map[string]ConnLimitPodInfo
	counts     map[connlimitKey]uint32
	// family is the IP family this scanner runs over (4 or 6). Used as
	// the family dimension when writing back to the cali_qos_conn map so
	// v4 and v6 each update their own counter, avoiding the dual-stack
	// overwrite that would otherwise happen with a shared map entry.
	family      uint16
	iterCount   int
	skipThisRun bool
}

// NewConnLimitScanner creates a new ConnLimitScanner. family must be either
// qos.IPFamilyV4 (4) or qos.IPFamilyV6 (6) — it identifies which family's
// CT map this scanner is walking and which family's cali_qos_conn entry
// it writes back to.
func NewConnLimitScanner(
	qosMap connLimitQoSMap,
	getPodInfo ConnLimitPodInfoProvider,
	family uint16,
) *ConnLimitScanner {
	return &ConnLimitScanner{
		qosMap:     qosMap,
		getPodInfo: getPodInfo,
		family:     family,
		counts:     make(map[connlimitKey]uint32),
	}
}

// IterationStart satisfies EntryScannerSynced. Downsamples the recount to run
// on iterations 1, 1+N, 1+2N, ... so a recount fires on the first CT scan
// after Felix starts (rather than waiting for the Nth scan).
func (s *ConnLimitScanner) IterationStart() {
	s.iterCount++
	s.skipThisRun = connLimitScannerRunEveryN > 1 && (s.iterCount-1)%connLimitScannerRunEveryN != 0
	if s.skipThisRun {
		return
	}
	s.podInfo = s.getPodInfo()
	s.counts = make(map[connlimitKey]uint32)
}

// Check satisfies EntryScanner. For each active TCP CT entry, it counts the
// connection against the appropriate interface+direction based on the pod IP
// and opener bit.
func (s *ConnLimitScanner) Check(ctKey KeyInterface, ctVal ValueInterface, get EntryGet) (ScanVerdict, int64) {
	if s.skipThisRun {
		return ScanVerdictOK, 0
	}
	if len(s.podInfo) == 0 {
		return ScanVerdictOK, 0
	}
	if ctKey.Proto() != 6 { // TCP only
		return ScanVerdictOK, 0
	}
	if ctVal.Type() == TypeNATForward {
		return ScanVerdictOK, 0
	}

	data := ctVal.Data()

	// Skip connections that are closing or closed (any FIN or RST),
	// or already decremented by the BPF fast path. The CONNLIMIT_DEC
	// flag is set when the BPF program decrements the counter on
	// FIN/RST; if we counted these entries, the scanner's recount
	// would overwrite the decremented value with a higher one.
	if data.FINsSeenDSR() || data.RSTSeen() {
		return ScanVerdictOK, 0
	}
	if ctVal.Flags()&ctv4.FlagConnLimitDec != 0 {
		return ScanVerdictOK, 0
	}
	// Only count fully established connections.
	if !data.Established() {
		return ScanVerdictOK, 0
	}

	addrA := ctKey.AddrA()
	addrB := ctKey.AddrB()
	ipA := ipToString(addrA)
	ipB := ipToString(addrB)

	podA, podAIsLimited := s.podInfo[ipA]
	podB, podBIsLimited := s.podInfo[ipB]

	if !podAIsLimited && !podBIsLimited {
		return ScanVerdictOK, 0
	}

	aIsOpener := data.A2B.Opener

	if podAIsLimited {
		if aIsOpener && podA.HasEgressLimit {
			s.counts[connlimitKey{ifindex: podA.IfIndex, direction: 0}]++
		} else if !aIsOpener && podA.HasIngressLimit {
			s.counts[connlimitKey{ifindex: podA.IfIndex, direction: 1}]++
		}
	}

	if podBIsLimited {
		if !aIsOpener && podB.HasEgressLimit {
			s.counts[connlimitKey{ifindex: podB.IfIndex, direction: 0}]++
		} else if aIsOpener && podB.HasIngressLimit {
			s.counts[connlimitKey{ifindex: podB.IfIndex, direction: 1}]++
		}
	}

	return ScanVerdictOK, 0
}

// IterationEnd satisfies EntryScannerSynced. Collects per-entry updates for
// the cali_qos BPF map (preserving all fields except current_count) and
// writes them in a single batch.
func (s *ConnLimitScanner) IterationEnd() {
	if s.skipThisRun {
		return
	}
	if len(s.podInfo) == 0 {
		return
	}

	log.WithField("counts", s.counts).WithField("numPods", len(s.podInfo)).Debug("ConnLimitScanner: recount done")

	batchCap := len(s.counts) + 2*len(s.podInfo)
	batchK := make([][]byte, 0, batchCap)
	batchV := make([][]byte, 0, batchCap)

	appendUpdate := func(ifindex uint32, direction uint16, count uint32) {
		if k, v, changed := s.prepareUpdate(ifindex, direction, count); changed {
			batchK = append(batchK, k)
			batchV = append(batchV, v)
		}
	}

	// Active counts.
	for key, count := range s.counts {
		appendUpdate(key.ifindex, key.direction, uint32(count))
	}

	// Zero out counts for limited pods with no active connections.
	seen := make(map[connlimitKey]bool)
	for _, pod := range s.podInfo {
		if pod.HasIngressLimit {
			key := connlimitKey{ifindex: pod.IfIndex, direction: 1}
			if !seen[key] {
				seen[key] = true
				if _, counted := s.counts[key]; !counted {
					appendUpdate(pod.IfIndex, 1, 0)
				}
			}
		}
		if pod.HasEgressLimit {
			key := connlimitKey{ifindex: pod.IfIndex, direction: 0}
			if !seen[key] {
				seen[key] = true
				if _, counted := s.counts[key]; !counted {
					appendUpdate(pod.IfIndex, 0, 0)
				}
			}
		}
	}

	if len(batchK) == 0 {
		return
	}
	applied, err := s.qosMap.BatchUpdate(batchK, batchV, unix.BPF_F_LOCK)
	if err != nil {
		log.WithError(err).
			WithField("applied", applied).
			WithField("requested", len(batchK)).
			Warn("ConnLimitScanner: BatchUpdate failed; some entries may not have been recounted.")
	}
}

// prepareUpdate reads the existing cali_qos_conn entry and returns the key
// bytes and a new value with current_count replaced by `count` (preserving
// max_connections). Returns changed=false when the existing count already
// matches `count`, or when the read fails. Packet-rate state lives in a
// separate map (cali_qos) that the scanner never touches.
func (s *ConnLimitScanner) prepareUpdate(ifindex uint32, direction uint16, count uint32) (keyBytes, valBytes []byte, changed bool) {
	qosKey := qos.NewKey(ifindex, direction, s.family)
	qosValBytes, err := s.qosMap.Get(qosKey.AsBytes())
	if err != nil {
		if !maps.IsNotExists(err) {
			log.WithField("ifindex", ifindex).WithField("direction", direction).WithError(err).Debug("ConnLimitScanner: error reading cali_qos_conn entry.")
		}
		return nil, nil, false
	}
	existing := qos.ConnValueFromBytes(qosValBytes)
	if existing.CurrentCount() == count {
		return nil, nil, false
	}
	newVal := qos.NewConnValue(existing.MaxConnections(), count)
	return qosKey.AsBytes(), newVal.AsBytes(), true
}

// ipToString converts a net.IP to a string key for map lookup.
func ipToString(ip net.IP) string {
	if ip4 := ip.To4(); ip4 != nil {
		return string(ip4)
	}
	return string(ip.To16())
}
