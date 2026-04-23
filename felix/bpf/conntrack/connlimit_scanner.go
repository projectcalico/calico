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
	direction uint32
}

// ConnLimitScanner is an EntryScannerSynced that periodically recounts active
// TCP connections per interface+direction using the BPF CT map and writes the
// true count to the cali_qos BPF map. This corrects any drift from LRU
// eviction or connection close without explicit decrement.
//
// The BPF dataplane increments the count on new TCP SYN. This scanner
// periodically recounts all established connections and overwrites the count,
// serving as the sole decrement mechanism (connections that close or time out
// simply aren't counted on the next scan).
type ConnLimitScanner struct {
	qosMap     maps.MapWithUpdateWithFlags
	getPodInfo ConnLimitPodInfoProvider
	podInfo    map[string]ConnLimitPodInfo
	counts     map[connlimitKey]uint32
}

// NewConnLimitScanner creates a new ConnLimitScanner.
func NewConnLimitScanner(
	qosMap maps.MapWithUpdateWithFlags,
	getPodInfo ConnLimitPodInfoProvider,
) *ConnLimitScanner {
	return &ConnLimitScanner{
		qosMap:     qosMap,
		getPodInfo: getPodInfo,
		counts:     make(map[connlimitKey]uint32),
	}
}

// IterationStart satisfies EntryScannerSynced
func (s *ConnLimitScanner) IterationStart() {
	s.podInfo = s.getPodInfo()
	s.counts = make(map[connlimitKey]uint32)
}

// Check satisfies EntryScanner. For each active TCP CT entry, it counts the
// connection against the appropriate interface+direction based on the pod IP
// and opener bit.
func (s *ConnLimitScanner) Check(ctKey KeyInterface, ctVal ValueInterface, get EntryGet) (ScanVerdict, int64) {
	if len(s.podInfo) == 0 {
		return ScanVerdictOK, 0
	}
	if ctKey.Proto() != 6 { // TCP only
		return ScanVerdictOK, 0
	}
	if ctVal.Type() == 1 { // Skip NAT_FWD
		return ScanVerdictOK, 0
	}

	data := ctVal.Data()

	// Skip connections that are closing or closed (any FIN or RST).
	if data.FINsSeenDSR() || data.RSTSeen() {
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

// IterationEnd satisfies EntryScannerSynced. Writes the recounted values to
// the cali_qos BPF map, updating only the current_count field while preserving
// all other fields (packet rate config/state).
func (s *ConnLimitScanner) IterationEnd() {
	if len(s.podInfo) == 0 {
		return
	}

	log.WithField("counts", s.counts).WithField("numPods", len(s.podInfo)).Debug("ConnLimitScanner: recount done")

	for key, count := range s.counts {
		s.updateCount(key.ifindex, key.direction, int32(count))
	}

	// Zero out counts for limited pods with no active connections.
	seen := make(map[connlimitKey]bool)
	for _, pod := range s.podInfo {
		if pod.HasIngressLimit {
			key := connlimitKey{ifindex: pod.IfIndex, direction: 1}
			if !seen[key] {
				seen[key] = true
				if _, counted := s.counts[key]; !counted {
					s.updateCount(pod.IfIndex, 1, 0)
				}
			}
		}
		if pod.HasEgressLimit {
			key := connlimitKey{ifindex: pod.IfIndex, direction: 0}
			if !seen[key] {
				seen[key] = true
				if _, counted := s.counts[key]; !counted {
					s.updateCount(pod.IfIndex, 0, 0)
				}
			}
		}
	}
}

// updateCount reads the QoS map entry, preserves all fields except
// current_count, and writes it back with the new count.
func (s *ConnLimitScanner) updateCount(ifindex, direction uint32, count int32) {
	qosKey := qos.NewKey(ifindex, direction)
	qosValBytes, err := s.qosMap.Get(qosKey.AsBytes())
	if err != nil {
		return
	}
	existing := qos.ValueFromBytes(qosValBytes)
	if existing.CurrentCount() == count {
		return // no change needed
	}
	newVal := qos.NewValue(
		existing.PacketRate(), existing.PacketBurst(),
		existing.PacketRateTokens(), existing.PacketRateLastUpdate(),
		existing.MaxConnections(), count,
	)
	if err := s.qosMap.UpdateWithFlags(qosKey.AsBytes(), newVal.AsBytes(), unix.BPF_F_LOCK); err != nil {
		log.WithField("ifindex", ifindex).WithField("direction", direction).WithError(err).Debug("Error updating QoS map during connlimit recount.")
	}
}

// ipToString converts a net.IP to a string key for map lookup.
func ipToString(ip net.IP) string {
	if ip4 := ip.To4(); ip4 != nil {
		return string(ip4)
	}
	return string(ip.To16())
}
