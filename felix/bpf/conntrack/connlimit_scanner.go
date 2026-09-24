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
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netlink/nl"
	"golang.org/x/sys/unix"

	"github.com/projectcalico/calico/felix/bpf/conntrack/timeouts"
	v4 "github.com/projectcalico/calico/felix/bpf/conntrack/v4"
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

// flowKey identifies a TCP flow independent of direction: the endpoint that
// sorts lower is always first.
type flowKey struct {
	ipA, ipB     string
	portA, portB uint16
}

// rstFlow is a counted flow that saw an RST, and the counters it charged.
type rstFlow struct {
	charged  []connlimitKey
	seenIter int
	lastSeen time.Time
}

// LinuxEstablishedTCPFlows returns the TCP flows that Linux conntrack holds in
// ESTABLISHED state for the given family (4 or 6).
type LinuxEstablishedTCPFlows func(family uint16) (map[flowKey]struct{}, error)

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
// scan loop, which runs every timeouts.ScanPeriod.
//
// N = 1 because the recount is no longer only a drift safety net: an RST no
// longer decrements on the fast path, so this is what returns the slot of an
// RST-closed connection once its entry is purged.
const connLimitScannerRunEveryN = 1

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

	// rstFlows: counted flows that saw an RST. Once reaped, they count while
	// Linux conntrack holds them ESTABLISHED, for at most rstFlowMaxAge.
	rstFlows         map[flowKey]*rstFlow
	rstFlowMaxAge    time.Duration
	linuxEstablished LinuxEstablishedTCPFlows
	now              func() time.Time
}

// ConnLimitScannerOpt configures a ConnLimitScanner.
type ConnLimitScannerOpt func(*ConnLimitScanner)

// WithRSTFlowMaxAge bounds how long a reaped RST'd flow keeps counting;
// TCPEstablished reaps any idle flow anyway.
func WithRSTFlowMaxAge(d time.Duration) ConnLimitScannerOpt {
	return func(s *ConnLimitScanner) {
		s.rstFlowMaxAge = d
	}
}

// WithLinuxEstablishedTCPFlows replaces the Linux conntrack reader, for tests.
func WithLinuxEstablishedTCPFlows(f LinuxEstablishedTCPFlows) ConnLimitScannerOpt {
	return func(s *ConnLimitScanner) {
		s.linuxEstablished = f
	}
}

// WithClock replaces the clock, for tests.
func WithClock(now func() time.Time) ConnLimitScannerOpt {
	return func(s *ConnLimitScanner) {
		s.now = now
	}
}

// NewConnLimitScanner creates a new ConnLimitScanner. family must be either
// qos.IPFamilyV4 (4) or qos.IPFamilyV6 (6) — it identifies which family's
// CT map this scanner is walking and which family's cali_qos_conn entry
// it writes back to.
func NewConnLimitScanner(
	qosMap connLimitQoSMap,
	getPodInfo ConnLimitPodInfoProvider,
	family uint16,
	opts ...ConnLimitScannerOpt,
) *ConnLimitScanner {
	s := &ConnLimitScanner{
		qosMap:           qosMap,
		getPodInfo:       getPodInfo,
		family:           family,
		counts:           make(map[connlimitKey]uint32),
		rstFlows:         make(map[flowKey]*rstFlow),
		rstFlowMaxAge:    timeouts.DefaultTimeouts().TCPEstablished,
		linuxEstablished: linuxEstablishedTCPFlows,
		now:              time.Now,
	}
	for _, opt := range opts {
		opt(s)
	}
	return s
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

	// A present entry is not reaped; it is remembered again below if it
	// still counts.
	if len(s.rstFlows) > 0 {
		delete(s.rstFlows, makeFlowKey(ctKey.AddrA(), ctKey.PortA(), ctKey.AddrB(), ctKey.PortB()))
	}

	data := ctVal.Data()

	// Skip a close both endpoints agreed on; the fast path decremented it.
	// Only DSR takes one FIN as the whole close, because the return leg
	// never reaches this hook (CORE-13478 Failure.6).
	if (ctVal.IsForwardDSR() && data.FINsSeenDSR()) || data.FINsSeen() {
		return ScanVerdictOK, 0
	}

	// No RST state is skipped: a pod emits RSTs at will and would hide its
	// own live connections (CORE-13478 Failure.1).

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

	// to-wep stamps this when it skips the ingress limit for a local-host
	// source. CORE-13478 Failure.4.
	hostOpened := ctVal.Flags()&v4.FlagHostOrigin != 0

	var charged []connlimitKey
	if podAIsLimited {
		if aIsOpener && podA.HasEgressLimit {
			charged = append(charged, connlimitKey{ifindex: podA.IfIndex, direction: 0})
		} else if !aIsOpener && podA.HasIngressLimit && !hostOpened {
			charged = append(charged, connlimitKey{ifindex: podA.IfIndex, direction: 1})
		}
	}

	if podBIsLimited {
		if !aIsOpener && podB.HasEgressLimit {
			charged = append(charged, connlimitKey{ifindex: podB.IfIndex, direction: 0})
		} else if aIsOpener && podB.HasIngressLimit && !hostOpened {
			charged = append(charged, connlimitKey{ifindex: podB.IfIndex, direction: 1})
		}
	}

	for _, k := range charged {
		s.counts[k]++
	}

	// Only flows routed through the host stack have Linux conntrack state to
	// outlive the reap.
	viaNetfilter := ctVal.Flags()&(v4.FlagNATOut|v4.FlagSkipFIB) != 0
	if len(charged) > 0 && ctVal.RSTSeen() != 0 && viaNetfilter {
		if s.rstFlows == nil {
			s.rstFlows = make(map[flowKey]*rstFlow)
		}
		s.rstFlows[makeFlowKey(addrA, ctKey.PortA(), addrB, ctKey.PortB())] = &rstFlow{
			charged:  charged,
			seenIter: s.iterCount,
			lastSeen: s.clock(),
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
		clear(s.rstFlows)
		return
	}

	s.countReapedRSTFlows()

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

// countReapedRSTFlows counts RST'd flows whose BPF entry is gone but which Linux
// conntrack still holds ESTABLISHED, and forgets the rest.
func (s *ConnLimitScanner) countReapedRSTFlows() {
	limited := s.limitedKeys()
	now := s.clock()
	var reaped []flowKey
	for fk, f := range s.rstFlows {
		if f.seenIter == s.iterCount {
			continue
		}
		if now.Sub(f.lastSeen) > s.rstFlowMaxAge || !chargesStillLimited(f.charged, limited) {
			delete(s.rstFlows, fk)
			continue
		}
		reaped = append(reaped, fk)
	}
	if len(reaped) == 0 {
		return
	}

	readLinux := s.linuxEstablished
	if readLinux == nil {
		readLinux = linuxEstablishedTCPFlows
	}
	linux, err := readLinux(s.family)
	if err != nil {
		// Keep counting them until the age cap; the next scan retries.
		log.WithError(err).Warn("ConnLimitScanner: failed to read Linux conntrack.")
	}
	for _, fk := range reaped {
		if err == nil {
			if _, ok := linux[fk]; !ok {
				delete(s.rstFlows, fk)
				continue
			}
		}
		for _, k := range s.rstFlows[fk].charged {
			s.counts[k]++
		}
	}
}

// limitedKeys returns the counters of the pods limited right now.
func (s *ConnLimitScanner) limitedKeys() map[connlimitKey]bool {
	keys := make(map[connlimitKey]bool)
	for _, pod := range s.podInfo {
		if pod.HasIngressLimit {
			keys[connlimitKey{ifindex: pod.IfIndex, direction: 1}] = true
		}
		if pod.HasEgressLimit {
			keys[connlimitKey{ifindex: pod.IfIndex, direction: 0}] = true
		}
	}
	return keys
}

// chargesStillLimited reports whether every charged counter still belongs to a
// limited pod; ifindexes get reused.
func chargesStillLimited(charged []connlimitKey, limited map[connlimitKey]bool) bool {
	for _, k := range charged {
		if !limited[k] {
			return false
		}
	}
	return true
}

func (s *ConnLimitScanner) clock() time.Time {
	if s.now == nil {
		return time.Now()
	}
	return s.now()
}

// linuxEstablishedTCPFlows reads Linux conntrack over netlink.
func linuxEstablishedTCPFlows(family uint16) (map[flowKey]struct{}, error) {
	inet := netlink.InetFamily(unix.AF_INET)
	if family == qos.IPFamilyV6 {
		inet = netlink.InetFamily(unix.AF_INET6)
	}
	flows, err := netlink.ConntrackTableList(netlink.ConntrackTable, inet)
	if err != nil {
		return nil, err
	}
	return establishedTCPFlowKeys(flows), nil
}

// establishedTCPFlowKeys keys each ESTABLISHED TCP flow by both of its tuples.
func establishedTCPFlowKeys(flows []*netlink.ConntrackFlow) map[flowKey]struct{} {
	established := make(map[flowKey]struct{})
	for _, f := range flows {
		if f.Forward.Protocol != unix.IPPROTO_TCP {
			continue
		}
		tcp, ok := f.ProtoInfo.(*netlink.ProtoInfoTCP)
		if !ok || tcp.State != nl.TCP_CONNTRACK_ESTABLISHED {
			continue
		}
		established[makeFlowKey(f.Forward.SrcIP, f.Forward.SrcPort, f.Forward.DstIP, f.Forward.DstPort)] = struct{}{}
		// A flow Linux DNATs to a workload is keyed post-DNAT in BPF, which
		// only the reply tuple carries.
		established[makeFlowKey(f.Reverse.SrcIP, f.Reverse.SrcPort, f.Reverse.DstIP, f.Reverse.DstPort)] = struct{}{}
	}
	return established
}

func makeFlowKey(ip1 net.IP, port1 uint16, ip2 net.IP, port2 uint16) flowKey {
	a, b := ipToString(ip1), ipToString(ip2)
	if a > b || (a == b && port1 > port2) {
		a, b = b, a
		port1, port2 = port2, port1
	}
	return flowKey{ipA: a, ipB: b, portA: port1, portB: port2}
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
