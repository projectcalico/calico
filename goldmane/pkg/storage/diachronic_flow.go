// Copyright (c) 2025-2026 Tigera, Inc. All rights reserved.

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

package storage

import (
	"math"
	"slices"
	"sort"
	"strings"
	"sync"
	"unique"

	"github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/goldmane/pkg/types"
	"github.com/projectcalico/calico/goldmane/proto"
)

// DiachronicFlow is a representation of a Flow over time. Each DiachronicFlow corresponds to a single FlowKey,
// but with statistics fields that are bucketed by time, allowing for easy aggregation of statistics
// across time windows.
type DiachronicFlow struct {
	ID  int64
	Key types.FlowKey

	// Windows is a slice of time windows that the DiachronicFlow has statistics for. Each element in the slice
	// represents a time window, and the statistics for that window are stored in the corresponding index
	// in the other fields.
	Windows []Window

	// sourceIPs and destIPs track the distinct source / destination IP addresses observed for this
	// flow (i.e. this FlowKey) across all of its windows. Each address records which windows it was
	// seen in via a bitmap, so a time-range query returns exactly the addresses seen in that range.
	//
	// ipsMu guards both maps: they are written by the main loop but also read by stream goroutines
	// building flows via DeferredFlowBuilder, and a concurrent map read/write is fatal.
	ipsMu     sync.RWMutex
	sourceIPs map[string]*ipEntry
	destIPs   map[string]*ipEntry
}

// MaxIPsPerFlow bounds the number of distinct source (or destination) IP addresses retained per
// DiachronicFlow, i.e. per FlowKey. A single FlowKey aggregates traffic from many connections
// (across nodes and time), so each IP set is capped to keep memory and wire size bounded. When the
// cap is reached, the least-recently-seen address is evicted to make room for a newly observed one,
// so the sets are best-effort (most-recent-wins) rather than exhaustive.
const MaxIPsPerFlow = 100

// windowSlots is the number of per-window bits tracked for each retained IP. Goldmane keeps at most
// numBuckets (242) windows of history, so 256 slots (packed into 4x uint64) give every live window
// its own bit with room to spare. A window's slot is (start/interval) % windowSlots; slots never
// collide while the number of live windows stays below windowSlots.
const windowSlots = 256

// windowSet is a windowSlots-bit set recording which window slots an IP was observed in.
type windowSet [windowSlots / 64]uint64

func (s *windowSet) set(slot int) { s[slot/64] |= 1 << (uint(slot) % 64) }
func (s *windowSet) empty() bool  { return s[0]|s[1]|s[2]|s[3] == 0 }

// clearAll clears every slot that is set in mask.
func (s *windowSet) clearAll(mask *windowSet) {
	for i := range s {
		s[i] &^= mask[i]
	}
}

// intersects reports whether this set shares any slot with other.
func (s *windowSet) intersects(other *windowSet) bool {
	return s[0]&other[0]|s[1]&other[1]|s[2]&other[2]|s[3]&other[3] != 0
}

// ipEntry records the windows an IP was seen in, plus the newest such window (lastSeen), which
// drives most-recent-wins eviction once the per-key cap is reached.
type ipEntry struct {
	windows  windowSet
	lastSeen int64
}

// bitIndex maps a window (identified by its [start, end) bounds) to its slot. Windows are aligned to
// interval boundaries and end == start+interval, so interval is recoverable as end-start.
func bitIndex(start, end int64) int {
	interval := end - start
	if interval <= 0 {
		return 0
	}
	slot := int((start / interval) % windowSlots)
	if slot < 0 {
		// Go's % keeps the dividend's sign; keep the slot in range for pre-epoch start times.
		slot += windowSlots
	}
	return slot
}

type Window struct {
	start int64
	end   int64

	SourceLabels            unique.Handle[string]
	DestLabels              unique.Handle[string]
	PacketsIn               int64
	PacketsOut              int64
	BytesIn                 int64
	BytesOut                int64
	NumConnectionsStarted   int64
	NumConnectionsCompleted int64
	NumConnectionsLive      int64
}

func (w *Window) Within(startGte, startLt int64) bool {
	return w.start >= startGte && w.end < startLt
}

func (w *Window) Contains(t int64) bool {
	return t >= w.start && t <= w.end
}

func NewDiachronicFlow(k *types.FlowKey, id int64) *DiachronicFlow {
	return &DiachronicFlow{
		ID:  id,
		Key: *k,
	}
}

func (d *DiachronicFlow) Rollover(limiter int64) {
	// Windows are sorted oldest -> newest. Find the first window that is still valid and
	// discard everything before it. Iterating forward finds the cut point on the first
	// check in the common case (one expired window per rollover).
	for i, w := range d.Windows {
		if w.end > limiter {
			if i > 0 {
				if logrus.IsLevelEnabled(logrus.DebugLevel) {
					logrus.WithFields(logrus.Fields{
						"limiter":  limiter,
						"numStale": i,
					}).Debug("Removing stale window(s) from diachronic flow")
				}
				d.expireWindows(d.Windows[:i])
				d.Windows = d.Windows[i:]
			}
			return
		}
	}

	// All windows are expired.
	if len(d.Windows) > 0 {
		d.expireWindows(d.Windows)
		d.Windows = d.Windows[:0]
	}
}

// expireWindows clears the bitmap slot of each expiring window from every tracked IP, and drops any
// IP that is no longer present in any live window.
func (d *DiachronicFlow) expireWindows(expired []Window) {
	d.ipsMu.Lock()
	defer d.ipsMu.Unlock()
	if len(d.sourceIPs) == 0 && len(d.destIPs) == 0 {
		return
	}
	var mask windowSet
	for i := range expired {
		mask.set(bitIndex(expired[i].start, expired[i].end))
	}
	clearSlots(d.sourceIPs, &mask)
	clearSlots(d.destIPs, &mask)
}

func clearSlots(m map[string]*ipEntry, mask *windowSet) {
	for ip, e := range m {
		e.windows.clearAll(mask)
		if e.windows.empty() {
			delete(m, ip)
		}
	}
}

func (d *DiachronicFlow) Empty() bool {
	return len(d.Windows) == 0
}

func (d *DiachronicFlow) AddFlow(flow *types.Flow, start, end int64) {
	if logrus.IsLevelEnabled(logrus.DebugLevel) {
		logrus.WithFields(d.Key.Fields()).WithFields(logrus.Fields{
			"flow":   flow,
			"window": Window{start: start, end: end},
		}).Debug("Adding flow data to diachronic flow")
	}

	// IPs are tracked per DiachronicFlow rather than per Window; see sourceIPs.
	d.recordIPs(flow, start, end)

	if len(d.Windows) == 0 {
		// This is the first Window, so create it.
		d.appendWindow(flow, start, end)
		return
	}

	// Find the Window that matches the flow's start time, if it exists. If it doesn't exist, create a new Window.
	// Windows are ordered by start time, so we can use binary search to find the correct window to add the flow to.
	index := sort.Search(len(d.Windows), func(i int) bool {
		return d.Windows[i].start >= start
	})
	if index == len(d.Windows) {
		// This flow is for a new window that is after all existing windows.
		d.appendWindow(flow, start, end)
		return
	} else if d.Windows[index].start != start {
		// We found a Window, but it doesn't match the flow's start time, so insert a new one.
		d.insertWindow(flow, index, start, end)
		return
	}

	// A window already exists for this flow's start time, so add this flow to it.
	d.addToWindow(flow, index)
}

func (d *DiachronicFlow) addToWindow(flow *types.Flow, index int) {
	if logrus.IsLevelEnabled(logrus.DebugLevel) {
		logrus.WithFields(d.Key.Fields()).WithFields(logrus.Fields{
			"flow":   flow,
			"window": d.Windows[index],
			"index":  index,
		}).Debug("Adding flow to existing window")
	}

	d.Windows[index].PacketsIn += flow.PacketsIn
	d.Windows[index].PacketsOut += flow.PacketsOut
	d.Windows[index].BytesIn += flow.BytesIn
	d.Windows[index].BytesOut += flow.BytesOut
	d.Windows[index].NumConnectionsStarted += flow.NumConnectionsStarted
	d.Windows[index].NumConnectionsCompleted += flow.NumConnectionsCompleted
	d.Windows[index].NumConnectionsLive += flow.NumConnectionsLive
	d.Windows[index].SourceLabels = intersection(d.Windows[index].SourceLabels, flow.SourceLabels)
	d.Windows[index].DestLabels = intersection(d.Windows[index].DestLabels, flow.DestLabels)
}

func (d *DiachronicFlow) insertWindow(flow *types.Flow, index int, start, end int64) {
	w := Window{
		start:                   start,
		end:                     end,
		PacketsIn:               flow.PacketsIn,
		PacketsOut:              flow.PacketsOut,
		BytesIn:                 flow.BytesIn,
		BytesOut:                flow.BytesOut,
		NumConnectionsStarted:   flow.NumConnectionsStarted,
		NumConnectionsCompleted: flow.NumConnectionsCompleted,
		NumConnectionsLive:      flow.NumConnectionsLive,
		SourceLabels:            flow.SourceLabels,
		DestLabels:              flow.DestLabels,
	}
	d.Windows = append(d.Windows[:index], append([]Window{w}, d.Windows[index:]...)...)

	if logrus.IsLevelEnabled(logrus.DebugLevel) {
		logrus.WithFields(d.Key.Fields()).WithFields(logrus.Fields{
			"flow":   flow,
			"window": w,
			"index":  index,
		}).Debug("Inserting new window for flow")
	}
}

func (d *DiachronicFlow) appendWindow(flow *types.Flow, start, end int64) {
	w := Window{
		start:                   start,
		end:                     end,
		PacketsIn:               flow.PacketsIn,
		PacketsOut:              flow.PacketsOut,
		BytesIn:                 flow.BytesIn,
		BytesOut:                flow.BytesOut,
		NumConnectionsStarted:   flow.NumConnectionsStarted,
		NumConnectionsCompleted: flow.NumConnectionsCompleted,
		NumConnectionsLive:      flow.NumConnectionsLive,
		SourceLabels:            flow.SourceLabels,
		DestLabels:              flow.DestLabels,
	}
	d.Windows = append(d.Windows, w)

	if logrus.IsLevelEnabled(logrus.DebugLevel) {
		logrus.WithFields(d.Key.Fields()).WithFields(logrus.Fields{
			"flow":   flow,
			"window": w,
		}).Debug("Adding flow to new window")
	}
}

// Aggregate aggregates the statistics from the DiachronicFlow into a new Flow object over the specified time range.
func (d *DiachronicFlow) Aggregate(startGte, startLt int64) *types.Flow {
	if !d.Within(startGte, startLt) {
		return nil
	}
	windows := d.GetWindows(startGte, startLt)
	f := d.AggregateWindows(windows)
	if f != nil {
		f.SourceIps, f.DestIps = d.ipsForWindows(windows)
	}
	return f
}

// GetWindows returns a slice of Windows that fall within the specified time range.
func (d *DiachronicFlow) GetWindows(startGte, startLt int64) []*Window {
	// Find the Windows that fall within the specified time range.
	windows := make([]*Window, 0)
	for _, w := range d.Windows {
		if (startGte == 0 || w.start >= startGte) &&
			(startLt == 0 || w.end <= startLt) {
			if logrus.IsLevelEnabled(logrus.DebugLevel) {
				logrus.WithFields(d.Key.Fields()).WithFields(logrus.Fields{
					"window":  w,
					"startGt": startGte,
					"startLt": startLt,
				}).Debug("Aggregating flow data from diachronic flow window")
			}
			windows = append(windows, &w)
		}
	}
	return windows
}

// AggregateWindows aggregates the statistics from the given Windows into a new Flow object.
func (d *DiachronicFlow) AggregateWindows(windows []*Window) *types.Flow {
	// Create a new Flow object and populate it with aggregated statistics from the DiachronicFlow.
	// acoss the time window specified by start and end.
	f := &types.Flow{
		SourceLabels: unique.Make(""),
		DestLabels:   unique.Make(""),
	}
	f.Key = &d.Key

	// Iterate each Window and aggregate the statistic contributions across all windows that fall within the
	// specified time range.
	for _, w := range windows {
		if logrus.IsLevelEnabled(logrus.DebugLevel) {
			logrus.WithFields(d.Key.Fields()).WithFields(logrus.Fields{
				"window": w,
			}).Debug("Aggregating flow data from diachronic flow window")
		}

		// Sum up summable stats.
		f.PacketsIn += w.PacketsIn
		f.PacketsOut += w.PacketsOut
		f.BytesIn += w.BytesIn
		f.BytesOut += w.BytesOut
		f.NumConnectionsStarted += w.NumConnectionsStarted
		f.NumConnectionsCompleted += w.NumConnectionsCompleted
		f.NumConnectionsLive += w.NumConnectionsLive

		// Merge labels. We use the intersection of the labels across all windows.
		if f.SourceLabels.Value() != "" {
			f.SourceLabels = intersection(f.SourceLabels, w.SourceLabels)
		} else {
			f.SourceLabels = w.SourceLabels
		}
		if f.DestLabels.Value() != "" {
			f.DestLabels = intersection(f.DestLabels, w.DestLabels)
		} else {
			f.DestLabels = w.DestLabels
		}

		// Update the flow's start and end times.
		if f.StartTime == 0 || w.start < f.StartTime {
			f.StartTime = w.start
		}
		if f.EndTime == 0 || w.end > f.EndTime {
			f.EndTime = w.end
		}
	}
	return f
}

func (d *DiachronicFlow) Matches(filter *proto.Filter, startGte, startLt int64) bool {
	if !d.Within(startGte, startLt) {
		return false
	}
	if filter == nil {
		return true
	}
	return types.Matches(filter, &d.Key)
}

func (d *DiachronicFlow) Within(startGte, startLt int64) bool {
	// Go through each window and return true if any of them
	// fall within the start and end time.
	for _, w := range d.Windows {
		if (startGte == 0 || w.start >= startGte) &&
			(startLt == 0 || w.start < startLt) {
			return true
		}
	}

	if logrus.IsLevelEnabled(logrus.DebugLevel) {
		logrus.WithFields(d.Key.Fields()).WithFields(logrus.Fields{
			"startGte": startGte,
			"startLt":  startLt,
		}).Debug("DiachronicFlow does not have data for time range")
	}
	return false
}

// intersection returns the intersection of two comma-separated label sets stored as unique handles.
func intersection(a unique.Handle[string], b unique.Handle[string]) unique.Handle[string] {
	if a == b {
		return a
	}
	return unique.Make(sortedCSVIntersection(a.Value(), b.Value()))
}

// sortedCSVIntersection computes the intersection of two sorted, comma-separated strings
// using a merge join in O(n+m). Both inputs must be sorted lexicographically by element
// (guaranteed by toHandles in types/flow.go).
func sortedCSVIntersection(a, b string) string {
	if a == "" || b == "" {
		return ""
	}

	var buf strings.Builder
	ai, bi := 0, 0
	for ai < len(a) && bi < len(b) {
		ae := strings.IndexByte(a[ai:], ',')
		if ae == -1 {
			ae = len(a) - ai
		}
		be := strings.IndexByte(b[bi:], ',')
		if be == -1 {
			be = len(b) - bi
		}

		aElem := a[ai : ai+ae]
		bElem := b[bi : bi+be]

		switch strings.Compare(aElem, bElem) {
		case 0:
			if buf.Len() > 0 {
				buf.WriteByte(',')
			}
			buf.WriteString(aElem)
			ai += ae + 1
			bi += be + 1
		case -1:
			ai += ae + 1
		case 1:
			bi += be + 1
		}
	}
	return buf.String()
}

// recordIPs marks each of the flow's source / destination IPs as seen in the window [start, end).
func (d *DiachronicFlow) recordIPs(flow *types.Flow, start, end int64) {
	if len(flow.SourceIps) == 0 && len(flow.DestIps) == 0 {
		return
	}
	slot := bitIndex(start, end)
	d.ipsMu.Lock()
	defer d.ipsMu.Unlock()
	d.sourceIPs = recordIPSet(d.sourceIPs, flow.SourceIps, slot, start)
	d.destIPs = recordIPSet(d.destIPs, flow.DestIps, slot, start)
}

// recordIPSet adds ips to m against the given window slot, lazily allocating m. When m is full, the
// least-recently-seen entry is evicted to make room, unless the incoming window is older than every
// retained entry (e.g. a late-arriving flow for an old window), in which case the new IP is dropped.
// Entries seen in the same window are equally recent; the lowest address, including incoming IPs, is dropped.
func recordIPSet(m map[string]*ipEntry, ips []string, slot int, start int64) map[string]*ipEntry {
	// Refresh already-tracked IPs first, so a new IP earlier in ips can't evict one that this flow
	// has just seen again (which would discard its history from earlier windows).
	for _, ip := range ips {
		if e, ok := m[ip]; ok {
			e.windows.set(slot)
			e.lastSeen = max(e.lastSeen, start)
		}
	}
	for _, ip := range ips {
		if ip == "" {
			continue
		}
		if e, ok := m[ip]; ok {
			// Refreshed above, or a duplicate within ips.
			e.windows.set(slot)
			continue
		}
		if m == nil {
			m = make(map[string]*ipEntry, min(len(ips), MaxIPsPerFlow))
		}
		if len(m) >= MaxIPsPerFlow {
			oldestIP, oldest := "", int64(math.MaxInt64)
			for k, e := range m {
				// Break ties on the address so eviction is deterministic.
				if e.lastSeen < oldest || (e.lastSeen == oldest && k < oldestIP) {
					oldestIP, oldest = k, e.lastSeen
				}
			}
			if oldest > start || (oldest == start && ip < oldestIP) {
				continue
			}
			delete(m, oldestIP)
		}
		e := &ipEntry{lastSeen: start}
		e.windows.set(slot)
		m[ip] = e
	}
	return m
}

// ipsForWindows returns the sorted source and destination IPs seen in any of the given windows.
func (d *DiachronicFlow) ipsForWindows(windows []*Window) (src, dst []string) {
	d.ipsMu.RLock()
	defer d.ipsMu.RUnlock()
	if len(d.sourceIPs) == 0 && len(d.destIPs) == 0 {
		return nil, nil
	}
	var mask windowSet
	for _, w := range windows {
		mask.set(bitIndex(w.start, w.end))
	}
	return ipsMatching(d.sourceIPs, &mask), ipsMatching(d.destIPs, &mask)
}

func ipsMatching(m map[string]*ipEntry, mask *windowSet) []string {
	var ips []string
	for ip, e := range m {
		if e.windows.intersects(mask) {
			ips = append(ips, ip)
		}
	}
	slices.Sort(ips)
	return ips
}
