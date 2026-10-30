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

	// visited holds the BucketRing walk that last yielded this flow. Only the main loop touches it.
	visited uint64

	// mu guards windows and the IP sets, which streams read off the aggregator goroutine.
	mu sync.Mutex

	// windows holds the flow's statistics for each time window, sorted oldest to newest.
	windows []Window

	// sourceIPs and destIPs track the distinct source / destination IPs observed for this FlowKey,
	// each with a bitmap of the windows it was seen in.
	sourceIPs map[string]*ipEntry
	destIPs   map[string]*ipEntry
}

// MaxIPsPerFlow caps the source (and destination) IP set of each DiachronicFlow. When full, the
// least-recently-seen IP is evicted from all of its windows, so the sets are best-effort.
const MaxIPsPerFlow = 100

// windowSlots is the number of per-window bits tracked for each retained IP. A window's slot is
// (start/interval) % windowSlots, so slots only stay unique while the history is shorter than
// windowSlots; NewBucketRing enforces this.
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

func (w *Window) inRange(startGte, startLt int64) bool {
	return (startGte == 0 || w.start >= startGte) && (startLt == 0 || w.end <= startLt)
}

func NewDiachronicFlow(k *types.FlowKey, id int64) *DiachronicFlow {
	return &DiachronicFlow{
		ID:  id,
		Key: *k,
	}
}

// Rollover drops windows that end at or before limiter, and reports whether none remain.
func (d *DiachronicFlow) Rollover(limiter int64) bool {
	d.mu.Lock()
	defer d.mu.Unlock()

	// Windows are sorted oldest -> newest. Find the first window that is still valid and
	// discard everything before it. Iterating forward finds the cut point on the first
	// check in the common case (one expired window per rollover).
	for i, w := range d.windows {
		if w.end > limiter {
			if i > 0 {
				if logrus.IsLevelEnabled(logrus.DebugLevel) {
					logrus.WithFields(logrus.Fields{
						"limiter":  limiter,
						"numStale": i,
					}).Debug("Removing stale window(s) from diachronic flow")
				}
				d.expireWindows(d.windows[:i])
				d.windows = d.windows[i:]
			}
			return false
		}
	}

	// All windows are expired.
	if len(d.windows) > 0 {
		d.expireWindows(d.windows)
		d.windows = d.windows[:0]
	}
	return true
}

// expireWindows clears the bitmap slot of each expiring window from every tracked IP, and drops any
// IP that is no longer present in any live window. Callers must hold d.mu.
func (d *DiachronicFlow) expireWindows(expired []Window) {
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

func (d *DiachronicFlow) AddFlow(flow *types.Flow, start, end int64) {
	d.mu.Lock()
	defer d.mu.Unlock()

	if logrus.IsLevelEnabled(logrus.DebugLevel) {
		logrus.WithFields(d.Key.Fields()).WithFields(logrus.Fields{
			"flow":   flow,
			"window": Window{start: start, end: end},
		}).Debug("Adding flow data to diachronic flow")
	}

	// IPs are tracked per DiachronicFlow rather than per Window; see sourceIPs.
	d.recordIPs(flow, start, end)

	if len(d.windows) == 0 {
		// This is the first Window, so create it.
		d.appendWindow(flow, start, end)
		return
	}

	// Find the Window that matches the flow's start time, if it exists. If it doesn't exist, create a new Window.
	// Windows are ordered by start time, so we can use binary search to find the correct window to add the flow to.
	index := sort.Search(len(d.windows), func(i int) bool {
		return d.windows[i].start >= start
	})
	if index == len(d.windows) {
		// This flow is for a new window that is after all existing windows.
		d.appendWindow(flow, start, end)
		return
	} else if d.windows[index].start != start {
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
			"window": d.windows[index],
			"index":  index,
		}).Debug("Adding flow to existing window")
	}

	d.windows[index].PacketsIn += flow.PacketsIn
	d.windows[index].PacketsOut += flow.PacketsOut
	d.windows[index].BytesIn += flow.BytesIn
	d.windows[index].BytesOut += flow.BytesOut
	d.windows[index].NumConnectionsStarted += flow.NumConnectionsStarted
	d.windows[index].NumConnectionsCompleted += flow.NumConnectionsCompleted
	d.windows[index].NumConnectionsLive += flow.NumConnectionsLive
	d.windows[index].SourceLabels = intersection(d.windows[index].SourceLabels, flow.SourceLabels)
	d.windows[index].DestLabels = intersection(d.windows[index].DestLabels, flow.DestLabels)
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
	d.windows = append(d.windows[:index], append([]Window{w}, d.windows[index:]...)...)

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
	d.windows = append(d.windows, w)

	if logrus.IsLevelEnabled(logrus.DebugLevel) {
		logrus.WithFields(d.Key.Fields()).WithFields(logrus.Fields{
			"flow":   flow,
			"window": w,
		}).Debug("Adding flow to new window")
	}
}

// Aggregate aggregates the statistics from the DiachronicFlow into a new Flow object over the specified time range.
func (d *DiachronicFlow) Aggregate(startGte, startLt int64) *types.Flow {
	d.mu.Lock()
	defer d.mu.Unlock()

	ws := d.windowsStarting(startGte, startLt)
	if len(ws) == 0 {
		return nil
	}
	f := newAggregateFlow(d)
	var mask windowSet
	for i := range ws {
		if w := &ws[i]; w.inRange(startGte, startLt) {
			d.aggregateWindow(f, w)
			mask.set(bitIndex(w.start, w.end))
		}
	}
	f.SourceIps, f.DestIps = d.ipsMatching(&mask)
	return f
}

// SortStartTime returns the StartTime that Aggregate would give the flow, without building it,
// and whether the flow is Within the range at all.
func (d *DiachronicFlow) SortStartTime(startGte, startLt int64) (int64, bool) {
	d.mu.Lock()
	defer d.mu.Unlock()

	ws := d.windowsStarting(startGte, startLt)
	if len(ws) == 0 {
		return 0, false
	}

	// Ends rise with starts, so if the first window ends past the range, every window does.
	if ws[0].inRange(startGte, startLt) {
		return ws[0].start, true
	}
	return 0, true
}

// windowsStarting returns the windows that start in [startGte, startLt), a zero bound being
// open. Every window that inRange accepts is among them. Callers must hold mu.
func (d *DiachronicFlow) windowsStarting(startGte, startLt int64) []Window {
	lo, hi := 0, len(d.windows)
	if startGte != 0 {
		lo = sort.Search(hi, func(i int) bool { return d.windows[i].start >= startGte })
	}
	if startLt != 0 {
		hi = lo + sort.Search(hi-lo, func(i int) bool { return d.windows[lo+i].start >= startLt })
	}
	return d.windows[lo:hi]
}

// bucketWindow returns a copy of the window for the given bucket. A bucket maps to exactly one
// window, because BucketRing.AddFlow passes the bucket's own start and end.
func (d *DiachronicFlow) bucketWindow(startGte, startLt int64) (Window, bool) {
	d.mu.Lock()
	defer d.mu.Unlock()

	for i := range d.windows {
		if d.windows[i].inRange(startGte, startLt) {
			return d.windows[i], true
		}
	}
	return Window{}, false
}

var emptyLabels = unique.Make("")

func newAggregateFlow(d *DiachronicFlow) *types.Flow {
	return &types.Flow{
		Key:          &d.Key,
		SourceLabels: emptyLabels,
		DestLabels:   emptyLabels,
	}
}

// aggregateWindow adds the window's statistics to f, using the intersection of labels across windows.
func (d *DiachronicFlow) aggregateWindow(f *types.Flow, w *Window) {
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
	d.mu.Lock()
	defer d.mu.Unlock()

	if len(d.windowsStarting(startGte, startLt)) > 0 {
		return true
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
// Callers must hold d.mu.
func (d *DiachronicFlow) recordIPs(flow *types.Flow, start, end int64) {
	if len(flow.SourceIps) == 0 && len(flow.DestIps) == 0 {
		return
	}
	slot := bitIndex(start, end)
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

// windowIPs returns the sorted source and destination IPs seen in the given window.
func (d *DiachronicFlow) windowIPs(w *Window) (src, dst []string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	var mask windowSet
	mask.set(bitIndex(w.start, w.end))
	return d.ipsMatching(&mask)
}

// ipsMatching returns the sorted source and destination IPs seen in any window in mask. Callers
// must hold d.mu.
func (d *DiachronicFlow) ipsMatching(mask *windowSet) (src, dst []string) {
	if len(d.sourceIPs) == 0 && len(d.destIPs) == 0 {
		return nil, nil
	}
	return ipsMatching(d.sourceIPs, mask), ipsMatching(d.destIPs, mask)
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
