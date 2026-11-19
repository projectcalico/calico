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
	"cmp"
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
	if !d.Within(startGte, startLt) {
		return nil
	}

	d.mu.Lock()
	defer d.mu.Unlock()

	f := newAggregateFlow(d)
	var mask windowSet
	for i := range d.windows {
		if w := &d.windows[i]; w.inRange(startGte, startLt) {
			d.aggregateWindow(f, w)
			mask.set(bitIndex(w.start, w.end))
		}
	}
	f.SourceIps, f.DestIps = d.ipsMatching(&mask)
	return f
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

	// Go through each window and return true if any of them
	// fall within the start and end time.
	for _, w := range d.windows {
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
// Callers must hold d.mu.
func (d *DiachronicFlow) recordIPs(flow *types.Flow, start, end int64) {
	if len(flow.SourceIps) == 0 && len(flow.DestIps) == 0 {
		return
	}
	slot := bitIndex(start, end)
	d.sourceIPs = recordIPSet(d.sourceIPs, flow.SourceIps, slot, start)
	d.destIPs = recordIPSet(d.destIPs, flow.DestIps, slot, start)
}

// recordIPSet adds ips to m against the given window slot, lazily allocating m. When m would grow
// past MaxIPsPerFlow, it keeps the most recently seen IPs, dropping the lowest address among
// equally recent ones; see evictLeastRecent. So an IP arriving late, for a window older than every
// retained entry, is dropped rather than evicting newer data.
func recordIPSet(m map[string]*ipEntry, ips []string, slot int, start int64) map[string]*ipEntry {
	// Updates rarely queue many new IPs, so fresh starts on the stack.
	var freshBuf [16]string
	fresh := freshBuf[:0]

	// New IPs go straight in while there is room. Once m is full they wait in fresh, so every
	// tracked IP is refreshed, keeping its history, before anything is evicted.
	for _, ip := range ips {
		if ip == "" {
			continue
		}
		if e, ok := m[ip]; ok {
			e.windows.set(slot)
			e.lastSeen = max(e.lastSeen, start)
			continue
		}
		if len(m) >= MaxIPsPerFlow {
			fresh = append(fresh, ip)
			continue
		}
		if m == nil {
			m = make(map[string]*ipEntry, min(len(ips), MaxIPsPerFlow))
		}
		addIPEntry(m, ip, slot, start)
	}
	if len(fresh) == 0 {
		return m
	}
	slices.Sort(fresh)
	for _, ip := range evictLeastRecent(m, slices.Compact(fresh), start) {
		addIPEntry(m, ip, slot, start)
	}
	return m
}

// addIPEntry records a new IP in m as seen only in the given window slot.
func addIPEntry(m map[string]*ipEntry, ip string, slot int, start int64) {
	e := &ipEntry{lastSeen: start}
	e.windows.set(slot)
	m[ip] = e
}

// ipRecency is an IP and the start of the newest window it was seen in, ranked for eviction.
type ipRecency struct {
	lastSeen int64
	ip       string
}

// compare orders the least recently seen first, then the lowest address.
func (a ipRecency) compare(b ipRecency) int {
	if a.lastSeen != b.lastSeen {
		return cmp.Compare(a.lastSeen, b.lastSeen)
	}
	return strings.Compare(a.ip, b.ip)
}

// evictLeastRecent makes room in m for fresh, a sorted set of distinct IPs absent from m and all
// seen at start. It ranks m's entries and fresh together by ipRecency.compare, drops the overflow
// lowest-ranked so the rest fit in MaxIPsPerFlow, and returns the IPs from fresh that survived.
// It finds them in one pass instead of sorting every candidate, so evicting one IP costs a single
// scan of m.
func evictLeastRecent(m map[string]*ipEntry, fresh []string, start int64) []string {
	// overflow is how many IPs, tracked or fresh, have to go.
	overflow := len(m) + len(fresh) - MaxIPsPerFlow
	if overflow <= 0 {
		return fresh
	}

	// The shortlist holds the overflow IPs to drop. It fits on the stack unless a single
	// update overflows by more than MaxIPsPerFlow.
	var buf [MaxIPsPerFlow]ipRecency
	slots := buf[:min(overflow, MaxIPsPerFlow)]
	if overflow > MaxIPsPerFlow {
		slots = make([]ipRecency, overflow)
	}
	shortlist := evictionShortlist{slots: slots}
	for ip, e := range m {
		// Entries seen after start outrank every fresh IP, so they can never be evicted here.
		if e.lastSeen <= start {
			shortlist.offer(ipRecency{lastSeen: e.lastSeen, ip: ip})
		}
	}
	for _, ip := range fresh {
		// fresh is sorted and shares one lastSeen, so once an IP misses the shortlist, every
		// later (higher) address would miss it too.
		if !shortlist.offer(ipRecency{lastSeen: start, ip: ip}) {
			break
		}
	}

	// Shortlisted fresh IPs are the lowest addresses in fresh, so they form a prefix of it and
	// the survivors are everything after that prefix.
	droppedFresh := 0
	for _, c := range shortlist.members() {
		if _, tracked := m[c.ip]; tracked {
			delete(m, c.ip)
		} else {
			droppedFresh++
		}
	}
	return fresh[droppedFresh:]
}

// evictionShortlist collects the len(slots) lowest-ranked IPs offered to it, by
// ipRecency.compare. Its members form a max-heap, so slots[0] always holds the highest-ranked
// member: the one each newcomer must beat, and the one it displaces. It is hand-rolled because
// container/heap boxes every element in an interface, which allocates.
type evictionShortlist struct {
	// slots is fixed-length storage for the heap, so the caller can back it with a stack array.
	// Only the first size entries are members.
	slots []ipRecency
	size  int
}

// members returns the IPs currently on the shortlist, in heap order.
func (s *evictionShortlist) members() []ipRecency {
	return s.slots[:s.size]
}

// offer adds c if the shortlist has room, or if c ranks below the highest-ranked member, which c
// then displaces. It reports whether c was added.
func (s *evictionShortlist) offer(c ipRecency) bool {
	if s.size < len(s.slots) {
		s.slots[s.size] = c
		s.size++
		s.siftUp(s.size - 1)
		return true
	}
	if c.compare(s.slots[0]) >= 0 {
		return false
	}
	s.slots[0] = c
	s.siftDown(0)
	return true
}

// siftUp moves the member at i toward the root until its parent ranks at or above it.
func (s *evictionShortlist) siftUp(i int) {
	for i > 0 {
		parent := (i - 1) / 2
		if s.slots[parent].compare(s.slots[i]) >= 0 {
			return
		}
		s.slots[parent], s.slots[i] = s.slots[i], s.slots[parent]
		i = parent
	}
}

// siftDown moves the member at i away from the root until neither child ranks above it.
func (s *evictionShortlist) siftDown(i int) {
	for {
		highest := i
		for _, child := range []int{2*i + 1, 2*i + 2} {
			if child < s.size && s.slots[child].compare(s.slots[highest]) > 0 {
				highest = child
			}
		}
		if highest == i {
			return
		}
		s.slots[i], s.slots[highest] = s.slots[highest], s.slots[i]
		i = highest
	}
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
