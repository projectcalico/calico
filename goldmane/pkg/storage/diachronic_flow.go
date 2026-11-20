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
// equally recent ones; see evictLeastRecent. So once m is full, an IP that arrives late, for a
// window older than every retained entry, is dropped rather than evicting newer data.
func recordIPSet(m map[string]*ipEntry, ips []string, slot int, start int64) map[string]*ipEntry {
	// fresh collects new IPs that arrive once m is full; after the loop, we evict to make room for
	// them. Updates rarely bring many, so fresh starts in a small fixed array and rarely allocates.
	var freshBuf [16]string
	fresh := freshBuf[:0]

	// Go through the IPs in this update, refreshing the ones we already track and adding new ones
	// while m has room. New IPs that don't fit wait in fresh until the loop ends.
	for _, ip := range ips {
		// Flows can carry empty addresses. There's nothing to record for them, so skip them.
		if ip == "" {
			continue
		}

		// Check whether we already track this IP. If we do, mark it as seen in this window and
		// update its lastSeen, keeping the history we have from earlier windows.
		if e, ok := m[ip]; ok {
			e.windows.set(slot)
			e.lastSeen = max(e.lastSeen, start)
			continue
		}

		// This IP is new. Check whether m has reached MaxIPsPerFlow.
		if len(m) >= MaxIPsPerFlow {
			// m is full. Queue the IP in fresh and evict only after the loop, so every tracked IP's
			// lastSeen is up to date when we rank them.
			fresh = append(fresh, ip)
			continue
		}

		// This IP is new and m has room, so we add it straight away.
		if m == nil {
			// This is the first IP this set has seen, so we create m first.
			m = make(map[string]*ipEntry, min(len(ips), MaxIPsPerFlow))
		}
		addIPEntry(m, ip, slot, start)
	}

	// Check whether any new IPs had to wait in fresh.
	if len(fresh) == 0 {
		// We don't have to evict any IP addresses here, since fresh is only populated when m is
		// full and new IPs arrive.
		return m
	}

	// An update can repeat an address, so we sort fresh and drop the duplicates.
	slices.Sort(fresh)
	fresh = slices.Compact(fresh)

	// We have new IPs to consider. Evict a number equal to the new IPs we have collected, and add
	// the new entries in their place, unless they rank below what we already track.
	for _, ip := range evictLeastRecent(m, fresh, start) {
		addIPEntry(m, ip, slot, start)
	}
	return m
}

// addIPEntry records a new IP in m. Since this is a new IP, the entry is marked only for the given
// window slot.
func addIPEntry(m map[string]*ipEntry, ip string, slot int, start int64) {
	e := &ipEntry{lastSeen: start}
	e.windows.set(slot)
	m[ip] = e
}

// evictionCandidate is an IP that could be evicted, with the start of the newest window it was
// seen in. The IP and that window start decide its rank; see compare.
type evictionCandidate struct {
	lastSeen int64
	ip       string
}

// compare ranks c against other for eviction. The IP seen least recently ranks lowest, and among
// IPs last seen in the same window, the lowest address ranks lowest.
func (c evictionCandidate) compare(other evictionCandidate) int {
	// If the two were last seen in different windows, the older one ranks lower. Otherwise they're
	// equally recent, and we fall back to comparing addresses.
	if c.lastSeen != other.lastSeen {
		return cmp.Compare(c.lastSeen, other.lastSeen)
	}
	return strings.Compare(c.ip, other.ip)
}

// evictLeastRecent makes room in m for fresh, a sorted set of distinct IPs absent from m and all
// seen at start. It ranks m's entries and fresh together by evictionCandidate.compare, drops as
// many of the lowest-ranked as it takes for the rest to fit in MaxIPsPerFlow, and returns the IPs from fresh that
// survived. It finds them in one pass instead of sorting every candidate, so evicting one IP costs
// a single scan of m.
func evictLeastRecent(m map[string]*ipEntry, fresh []string, start int64) []string {
	// Work out how many IPs, tracked or fresh, have to go to bring the set back to MaxIPsPerFlow.
	// If everything fits, we don't need to evict anything, and every fresh IP can be added.
	overflow := len(m) + len(fresh) - MaxIPsPerFlow
	if overflow <= 0 {
		return fresh
	}

	// Check whether this update brings more new IPs than the set can hold.
	if surplus := len(fresh) - MaxIPsPerFlow; surplus > 0 {
		// The fresh IPs share one lastSeen, so the lowest addresses rank lowest and would be dropped
		// anyway. Dropping them up front keeps the overflow within the shortlist's fixed array.
		fresh = fresh[surplus:]
		overflow -= surplus
	}

	// The shortlist holds the overflow lowest-ranked IPs, which are the ones we'll drop. Its
	// storage is a fixed-size array, so building it doesn't allocate memory.
	var buf [MaxIPsPerFlow]evictionCandidate
	shortlist := evictionShortlist{slots: buf[:overflow]}

	// Offer each tracked IP to the shortlist.
	for ip, e := range m {
		// Check whether this IP was seen after start.
		if e.lastSeen > start {
			// It ranks above every fresh IP, so it can never be among the lowest-ranked. Skip it.
			continue
		}
		shortlist.offer(evictionCandidate{lastSeen: e.lastSeen, ip: ip})
	}

	// Offer the fresh IPs too, lowest address first.
	for _, ip := range fresh {
		// The fresh IPs all share one lastSeen, so once one doesn't make the shortlist, no higher
		// address will either, and we can stop.
		if !shortlist.offer(evictionCandidate{lastSeen: start, ip: ip}) {
			break
		}
	}

	// At this point the shortlist holds exactly the IPs to drop. We evict the tracked ones from m,
	// and count the fresh ones, which were never added to m.
	droppedFresh := 0
	for _, candidate := range shortlist.members() {
		// Check whether we track this IP. If we do, evict it from m. If not, it's a fresh IP that
		// ranked too low to keep, so we just count it.
		if _, tracked := m[candidate.ip]; tracked {
			delete(m, candidate.ip)
		} else {
			droppedFresh++
		}
	}

	// The fresh IPs that ranked too low are the lowest addresses in fresh, so they sit at the
	// front of the sorted slice, and we keep everything after them.
	return fresh[droppedFresh:]
}

// evictionShortlist collects the len(slots) lowest-ranked candidates offered to it. It keeps them
// as a max-heap, a tree stored in slots where every member ranks at or above its children, so
// slots[0] is always the highest-ranked member: the one a newcomer must beat, and the one it
// replaces. It is hand-rolled because Go's container/heap stores each element as an interface
// value, which allocates memory.
type evictionShortlist struct {
	// slots is fixed-length storage for the tree, so the caller decides where its memory comes
	// from. Only the first size entries are members.
	slots []evictionCandidate
	size  int
}

// members returns the candidates currently on the shortlist, in tree order rather than sorted.
func (s *evictionShortlist) members() []evictionCandidate {
	return s.slots[:s.size]
}

// offer adds candidate if the shortlist has room, or if it ranks below the highest-ranked member,
// which it then replaces. It reports whether candidate was added.
func (s *evictionShortlist) offer(candidate evictionCandidate) bool {
	// Check whether the shortlist has a free slot.
	if s.size < len(s.slots) {
		// It isn't full yet, so the candidate gets on regardless. We put it at the end and move it
		// up the tree to its place.
		s.slots[s.size] = candidate
		s.size++
		s.siftUp(s.size - 1)
		return true
	}

	// The shortlist is full. If the candidate ranks at or above every member, it isn't among the
	// lowest-ranked, so we turn it away.
	if candidate.compare(s.slots[0]) >= 0 {
		return false
	}

	// The candidate ranks below the highest-ranked member, so it replaces that member at the top
	// of the tree, then moves down to its place.
	s.slots[0] = candidate
	s.siftDown(0)
	return true
}

// siftUp moves the member at i up the tree, swapping it with its parent until the parent ranks at
// or above it or it reaches the top.
func (s *evictionShortlist) siftUp(i int) {
	for i > 0 {
		// In the array layout, the parent of position i sits at (i-1)/2.
		parent := (i - 1) / 2

		// If the parent ranks at or above this member, the tree is in order and we're done.
		// Otherwise we swap them and keep climbing.
		if s.slots[parent].compare(s.slots[i]) >= 0 {
			return
		}
		s.slots[parent], s.slots[i] = s.slots[i], s.slots[parent]
		i = parent
	}
}

// siftDown moves the member at i down the tree, swapping it with its higher-ranked child until
// neither child ranks above it.
func (s *evictionShortlist) siftDown(i int) {
	for {
		// Find which of this member and its two children ranks highest. In the array layout, the
		// children of position i sit at 2i+1 and 2i+2.
		highest := i
		for _, child := range []int{2*i + 1, 2*i + 2} {
			// A child position past the end of the tree is empty. Otherwise the child becomes the
			// highest if it ranks above the best we've seen so far.
			if child < s.size && s.slots[child].compare(s.slots[highest]) > 0 {
				highest = child
			}
		}

		// If neither child ranks above this member, the tree is in order and we're done.
		// Otherwise we swap it with the higher child and keep sinking.
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
