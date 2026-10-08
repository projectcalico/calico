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

	// policyRules is derived from Key at construction and never changes, so buckets can add
	// statistics without decoding the policy trace on every flow.
	policyRules []policyRule

	// mu guards windows, which streams read off the aggregator goroutine.
	mu sync.Mutex

	// windows holds the flow's statistics for each time window, sorted oldest to newest.
	windows []Window
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
		ID:          id,
		Key:         *k,
		policyRules: toPolicyRules(k),
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
				d.windows = d.windows[i:]
			}
			return false
		}
	}

	// All windows are expired.
	if len(d.windows) > 0 {
		d.windows = d.windows[:0]
	}
	return true
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
	for i := range d.windows {
		if w := &d.windows[i]; w.inRange(startGte, startLt) {
			d.aggregateWindow(f, w)
		}
	}
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
