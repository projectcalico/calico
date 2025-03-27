// Copyright (c) 2025 Tigera, Inc. All rights reserved.

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

package types

import (
	"slices"
	"sort"
	"strings"
	"unique"

	"github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/goldmane/proto"
)

// DiachronicFlow is a representation of a Flow over time. Each DiachronicFlow corresponds to a single FlowKey,
// but with statistics fields that are bucketed by time, allowing for easy aggregation of statistics
// across time windows.
type DiachronicFlow struct {
	ID  int64
	Key FlowKey

	// Windows is a slice of time windows that the DiachronicFlow has statistics for. Each element in the slice
	// represents a time window, and the statistics for that window are stored in the corresponding index
	// in the other fields.
	Windows []Window
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

var nextID int64

func NewDiachronicFlow(k *FlowKey) *DiachronicFlow {
	nextID++
	return &DiachronicFlow{
		ID:  nextID,
		Key: *k,
	}
}

func (d *DiachronicFlow) Rollover(limiter int64) {
	// We need to remove any Windows which are no longer within the time range we are interested in.
	// c.Windows is sorted oldest -> newest, so we can do this pretty easily by iterating in order.
	// We can stop iterating when we find a Window that is still valid.
	// Note: Since we Rollover() ever aggregation period, we should never need to remove more than one Window at a time.
	for i := len(d.Windows) - 1; i >= 0; i-- {
		w := d.Windows[i]
		if w.end <= limiter {
			if logrus.IsLevelEnabled(logrus.DebugLevel) {
				logrus.WithFields(logrus.Fields{
					"limiter": limiter,
					"index":   i,
					"endTime": w.end,
				}).Debug("Removing Window(s) before limiter from diachronic flow")
			}

			// Remove the Window and all corresponding statistics.
			d.Windows = d.Windows[i+1:]
			return
		}
	}
	logrus.Debug("Rollover called with no windows to rollover")
}

func (d *DiachronicFlow) Empty() bool {
	return len(d.Windows) == 0
}

func (d *DiachronicFlow) AddFlow(flow *Flow, start, end int64) {
	if logrus.IsLevelEnabled(logrus.DebugLevel) {
		logrus.WithFields(d.Key.Fields()).WithFields(logrus.Fields{
			"flow":   flow,
			"window": Window{start: start, end: end},
		}).Debug("Adding flow data to diachronic flow")
	}

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

func (d *DiachronicFlow) addToWindow(flow *Flow, index int) {
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

func (d *DiachronicFlow) insertWindow(flow *Flow, index int, start, end int64) {
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

func (d *DiachronicFlow) appendWindow(flow *Flow, start, end int64) {
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

func (d *DiachronicFlow) Aggregate(startGte, startLt int64) *Flow {
	if !d.Within(startGte, startLt) {
		return nil
	}

	// Create a new Flow object and populate it with aggregated statistics from the DiachronicFlow.
	// acoss the time window specified by start and end.
	f := &Flow{
		SourceLabels: unique.Make(""),
		DestLabels:   unique.Make(""),
	}
	f.Key = &d.Key

	// Iterate each Window and aggregate the statistic contributions across all windows that fall within the
	// specified time range.
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
	return Matches(filter, &d.Key)
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

// intersection returns the intersection of two slices of strings. i.e., all the values that
// exist in both input slices.
func intersection(a unique.Handle[string], b unique.Handle[string]) unique.Handle[string] {
	common := make([]string, 0)
	av := strings.Split(a.Value(), ",")
	bv := strings.Split(b.Value(), ",")
	for _, v := range av {
		if slices.Contains(bv, v) {
			common = append(common, v)
		}
	}
	return unique.Make(strings.Join(common, ","))
}
