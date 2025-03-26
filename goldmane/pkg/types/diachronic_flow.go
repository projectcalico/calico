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

	"github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/goldmane/proto"
	"github.com/projectcalico/calico/libcalico-go/lib/set"
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

	// The fields below are individual statistics fields, represented as slices of values. Each element in the slice
	// represents an aggregated statistic for a time window.
	SourceLabels            [][]string
	DestLabels              [][]string
	PacketsIn               []int64
	PacketsOut              []int64
	BytesIn                 []int64
	BytesOut                []int64
	NumConnectionsStarted   []int64
	NumConnectionsCompleted []int64
	NumConnectionsLive      []int64
}

type Window struct {
	start int64
	end   int64
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
			logrus.WithFields(logrus.Fields{
				"limiter": limiter,
				"index":   i,
				"endTime": w.end,
			}).Debug("Removing Window(s) before limiter from diachronic flow")

			// Remove the Window and all corresponding statistics.
			d.Windows = d.Windows[i+1:]
			d.PacketsIn = d.PacketsIn[i+1:]
			d.PacketsOut = d.PacketsOut[i+1:]
			d.BytesIn = d.BytesIn[i+1:]
			d.BytesOut = d.BytesOut[i+1:]
			d.NumConnectionsStarted = d.NumConnectionsStarted[i+1:]
			d.NumConnectionsCompleted = d.NumConnectionsCompleted[i+1:]
			d.NumConnectionsLive = d.NumConnectionsLive[i+1:]
			d.SourceLabels = d.SourceLabels[i+1:]
			d.DestLabels = d.DestLabels[i+1:]
			return
		}
	}
	logrus.Debug("Rollover called with no windows to rollover")
}

func (d *DiachronicFlow) Empty() bool {
	return len(d.Windows) == 0
}

func (d *DiachronicFlow) AddFlow(flow *Flow, start, end int64) {
	logrus.WithFields(logrus.Fields{
		"flow":   flow,
		"window": Window{start: start, end: end},
	}).Debug("Adding flow data to diachronic flow")

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
	logrus.WithFields(logrus.Fields{
		"flow":   flow,
		"window": d.Windows[index],
		"index":  index,
	}).Debug("Adding flow to existing window")

	d.PacketsIn[index] += flow.PacketsIn
	d.PacketsOut[index] += flow.PacketsOut
	d.BytesIn[index] += flow.BytesIn
	d.BytesOut[index] += flow.BytesOut
	d.NumConnectionsStarted[index] += flow.NumConnectionsStarted
	d.NumConnectionsCompleted[index] += flow.NumConnectionsCompleted
	d.NumConnectionsLive[index] += flow.NumConnectionsLive
	d.SourceLabels[index] = intersection(d.SourceLabels[index], flow.SourceLabels)
	d.DestLabels[index] = intersection(d.DestLabels[index], flow.DestLabels)
}

func (d *DiachronicFlow) insertWindow(flow *Flow, index int, start, end int64) {
	w := Window{start: start, end: end}
	d.Windows = append(d.Windows[:index], append([]Window{w}, d.Windows[index:]...)...)

	logrus.WithFields(logrus.Fields{
		"flow":   flow,
		"window": w,
		"index":  index,
	}).Debug("Inserting new window for flow")

	d.PacketsIn = append(d.PacketsIn[:index], append([]int64{flow.PacketsIn}, d.PacketsIn[index:]...)...)
	d.PacketsOut = append(d.PacketsOut[:index], append([]int64{flow.PacketsOut}, d.PacketsOut[index:]...)...)
	d.BytesIn = append(d.BytesIn[:index], append([]int64{flow.BytesIn}, d.BytesIn[index:]...)...)
	d.BytesOut = append(d.BytesOut[:index], append([]int64{flow.BytesOut}, d.BytesOut[index:]...)...)
	d.NumConnectionsStarted = append(d.NumConnectionsStarted[:index], append([]int64{flow.NumConnectionsStarted}, d.NumConnectionsStarted[index:]...)...)
	d.NumConnectionsCompleted = append(d.NumConnectionsCompleted[:index], append([]int64{flow.NumConnectionsCompleted}, d.NumConnectionsCompleted[index:]...)...)
	d.NumConnectionsLive = append(d.NumConnectionsLive[:index], append([]int64{flow.NumConnectionsLive}, d.NumConnectionsLive[index:]...)...)
	d.SourceLabels = append(d.SourceLabels[:index], append([][]string{flow.SourceLabels}, d.SourceLabels[index:]...)...)
	d.DestLabels = append(d.DestLabels[:index], append([][]string{flow.DestLabels}, d.DestLabels[index:]...)...)
}

func (d *DiachronicFlow) appendWindow(flow *Flow, start, end int64) {
	w := Window{start: start, end: end}
	d.Windows = append(d.Windows, w)

	logrus.WithFields(logrus.Fields{
		"flow":   flow,
		"window": w,
	}).Debug("Adding flow to new window")

	d.PacketsIn = append(d.PacketsIn, flow.PacketsIn)
	d.PacketsOut = append(d.PacketsOut, flow.PacketsOut)
	d.BytesIn = append(d.BytesIn, flow.BytesIn)
	d.BytesOut = append(d.BytesOut, flow.BytesOut)
	d.NumConnectionsStarted = append(d.NumConnectionsStarted, flow.NumConnectionsStarted)
	d.NumConnectionsCompleted = append(d.NumConnectionsCompleted, flow.NumConnectionsCompleted)
	d.NumConnectionsLive = append(d.NumConnectionsLive, flow.NumConnectionsLive)
	d.SourceLabels = append(d.SourceLabels, flow.SourceLabels)
	d.DestLabels = append(d.DestLabels, flow.DestLabels)
}

func (d *DiachronicFlow) Aggregate(startGte, startLt int64) *Flow {
	if !d.Within(startGte, startLt) {
		return nil
	}

	// Create a new Flow object and populate it with aggregated statistics from the DiachronicFlow.
	// acoss the time window specified by start and end.
	f := &Flow{}
	f.Key = &d.Key

	// Iterate each Window and aggregate the statistic contributions across all windows that fall within the
	// specified time range.
	for i, w := range d.Windows {
		if (startGte == 0 || w.start >= startGte) &&
			(startLt == 0 || w.end <= startLt) {
			logrus.WithFields(logrus.Fields{
				"window":  w,
				"startGt": startGte,
				"startLt": startLt,
			}).Debug("Aggregating flow data from diachronic flow window")

			// Sum up summable stats.
			f.PacketsIn += d.PacketsIn[i]
			f.PacketsOut += d.PacketsOut[i]
			f.BytesIn += d.BytesIn[i]
			f.BytesOut += d.BytesOut[i]
			f.NumConnectionsStarted += d.NumConnectionsStarted[i]
			f.NumConnectionsCompleted += d.NumConnectionsCompleted[i]
			f.NumConnectionsLive += d.NumConnectionsLive[i]

			// Merge labels. We use the intersection of the labels across all windows.
			if f.SourceLabels != nil {
				f.SourceLabels = intersection(f.SourceLabels, d.SourceLabels[i])
			} else {
				f.SourceLabels = slices.Clone(d.SourceLabels[i])
			}
			if f.DestLabels != nil {
				f.DestLabels = intersection(f.DestLabels, d.DestLabels[i])
			} else {
				f.DestLabels = slices.Clone(d.DestLabels[i])
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

	logrus.WithFields(logrus.Fields{
		"DiachronicFlow": d,
		"startGte":       startGte,
		"startLt":        startLt,
	}).Debug("DiachronicFlow does not have data for time range")
	return false
}

// intersection returns the intersection of two slices of strings. i.e., all the values that
// exist in both input slices.
func intersection(a, b []string) []string {
	labelsA := set.New[string]()
	labelsB := set.New[string]()
	intersection := set.New[string]()
	for _, v := range a {
		labelsA.Add(v)
	}
	for _, v := range b {
		labelsB.Add(v)
	}
	labelsA.Iter(func(l string) error {
		if labelsB.Contains(l) {
			intersection.Add(l)
		}
		return nil
	})
	return intersection.Slice()
}
