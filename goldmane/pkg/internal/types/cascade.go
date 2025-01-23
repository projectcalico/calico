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
	"github.com/sirupsen/logrus"

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

func (w *Window) Within(startGt, startLt int64) bool {
	return w.start >= startGt && w.end <= startLt
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

func (c *DiachronicFlow) Rollover(limiter int64) {
	// We need to remove any Windows which are no longer within the time range we are interested in.
	// c.Windows is sorted oldest -> newest, so we can do this pretty easily by finding the oldest window
	// that is still within the time range, and then removing all windows before it.
	for i, w := range c.Windows {
		if w.end > limiter {
			// We have found a bucket that is still within the time range. Remove all buckets before it.
			logrus.WithFields(logrus.Fields{
				"limiter": limiter,
				"index":   i,
			}).Debug("Removing old windows prior to index i")
			c.Windows = c.Windows[i:]
			c.PacketsIn = c.PacketsIn[i:]
			c.PacketsOut = c.PacketsOut[i:]
			c.BytesIn = c.BytesIn[i:]
			c.BytesOut = c.BytesOut[i:]
			c.NumConnectionsStarted = c.NumConnectionsStarted[i:]
			c.NumConnectionsCompleted = c.NumConnectionsCompleted[i:]
			c.NumConnectionsLive = c.NumConnectionsLive[i:]
			c.SourceLabels = c.SourceLabels[i:]
			c.DestLabels = c.DestLabels[i:]
			return
		}
	}
	logrus.Debug("Rollover called with no windows to rollover")
}

func (c *DiachronicFlow) Empty() bool {
	return len(c.Windows) == 0
}

func (c *DiachronicFlow) AddFlow(flow *Flow, start, end int64) {
	logrus.WithField("flow", flow).Debug("Adding flow to DiachronicFlow")

	// Add this flow's statistics to the DiachronicFlow. If it falls within an already tracked Window,
	// add the statistics to that window. Otherwise, create a new window.
	for i, w := range c.Windows {
		if w.Contains(flow.StartTime) {
			logrus.WithFields(logrus.Fields{
				"flow":   flow,
				"window": w,
				"index":  i,
			}).Debug("Adding flow to existing window")
			c.PacketsIn[i] += flow.PacketsIn
			c.PacketsOut[i] += flow.PacketsOut
			c.BytesIn[i] += flow.BytesIn
			c.BytesOut[i] += flow.BytesOut
			c.NumConnectionsStarted[i] += flow.NumConnectionsStarted
			c.NumConnectionsCompleted[i] += flow.NumConnectionsCompleted
			c.NumConnectionsLive[i] += flow.NumConnectionsLive
			return
		}
	}

	// If we didn't find a window, create a new one.
	// TODO: We shouldn't just append here. We need to insert this window in a sorted manner
	// within the slice to ensure that Rollover works correctly. We can get out-of-order FlowUpdates,
	// which would in turn cause out-of-order Windows.
	logrus.WithFields(logrus.Fields{
		"flow":  flow,
		"start": start,
		"end":   end,
	}).Debug("Adding flow to new window")
	c.Windows = append(c.Windows, Window{start: start, end: end})
	c.PacketsIn = append(c.PacketsIn, flow.PacketsIn)
	c.PacketsOut = append(c.PacketsOut, flow.PacketsOut)
	c.BytesIn = append(c.BytesIn, flow.BytesIn)
	c.BytesOut = append(c.BytesOut, flow.BytesOut)
	c.NumConnectionsStarted = append(c.NumConnectionsStarted, flow.NumConnectionsStarted)
	c.NumConnectionsCompleted = append(c.NumConnectionsCompleted, flow.NumConnectionsCompleted)
	c.NumConnectionsLive = append(c.NumConnectionsLive, flow.NumConnectionsLive)
	c.SourceLabels = append(c.SourceLabels, flow.SourceLabels)
	c.DestLabels = append(c.DestLabels, flow.DestLabels)
}

func (c *DiachronicFlow) Aggregate(startGt, startLt int64) *Flow {
	if !c.Within(startGt, startLt) {
		return nil
	}

	// Create a new Flow object and populate it with aggregated statistics from the DiachronicFlow.
	// acoss the time window specified by start and end.
	f := &Flow{}
	f.Key = &c.Key

	// Iterate each Window and aggregate the statistic contributions across all windows that fall within the
	// specified time range.
	for i, w := range c.Windows {
		if (startGt == 0 || w.start >= startGt) &&
			(startLt == 0 || w.end <= startLt) {
			// Sum up summable stats.
			f.PacketsIn += c.PacketsIn[i]
			f.PacketsOut += c.PacketsOut[i]
			f.BytesIn += c.BytesIn[i]
			f.BytesOut += c.BytesOut[i]
			f.NumConnectionsStarted += c.NumConnectionsStarted[i]
			f.NumConnectionsCompleted += c.NumConnectionsCompleted[i]
			f.NumConnectionsLive += c.NumConnectionsLive[i]

			// Merge labels. We use the intersection.
			f.SourceLabels = intersection(f.SourceLabels, c.SourceLabels[i])
			f.DestLabels = intersection(f.DestLabels, c.DestLabels[i])

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

func (c *DiachronicFlow) Within(startGt, startLt int64) bool {
	if startGt == 0 && startLt == 0 {
		return true
	}

	// Go through each window and return true if any of them
	// fall within the start and end time.
	for _, w := range c.Windows {
		if w.start >= startGt && w.start <= startLt {
			return true
		}
	}
	logrus.WithFields(logrus.Fields{
		"DiachronicFlow": c,
		"startGt":        startGt,
		"startLt":        startLt,
	}).Debug("DiachronicFlow not within time range")
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
