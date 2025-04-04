// Copyright (c) 2025 Tigera, Inc. All rights reserved.

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package old

import (
	"github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/goldmane/proto"
)

// AggregationBucket represents a bucket of aggregated flows across a time range.
type AggregationBucket struct {
	// Pushed indicates whether this bucket has been pushed to the emitter.
	Pushed bool

	Windows map[*DiachronicFlow]Window

	// Tracker for statistics within this bucket.
	stats *statisticsIndex
}

func (b *AggregationBucket) AddFlow(d *DiachronicFlow, window Window) *DiachronicFlow {
	if b.Pushed {
		logrus.WithField("flow", d.Key).Warn("Adding flow to already published bucket")
	}

	if d == nil {
		logrus.Fatal("BUG: Attempted to add nil flow to bucket")
	}

	d.windowCount++

	if existing, ok := b.Windows[d]; ok {
		existing.PacketsIn += window.PacketsIn
		existing.PacketsOut += window.PacketsOut
		existing.BytesIn += window.BytesIn
		existing.BytesOut += window.BytesOut
		existing.NumConnectionsStarted += window.NumConnectionsStarted
		existing.NumConnectionsCompleted += window.NumConnectionsCompleted
		existing.NumConnectionsLive += window.NumConnectionsLive
		existing.SourceLabels = intersection(existing.SourceLabels, window.SourceLabels)
		existing.DestLabels = intersection(existing.DestLabels, window.DestLabels)
	} else {
		b.Windows[d] = window
	}

	return d
}

func NewAggregationBucket() *AggregationBucket {
	return &AggregationBucket{
		Windows: make(map[*DiachronicFlow]Window),
		stats:   newStatisticsIndex(),
	}
}

func (b *AggregationBucket) Fields() logrus.Fields {
	return logrus.Fields{
		"flows": len(b.Windows),
	}
}

func (b *AggregationBucket) Reset() {
	b.Pushed = false
	b.stats = newStatisticsIndex()

	for d := range b.Windows {
		d.windowCount--
		if d.windowCount == 0 {
			if logrus.IsLevelEnabled(logrus.DebugLevel) {
				logrus.WithFields(d.Key.Fields()).Debug("Removing empty DiachronicFlow")
			}
			d.Delete()
			delete(b.Windows, d)
		}
	}

	b.Windows = make(map[*DiachronicFlow]Window)
}

func (b *AggregationBucket) QueryStatistics(q *proto.StatisticsRequest) map[StatisticsKey]*counts {
	return b.stats.QueryStatistics(q)
}
