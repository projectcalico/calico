// Copyright (c) 2026 Tigera, Inc. All rights reserved.

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

package storage_test

import (
	"fmt"
	"testing"

	"github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/goldmane/pkg/storage"
	"github.com/projectcalico/calico/goldmane/proto"
)

// BenchmarkDeferredFlowBuilder builds every flow in the newest bucket, as one stream does on rollover.
func BenchmarkDeferredFlowBuilder(b *testing.B) {
	logrus.SetLevel(logrus.WarnLevel)
	const numFlows = 10_000

	for _, windows := range []int{1, 20, 242} {
		flows := make([]*storage.DiachronicFlow, numFlows)
		for i := range flows {
			flows[i], _ = newBuilderTestFlow(windows)
		}
		start, end := int64((windows-1)*builderInterval), int64(windows*builderInterval)

		b.Run(fmt.Sprintf("history=%d", windows), func(b *testing.B) {
			res := &proto.FlowResult{Flow: &proto.Flow{}}
			b.ReportAllocs()
			for b.Loop() {
				for _, d := range flows {
					storage.NewDeferredFlowBuilder(d, start, end).BuildInto(nil, res)
				}
			}
			b.ReportMetric(float64(b.Elapsed().Nanoseconds())/float64(b.N*numFlows), "ns/flow")
		})
	}
}
