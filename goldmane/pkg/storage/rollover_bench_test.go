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

package storage

import (
	"fmt"
	"testing"
	"unique"

	"github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/goldmane/pkg/types"
	"github.com/projectcalico/calico/goldmane/proto"
)

func buildDiachronicFlow(numWindows int) *DiachronicFlow {
	k := types.NewFlowKey(
		&types.FlowKeySource{SourceName: "src", SourceNamespace: "default"},
		&types.FlowKeyDestination{DestName: "dst", DestNamespace: "default"},
		&types.FlowKeyMeta{Proto: "TCP", Reporter: proto.Reporter_Src, Action: proto.Action_Allow},
		&proto.PolicyTrace{},
	)
	df := NewDiachronicFlow(k, 1)
	f := &types.Flow{
		Key:          k,
		PacketsIn:    100,
		SourceLabels: unique.Make("app=test"),
		DestLabels:   unique.Make("app=test"),
	}
	for i := range numWindows {
		df.AddFlow(f, int64(i*15), int64((i+1)*15))
	}
	return df
}

func BenchmarkRollover(b *testing.B) {
	logrus.SetLevel(logrus.WarnLevel)

	for _, numWindows := range []int{50, 242} {
		limiter := int64(15)
		template := buildDiachronicFlow(numWindows)
		origWindows := template.Windows

		b.Run(fmt.Sprintf("%d_windows", numWindows), func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				// Rollover only reslices, so restoring the slice header is sufficient.
				template.Windows = origWindows
				template.Rollover(limiter)
			}
		})
	}
}
