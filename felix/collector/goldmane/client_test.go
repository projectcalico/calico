// Copyright (c) 2026 Tigera, Inc. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package goldmane

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/projectcalico/calico/felix/collector/flowlog"
	"github.com/projectcalico/calico/felix/collector/types/endpoint"
	"github.com/projectcalico/calico/felix/collector/types/tuple"
	"github.com/projectcalico/calico/goldmane/pkg/types"
	"github.com/projectcalico/calico/lib/std/uniquelabels"
)

func newConvertibleFlowLog() *flowlog.FlowLog {
	return &flowlog.FlowLog{
		StartTime: time.Unix(1234567890, 0),
		EndTime:   time.Unix(1234567890, 0),
		FlowMeta: flowlog.FlowMeta{
			// The aggregated tuple has zeroed IPs (FlowPrefixName aggregation); the IP sets are
			// carried separately on SourceIPs / DestIPs.
			Tuple: tuple.Tuple{Proto: 6, L4Dst: 80},
			SrcMeta: endpoint.Metadata{
				AggregatedName: "web-frontend",
				Namespace:      "production",
				Type:           endpoint.Wep,
			},
			DstMeta: endpoint.Metadata{
				AggregatedName: "api-backend",
				Namespace:      "production",
				Type:           endpoint.Wep,
			},
			Action:   flowlog.ActionAllow,
			Reporter: flowlog.ReporterSrc,
		},
		FlowLabels: flowlog.FlowLabels{
			SrcLabels: uniquelabels.Empty,
			DstLabels: uniquelabels.Empty,
		},
		SourceIPs: []string{"10.0.0.1", "10.0.0.3"},
		DestIPs:   []string{"20.0.0.1"},
	}
}

// TestConvertFlowlogToGoldmane_IPs verifies that the source / destination IP sets on the flow log
// are carried onto the Goldmane Flow (and not into the FlowKey).
func TestConvertFlowlogToGoldmane_IPs(t *testing.T) {
	fl := newConvertibleFlowLog()

	gf := ConvertFlowlogToGoldmane(fl)

	assert.Equal(t, []string{"10.0.0.1", "10.0.0.3"}, gf.SourceIps)
	assert.Equal(t, []string{"20.0.0.1"}, gf.DestIps)
}

// TestConvertGoldmaneToFlowlog_IPs verifies the reverse direction: the IP sets on the proto Flow
// are restored onto the flow log.
func TestConvertGoldmaneToFlowlog_IPs(t *testing.T) {
	fl := newConvertibleFlowLog()
	protoFlow := types.FlowToProto(ConvertFlowlogToGoldmane(fl))

	out := ConvertGoldmaneToFlowlog(protoFlow)

	assert.Equal(t, []string{"10.0.0.1", "10.0.0.3"}, out.SourceIPs)
	assert.Equal(t, []string{"20.0.0.1"}, out.DestIPs)
}

// TestConvertFlowlogToGoldmane_NoIPs verifies that a flow log without IP sets converts cleanly
// (backward compatibility with flows that carry no IP information).
func TestConvertFlowlogToGoldmane_NoIPs(t *testing.T) {
	fl := newConvertibleFlowLog()
	fl.SourceIPs = nil
	fl.DestIPs = nil

	gf := ConvertFlowlogToGoldmane(fl)

	assert.Empty(t, gf.SourceIps)
	assert.Empty(t, gf.DestIps)
}
