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
	"github.com/stretchr/testify/require"

	"github.com/projectcalico/calico/felix/collector/flowlog"
	"github.com/projectcalico/calico/felix/collector/types/endpoint"
	"github.com/projectcalico/calico/felix/collector/types/tuple"
	"github.com/projectcalico/calico/goldmane/pkg/types"
	"github.com/projectcalico/calico/goldmane/proto"
	"github.com/projectcalico/calico/lib/std/uniquelabels"
)

func TestConvertFlowlogToGoldmane(t *testing.T) {
	tests := []struct {
		name         string
		action       flowlog.Action
		reporter     flowlog.ReporterType
		wantErr      bool
		wantAction   proto.Action
		wantReporter proto.Reporter
	}{
		{name: "allow src", action: flowlog.ActionAllow, reporter: flowlog.ReporterSrc, wantAction: proto.Action_Allow, wantReporter: proto.Reporter_Src},
		{name: "deny dst", action: flowlog.ActionDeny, reporter: flowlog.ReporterDst, wantAction: proto.Action_Deny, wantReporter: proto.Reporter_Dst},
		{name: "no action", action: "", reporter: flowlog.ReporterDst, wantErr: true},
		{name: "no reporter", action: flowlog.ActionAllow, reporter: "", wantErr: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			fl := &flowlog.FlowLog{}
			fl.Action = tc.action
			fl.Reporter = tc.reporter
			fl.SrcMeta.Type = endpoint.Wep
			fl.DstMeta.Type = endpoint.Wep

			f, err := ConvertFlowlogToGoldmane(fl)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected an error, got flow %v", f)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got := f.Key.Action(); got != tc.wantAction {
				t.Errorf("action = %v, want %v", got, tc.wantAction)
			}
			if got := f.Key.Reporter(); got != tc.wantReporter {
				t.Errorf("reporter = %v, want %v", got, tc.wantReporter)
			}
		})
	}
}

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

	gf, err := ConvertFlowlogToGoldmane(fl)
	require.NoError(t, err)

	assert.Equal(t, []string{"10.0.0.1", "10.0.0.3"}, gf.SourceIps)
	assert.Equal(t, []string{"20.0.0.1"}, gf.DestIps)
}

// TestConvertGoldmaneToFlowlog_IPs verifies the reverse direction: the IP sets on the proto Flow
// are restored onto the flow log.
func TestConvertGoldmaneToFlowlog_IPs(t *testing.T) {
	fl := newConvertibleFlowLog()
	gf, err := ConvertFlowlogToGoldmane(fl)
	require.NoError(t, err)
	protoFlow := types.FlowToProto(gf)

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

	gf, err := ConvertFlowlogToGoldmane(fl)
	require.NoError(t, err)

	assert.Empty(t, gf.SourceIps)
	assert.Empty(t, gf.DestIps)
}
