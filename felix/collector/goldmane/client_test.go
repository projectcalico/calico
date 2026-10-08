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

	"github.com/projectcalico/calico/felix/collector/flowlog"
	"github.com/projectcalico/calico/felix/collector/types/endpoint"
	"github.com/projectcalico/calico/goldmane/proto"
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
