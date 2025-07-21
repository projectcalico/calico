// Copyright (c) 2025 Tigera, Inc. All rights reserved.
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
	"github.com/projectcalico/calico/felix/collector/utils"
	"github.com/projectcalico/calico/lib/std/uniquelabels"
)

func TestConvertFlowlogToGoldmane_WithSourceIP(t *testing.T) {
	// Create a test flow log with source IP
	sourceIP := utils.IpStrTo16Byte("10.0.0.1")
	destIP := utils.IpStrTo16Byte("10.0.0.2")
	
	fl := &flowlog.FlowLog{
		StartTime: time.Unix(1234567890, 0),
		FlowMeta: flowlog.FlowMeta{
			Tuple: tuple.Tuple{
				Src:   sourceIP,
				Dst:   destIP,
				Proto: 6, // TCP
				L4Src: 12345,
				L4Dst: 80,
			},
			SrcMeta: endpoint.Metadata{
				AggregatedName: "pod1",
				Namespace:      "default",
				Type:           endpoint.Wep,
			},
			DstMeta: endpoint.Metadata{
				AggregatedName: "pod2",
				Namespace:      "default",
				Type:           endpoint.Wep,
			},
			Action:   flowlog.ActionAllow,
			Reporter: flowlog.ReporterSrc,
		},
		FlowLabels: flowlog.FlowLabels{
			SrcLabels: uniquelabels.Empty,
			DstLabels: uniquelabels.Empty,
		},
	}

	// Convert to Goldmane flow
	gf := ConvertFlowlogToGoldmane(fl)

	// Verify the source IP and port are set correctly
	assert.Equal(t, "10.0.0.1", gf.Key.SourceIP())
	assert.Equal(t, int64(12345), gf.Key.SourcePort())
	
	// Verify other fields are still set correctly
	assert.Equal(t, "pod1", gf.Key.SourceName())
	assert.Equal(t, "default", gf.Key.SourceNamespace())
	assert.Equal(t, int64(80), gf.Key.DestPort())
}

func TestConvertGoldmaneToFlowlog_WithSourceIP(t *testing.T) {
	// Test the reverse conversion
	gl := ConvertFlowlogToGoldmane(&flowlog.FlowLog{
		StartTime: time.Unix(1234567890, 0),
		FlowMeta: flowlog.FlowMeta{
			Tuple: tuple.Tuple{
				Src:   utils.IpStrTo16Byte("192.168.1.10"),
				Dst:   utils.IpStrTo16Byte("192.168.1.20"),
				Proto: 17, // UDP
				L4Src: 5000,
				L4Dst: 53,
			},
			SrcMeta: endpoint.Metadata{
				AggregatedName: "app1",
				Namespace:      "prod",
				Type:           endpoint.Wep,
			},
			DstMeta: endpoint.Metadata{
				AggregatedName: "dns",
				Namespace:      "kube-system",
				Type:           endpoint.Wep,
			},
			Action:   flowlog.ActionAllow,
			Reporter: flowlog.ReporterDst,
		},
		FlowLabels: flowlog.FlowLabels{
			SrcLabels: uniquelabels.Empty,
			DstLabels: uniquelabels.Empty,
		},
	})

	// Convert back to flowlog
	protoFlow := gl.Key.Proto()
	fl := ConvertGoldmaneToFlowlog(protoFlow)

	// Verify source IP was converted back correctly
	assert.Equal(t, utils.IpStrTo16Byte("192.168.1.10"), fl.Tuple.Src)
	assert.Equal(t, 5000, fl.Tuple.L4Src)
	assert.Equal(t, 53, fl.Tuple.L4Dst)
}