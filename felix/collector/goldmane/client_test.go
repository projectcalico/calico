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
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/projectcalico/calico/felix/collector/flowlog"
	"github.com/projectcalico/calico/felix/collector/types/endpoint"
	"github.com/projectcalico/calico/felix/collector/types/tuple"
	"github.com/projectcalico/calico/felix/collector/utils"
	"github.com/projectcalico/calico/goldmane/pkg/types"
	"github.com/projectcalico/calico/lib/std/uniquelabels"
)

func TestConvertFlowlogToGoldmane_CompleteFlow(t *testing.T) {
	// Create a test flow log with all fields populated
	sourceIP := utils.IpStrTo16Byte("192.168.1.10")
	destIP := utils.IpStrTo16Byte("192.168.1.20")
	
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
				AggregatedName: "web-frontend",
				Namespace:      "production",
				Type:           endpoint.Wep,
			},
			DstMeta: endpoint.Metadata{
				AggregatedName: "api-backend",
				Namespace:      "production",
				Type:           endpoint.Wep,
			},
			DstService: flowlog.FlowService{
				Name:      "api-service",
				Namespace: "production",
				PortName:  "http",
				PortNum:   80,
			},
			Action:   flowlog.ActionAllow,
			Reporter: flowlog.ReporterSrc,
		},
		FlowLabels: flowlog.FlowLabels{
			SrcLabels: uniquelabels.Make(map[string]string{
				"app": "frontend",
				"env": "prod",
			}),
			DstLabels: uniquelabels.Make(map[string]string{
				"app": "backend",
				"env": "prod",
			}),
		},
		PacketsIn:          100,
		PacketsOut:         200,
		BytesIn:            10000,
		BytesOut:           20000,
		NumFlows:           5,
		NumFlowsStarted:    10,
		NumFlowsCompleted:  8,
	}

	// Convert to Goldmane flow
	gf := ConvertFlowlogToGoldmane(fl)

	// Verify all fields are converted correctly
	assert.Equal(t, "192.168.1.10", gf.Key.SourceIP())
	assert.Equal(t, "192.168.1.20", gf.Key.DestIP())
	assert.Equal(t, int64(12345), gf.Key.SourcePort())
	assert.Equal(t, int64(80), gf.Key.DestPort())
	
	assert.Equal(t, "web-frontend", gf.Key.SourceName())
	assert.Equal(t, "production", gf.Key.SourceNamespace())
	assert.Equal(t, "api-backend", gf.Key.DestName())
	assert.Equal(t, "production", gf.Key.DestNamespace())
	
	assert.Equal(t, "api-service", gf.Key.DestServiceName())
	assert.Equal(t, "production", gf.Key.DestServiceNamespace())
	assert.Equal(t, "http", gf.Key.DestServicePortName())
	assert.Equal(t, int64(80), gf.Key.DestServicePort())
	
	assert.Equal(t, "TCP", gf.Key.Proto())
	assert.Equal(t, int64(100), gf.PacketsIn)
	assert.Equal(t, int64(200), gf.PacketsOut)
	assert.Equal(t, int64(10000), gf.BytesIn)
	assert.Equal(t, int64(20000), gf.BytesOut)
}

func TestConvertFlowlogToGoldmane_IPv6(t *testing.T) {
	// Test with IPv6 addresses
	sourceIP := utils.IpStrTo16Byte("2001:db8::1")
	destIP := utils.IpStrTo16Byte("2001:db8::2")
	
	fl := &flowlog.FlowLog{
		StartTime: time.Unix(1234567890, 0),
		FlowMeta: flowlog.FlowMeta{
			Tuple: tuple.Tuple{
				Src:   sourceIP,
				Dst:   destIP,
				Proto: 17, // UDP
				L4Src: 5353,
				L4Dst: 53,
			},
			SrcMeta: endpoint.Metadata{
				AggregatedName: "dns-client",
				Namespace:      "kube-system",
				Type:           endpoint.Wep,
			},
			DstMeta: endpoint.Metadata{
				AggregatedName: "coredns",
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
	}

	gf := ConvertFlowlogToGoldmane(fl)

	assert.Equal(t, "2001:db8::1", gf.Key.SourceIP())
	assert.Equal(t, "2001:db8::2", gf.Key.DestIP())
	assert.Equal(t, "UDP", gf.Key.Proto())
}

func TestConvertGoldmaneToFlowlog_CompleteFlow(t *testing.T) {
	// Create a Goldmane flow
	gf := types.NewFlowKey(
		&types.FlowKeySource{
			SourceName:      "web-app",
			SourceNamespace: "default",
			SourceType:      convertType(endpoint.Wep),
			SourceIP:        "10.0.0.1",
			SourcePort:      8080,
		},
		&types.FlowKeyDestination{
			DestName:             "database",
			DestNamespace:        "default",
			DestType:             convertType(endpoint.Wep),
			DestIP:               "10.0.0.2",
			DestPort:             3306,
			DestServiceName:      "mysql-service",
			DestServiceNamespace: "default",
			DestServicePortName:  "mysql",
			DestServicePort:      3306,
		},
		&types.FlowKeyMeta{
			Proto:    "TCP",
			Reporter: convertReporter(flowlog.ReporterSrc),
			Action:   convertAction(flowlog.ActionAllow),
		},
		nil,
	)

	flow := &types.Flow{
		Key:                     gf,
		StartTime:               1234567890,
		EndTime:                 1234567890,
		PacketsIn:               50,
		PacketsOut:              60,
		BytesIn:                 5000,
		BytesOut:                6000,
		NumConnectionsLive:      2,
		NumConnectionsStarted:   5,
		NumConnectionsCompleted: 3,
	}

	// Convert to proto then to flowlog
	protoFlow := types.FlowToProto(flow)
	fl := ConvertGoldmaneToFlowlog(protoFlow)

	// Verify source and destination IPs are converted correctly
	assert.Equal(t, utils.IpStrTo16Byte("10.0.0.1"), fl.Tuple.Src)
	assert.Equal(t, utils.IpStrTo16Byte("10.0.0.2"), fl.Tuple.Dst)
	assert.Equal(t, 8080, fl.Tuple.L4Src)
	assert.Equal(t, 3306, fl.Tuple.L4Dst)
	assert.Equal(t, 6, fl.Tuple.Proto) // TCP
	
	assert.Equal(t, "web-app", fl.SrcMeta.AggregatedName)
	assert.Equal(t, "default", fl.SrcMeta.Namespace)
	assert.Equal(t, "database", fl.DstMeta.AggregatedName)
	assert.Equal(t, "default", fl.DstMeta.Namespace)
	
	assert.Equal(t, "mysql-service", fl.DstService.Name)
	assert.Equal(t, "default", fl.DstService.Namespace)
	assert.Equal(t, "mysql", fl.DstService.PortName)
	assert.Equal(t, 3306, fl.DstService.PortNum)
}

func TestConvertGoldmaneToFlowlog_IPv6(t *testing.T) {
	// Test reverse conversion with IPv6
	gf := types.NewFlowKey(
		&types.FlowKeySource{
			SourceName:      "ipv6-client",
			SourceNamespace: "test",
			SourceType:      convertType(endpoint.Hep),
			SourceIP:        "fd00::1",
			SourcePort:      9000,
		},
		&types.FlowKeyDestination{
			DestName:      "ipv6-server",
			DestNamespace: "test",
			DestType:      convertType(endpoint.Hep),
			DestIP:        "fd00::2",
			DestPort:      443,
		},
		&types.FlowKeyMeta{
			Proto:    "TCP",
			Reporter: convertReporter(flowlog.ReporterDst),
			Action:   convertAction(flowlog.ActionDeny),
		},
		nil,
	)

	flow := &types.Flow{
		Key:       gf,
		StartTime: 1234567890,
		EndTime:   1234567890,
	}

	protoFlow := types.FlowToProto(flow)
	fl := ConvertGoldmaneToFlowlog(protoFlow)

	assert.Equal(t, utils.IpStrTo16Byte("fd00::1"), fl.Tuple.Src)
	assert.Equal(t, utils.IpStrTo16Byte("fd00::2"), fl.Tuple.Dst)
	assert.Equal(t, endpoint.Hep, fl.SrcMeta.Type)
	assert.Equal(t, endpoint.Hep, fl.DstMeta.Type)
	assert.Equal(t, flowlog.ActionDeny, fl.Action)
	assert.Equal(t, flowlog.ReporterDst, fl.Reporter)
}

func TestConvertGoldmaneToFlowlog_EmptyIPs(t *testing.T) {
	// Test with empty IP addresses
	gf := types.NewFlowKey(
		&types.FlowKeySource{
			SourceName:      "unknown",
			SourceNamespace: "default",
			SourceType:      convertType(endpoint.Net),
			SourceIP:        "",
			SourcePort:      0,
		},
		&types.FlowKeyDestination{
			DestName:      "unknown",
			DestNamespace: "default",
			DestType:      convertType(endpoint.Net),
			DestIP:        "",
			DestPort:      0,
		},
		&types.FlowKeyMeta{
			Proto:    "ICMP",
			Reporter: convertReporter(flowlog.ReporterSrc),
			Action:   convertAction(flowlog.ActionAllow),
		},
		nil,
	)

	flow := &types.Flow{
		Key:       gf,
		StartTime: 1234567890,
		EndTime:   1234567890,
	}

	protoFlow := types.FlowToProto(flow)
	fl := ConvertGoldmaneToFlowlog(protoFlow)

	// Empty IPs should result in zero-filled arrays
	var emptyIP [16]byte
	assert.Equal(t, emptyIP, fl.Tuple.Src)
	assert.Equal(t, emptyIP, fl.Tuple.Dst)
}

func TestConvertGoldmaneToFlowlog_InvalidIPs(t *testing.T) {
	// Test with invalid IP addresses
	gf := types.NewFlowKey(
		&types.FlowKeySource{
			SourceName:      "invalid",
			SourceNamespace: "default",
			SourceType:      convertType(endpoint.Ns),
			SourceIP:        "not-an-ip",
			SourcePort:      1234,
		},
		&types.FlowKeyDestination{
			DestName:      "invalid",
			DestNamespace: "default",
			DestType:      convertType(endpoint.Ns),
			DestIP:        "also-not-an-ip",
			DestPort:      5678,
		},
		&types.FlowKeyMeta{
			Proto:    "TCP",
			Reporter: convertReporter(flowlog.ReporterSrc),
			Action:   convertAction(flowlog.ActionAllow),
		},
		nil,
	)

	flow := &types.Flow{
		Key:       gf,
		StartTime: 1234567890,
		EndTime:   1234567890,
	}

	protoFlow := types.FlowToProto(flow)
	fl := ConvertGoldmaneToFlowlog(protoFlow)

	// Invalid IPs should result in zero-filled arrays
	var emptyIP [16]byte
	assert.Equal(t, emptyIP, fl.Tuple.Src)
	assert.Equal(t, emptyIP, fl.Tuple.Dst)
}

func TestIPConversion_RoundTrip(t *testing.T) {
	// Test round-trip conversion for various IP formats
	testCases := []struct {
		name string
		ip   string
	}{
		{"IPv4 localhost", "127.0.0.1"},
		{"IPv4 private", "192.168.1.1"},
		{"IPv4 public", "8.8.8.8"},
		{"IPv6 localhost", "::1"},
		{"IPv6 full", "2001:db8:85a3::8a2e:370:7334"},
		{"IPv6 compressed", "2001:db8::1"},
		{"IPv4-mapped IPv6", "::ffff:192.0.2.1"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Parse IP to [16]byte format
			ip := net.ParseIP(tc.ip)
			var ipBytes [16]byte
			copy(ipBytes[:], ip.To16())

			// Create flow log with this IP
			fl := &flowlog.FlowLog{
				StartTime: time.Unix(1234567890, 0),
				FlowMeta: flowlog.FlowMeta{
					Tuple: tuple.Tuple{
						Src:   ipBytes,
						Dst:   ipBytes,
						Proto: 6,
						L4Src: 1234,
						L4Dst: 5678,
					},
					SrcMeta: endpoint.Metadata{
						AggregatedName: "test",
						Namespace:      "default",
						Type:           endpoint.Wep,
					},
					DstMeta: endpoint.Metadata{
						AggregatedName: "test",
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

			// Convert to Goldmane and back
			gf := ConvertFlowlogToGoldmane(fl)
			protoFlow := types.FlowToProto(gf)
			fl2 := ConvertGoldmaneToFlowlog(protoFlow)

			// Verify IPs match after round trip
			assert.Equal(t, ipBytes, fl2.Tuple.Src)
			assert.Equal(t, ipBytes, fl2.Tuple.Dst)
		})
	}
}