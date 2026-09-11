// Copyright (c) 2026 Tigera, Inc. All rights reserved.
//
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

package collector

import (
	"testing"
	"time"

	. "github.com/onsi/gomega"
	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/projectcalico/calico/felix/calc"
	"github.com/projectcalico/calico/felix/proto"
)

// A DataplaneStats update that the collector cannot turn into a 5-tuple is one error, so it must
// move the counter by one. It used to move it by four: the extract helper reported at its own
// error paths, the caller reported the error it returned, and the reporting function added each
// delta twice.
func TestConvertDataplaneStatsCountsEachBadUpdateOnce(t *testing.T) {
	RegisterTestingT(t)

	for _, tc := range []struct {
		name      string
		stats     *proto.DataplaneStats
		wantDelta float64
	}{
		{
			name: "unhandled protocol name",
			stats: &proto.DataplaneStats{
				SrcIp: localIp1Str, DstIp: localIp2Str, SrcPort: 1000, DstPort: 2000,
				Protocol: &proto.Protocol{NumberOrName: &proto.Protocol_Name{Name: "sctp"}},
			},
			wantDelta: 1,
		},
		{
			name: "bad source IP",
			stats: &proto.DataplaneStats{
				SrcIp: "not-an-ip", DstIp: localIp2Str, SrcPort: 1000, DstPort: 2000,
				Protocol: &proto.Protocol{NumberOrName: &proto.Protocol_Number{Number: proto_tcp}},
			},
			wantDelta: 1,
		},
		{
			name: "bad destination IP",
			stats: &proto.DataplaneStats{
				SrcIp: localIp1Str, DstIp: "not-an-ip", SrcPort: 1000, DstPort: 2000,
				Protocol: &proto.Protocol{NumberOrName: &proto.Protocol_Number{Number: proto_tcp}},
			},
			wantDelta: 1,
		},
		{
			name: "good update",
			stats: &proto.DataplaneStats{
				SrcIp: localIp1Str, DstIp: localIp2Str, SrcPort: 1000, DstPort: 2000,
				Protocol: &proto.Protocol{NumberOrName: &proto.Protocol_Number{Number: proto_tcp}},
			},
			wantDelta: 0,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			RegisterTestingT(t)
			c := newDataplaneStatsTestCollector()

			// The counter is package level and other tests in this package move it, so compare a
			// delta rather than an absolute value.
			before := testutil.ToFloat64(counterDataplaneStatsUpdateErrors)
			c.convertDataplaneStatsAndApplyUpdate(tc.stats)
			after := testutil.ToFloat64(counterDataplaneStatsUpdateErrors)

			Expect(after - before).To(Equal(tc.wantDelta))
		})
	}
}

// extractTupleFromDataplaneStats is a pure conversion: it reports the failure by returning an
// error, and leaves counting it to the caller. Reporting in both places is what double counted.
func TestExtractTupleFromDataplaneStatsReportsNoMetric(t *testing.T) {
	RegisterTestingT(t)

	before := testutil.ToFloat64(counterDataplaneStatsUpdateErrors)
	_, err := extractTupleFromDataplaneStats(&proto.DataplaneStats{
		SrcIp: "not-an-ip", DstIp: localIp2Str, SrcPort: 1000, DstPort: 2000,
		Protocol: &proto.Protocol{NumberOrName: &proto.Protocol_Number{Number: proto_tcp}},
	})

	Expect(err).To(HaveOccurred())
	Expect(testutil.ToFloat64(counterDataplaneStatsUpdateErrors)).To(Equal(before))
}

func newDataplaneStatsTestCollector() *collector {
	epMap := map[[16]byte]calc.EndpointData{
		localIp1: localEd1,
		localIp2: localEd2,
	}
	return newCollector(newMockLookupsCache(epMap, nil, nil, nil), &Config{
		AgeTimeout:            10 * time.Second,
		InitialReportingDelay: 5 * time.Second,
		ExportingInterval:     time.Second,
		FlowLogsFlushInterval: time.Second,
	}).(*collector)
}
