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

package iperfcheck

import (
	"math"
	"testing"
)

// The UDP figures are taken verbatim from a real run of the QoS packet rate
// e2e test (Semaphore job 602788a3, gcp-kubeadm/CalicoBPF).  That run offered
// 100 Mbps, lost 23.8% of the datagrams, and so delivered 76.19 Mbps -- which
// the test's original baseline gate rejected for being under 80 Mbps, despite
// the delivered packet rate being ~95x the 100 pps limit under test.
const udpLossyOutput = `{
  "intervals": [{"sum": {"bits_per_second": 100003693.5989926}}],
  "end": {
    "sum_received": {
      "bits_per_second": 76191382.840279177,
      "seconds": 10.000186,
      "bytes": 95241000,
      "packets": 125042,
      "lost_packets": 29801,
      "lost_percent": 23.840418553303149
    },
    "sum": {
      "bits_per_second": 99996160.208884642,
      "seconds": 10.000544,
      "packets": 125002,
      "lost_packets": 29801,
      "lost_percent": 23.840418553303149
    }
  }
}`

// TCP runs carry no packet accounting at all, so the packet fields must stay
// zero rather than being invented from the byte counts.
const tcpOutput = `{
  "intervals": [{"sum": {"bits_per_second": 943000000}}],
  "end": {
    "sum_received": {"bits_per_second": 941000000, "seconds": 10.0},
    "sum": {"bits_per_second": 0}
  }
}`

// Some iperf3 versions report UDP only under "sum", leaving "sum_received"
// empty; the packet counts must then come from the same block as the rate.
const udpSumOnlyOutput = `{
  "intervals": [{"sum": {"bits_per_second": 8000000}}],
  "end": {
    "sum_received": {"bits_per_second": 0},
    "sum": {
      "bits_per_second": 8000000,
      "seconds": 10.0,
      "packets": 10000,
      "lost_packets": 1000,
      "lost_percent": 10.0
    }
  }
}`

func TestParseIperf3JSON(t *testing.T) {
	for _, tc := range []struct {
		name        string
		output      string
		wantRate    float64
		wantPPS     float64
		wantLossPct float64
	}{
		{"udp with heavy loss", udpLossyOutput, 76191382.84, 9523.92, 23.84},
		{"tcp has no packet counts", tcpOutput, 941000000, 0, 0},
		{"udp reported under sum only", udpSumOnlyOutput, 8000000, 900, 10.0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseIperf3JSON(tc.output)
			if err != nil {
				t.Fatalf("parseIperf3JSON returned an error: %v", err)
			}
			if math.Abs(got.AverageRate-tc.wantRate) > 1 {
				t.Errorf("AverageRate = %.2f, want %.2f", got.AverageRate, tc.wantRate)
			}
			if math.Abs(got.DeliveredPacketsPerSecond-tc.wantPPS) > 0.1 {
				t.Errorf("DeliveredPacketsPerSecond = %.2f, want %.2f", got.DeliveredPacketsPerSecond, tc.wantPPS)
			}
			if math.Abs(got.LostPercent-tc.wantLossPct) > 0.01 {
				t.Errorf("LostPercent = %.2f, want %.2f", got.LostPercent, tc.wantLossPct)
			}
		})
	}
}

// TestLossyRunClearsBaselineGate is the regression this change exists for: the
// run above must satisfy the packet rate test's baseline gate, which requires
// 10x headroom over the 100 pps limit under test.
func TestLossyRunClearsBaselineGate(t *testing.T) {
	const packetRateLimit, baselineHeadroom = 100, 10

	got, err := parseIperf3JSON(udpLossyOutput)
	if err != nil {
		t.Fatalf("parseIperf3JSON returned an error: %v", err)
	}
	if min := float64(packetRateLimit * baselineHeadroom); got.DeliveredPacketsPerSecond < min {
		t.Errorf("delivered %.0f pps, which does not clear the %.0f pps baseline gate",
			got.DeliveredPacketsPerSecond, min)
	}
}
