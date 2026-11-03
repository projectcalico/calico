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

package metrics

import (
	"strings"
	"testing"
)

const scrapeOutput = `# HELP wireguard_bytes_sent wireguard bytes sent
# TYPE wireguard_bytes_sent counter
wireguard_bytes_sent{hostname="a",peer_endpoint="10.0.0.2:51820"} 100 1700000000000
wireguard_bytes_sent{hostname="a",peer_endpoint="10.0.0.3:51820"} 7
wireguard_bytes_sent{hostname="a",peer_endpoint="x\"y"} 1000 1700000000000
wireguard_bytes_sent_total 5
other_metric 9
`

func sumWhere(t *testing.T, match func(map[string]string) bool) (float64, error) {
	t.Helper()
	series, err := parseSeries(scrapeOutput, "wireguard_bytes_sent")
	if err != nil {
		t.Fatalf("parseSeries: %v", err)
	}
	return sumSeries("wireguard_bytes_sent", series, match, "test")
}

func TestSumIgnoresTimestamps(t *testing.T) {
	got, err := sumWhere(t, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got != 1107 {
		t.Fatalf("got %v, want 1107", got)
	}
}

func TestSumWhereFiltersByLabel(t *testing.T) {
	got, err := sumWhere(t, func(l map[string]string) bool {
		return strings.HasPrefix(l["peer_endpoint"], "10.0.0.2:")
	})
	if err != nil {
		t.Fatal(err)
	}
	if got != 100 {
		t.Fatalf("got %v, want 100", got)
	}
}

func TestSumWhereNoMatchNamesSkipped(t *testing.T) {
	_, err := sumWhere(t, func(map[string]string) bool { return false })
	if err == nil || !strings.Contains(err.Error(), `peer_endpoint="10.0.0.3:51820"`) {
		t.Fatalf("expected error naming skipped series, got %v", err)
	}
}

func TestSumMissingMetric(t *testing.T) {
	series, err := parseSeries(scrapeOutput, "absent")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := sumSeries("absent", series, nil, "test"); err == nil {
		t.Fatal("expected error for missing metric")
	}
}
