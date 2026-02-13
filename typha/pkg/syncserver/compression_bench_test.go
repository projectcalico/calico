// Copyright (c) 2026 Tigera, Inc. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package syncserver_test

import (
	"bytes"
	"encoding/gob"
	"fmt"
	"io"
	"math/rand"
	"net"
	"testing"
	"time"

	"github.com/golang/snappy"
	"github.com/klauspost/compress/zstd"

	"github.com/projectcalico/calico/lib/std/uniquelabels"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	calinet "github.com/projectcalico/calico/libcalico-go/lib/net"
	"github.com/projectcalico/calico/typha/pkg/syncproto"
)

// generateBenchPod creates a realistic Pod WorkloadEndpoint update similar to
// what the Typha snapshot cache compresses and sends to clients.
func generateBenchPod(rng *rand.Rand, n int) api.Update {
	namespace := fmt.Sprintf("a-namespace-name-%x", n/100)
	name := fmt.Sprintf("some-app-name-%d-%x", n, rng.Uint64())
	hostname := fmt.Sprintf("hostname%d", n/20)
	ip := net.IP{10, byte(n >> 16), byte(n >> 8), byte(n)}

	return api.Update{
		KVPair: model.KVPair{
			Key: model.WorkloadEndpointKey{
				Hostname:       hostname,
				OrchestratorID: "k8s",
				WorkloadID:     fmt.Sprintf("%s/%s", namespace, name),
				EndpointID:     name,
			},
			Value: &model.WorkloadEndpoint{
				Labels: uniquelabels.Make(map[string]string{
					"kubernetes-topology-label": "zone-A",
					"kubernetes-region-label":   "zone-A",
					"owner":                     fmt.Sprintf("someone-%x", rng.Uint32()),
					"oneof10":                   fmt.Sprintf("value-%d", n/10),
					"oneof100":                  fmt.Sprintf("value-%d", n/100),
				}),
				IPv4Nets: []calinet.IPNet{
					{IPNet: net.IPNet{IP: ip, Mask: net.CIDRMask(32, 32)}},
				},
				ProfileIDs: []string{
					fmt.Sprintf("kns.%s", namespace),
					fmt.Sprintf("ksa.%s.default", namespace),
				},
			},
			Revision: fmt.Sprintf("%d", n),
		},
		UpdateType: api.UpdateTypeKVNew,
	}
}

// generateBenchConfig creates a GlobalConfig update with a large random value,
// simulating config entries that Typha sends.
func generateBenchConfig(rng *rand.Rand, n int) api.Update {
	buf := make([]byte, 500)
	rng.Read(buf)
	return api.Update{
		KVPair: model.KVPair{
			Key:      model.GlobalConfigKey{Name: fmt.Sprintf("config-key-%d", n)},
			Value:    fmt.Sprintf("%d=%x", n, buf),
			Revision: fmt.Sprintf("%d", n),
		},
		UpdateType: api.UpdateTypeKVNew,
	}
}

// generateBenchNode creates a HostIP update similar to what Typha sends
// for node resources.
func generateBenchNode(_ *rand.Rand, n int) api.Update {
	ip := calinet.ParseIP(fmt.Sprintf("10.%d.%d.%d", n>>16&0xff, n>>8&0xff, n&0xff))
	return api.Update{
		KVPair: model.KVPair{
			Key: model.HostIPKey{
				Hostname: fmt.Sprintf("node-%d", n),
			},
			Value:    ip,
			Revision: fmt.Sprintf("%d", n),
		},
		UpdateType: api.UpdateTypeKVNew,
	}
}

// gobEncodeUpdates encodes a batch of updates in the same way as Typha's
// snapshot cache: gob-encoded syncproto.Envelope messages.
func gobEncodeUpdates(updates []api.Update) []byte {
	var buf bytes.Buffer
	encoder := gob.NewEncoder(&buf)
	for i := 0; i < len(updates); i += 100 {
		end := i + 100
		if end > len(updates) {
			end = len(updates)
		}
		kvs := make([]syncproto.SerializedUpdate, 0, end-i)
		for _, u := range updates[i:end] {
			su, err := syncproto.SerializeUpdate(u)
			if err != nil {
				continue // skip unserializable (same as production code)
			}
			kvs = append(kvs, su)
		}
		envelope := syncproto.Envelope{
			Message: syncproto.MsgKVs{KVs: kvs},
		}
		if err := encoder.Encode(&envelope); err != nil {
			panic(err)
		}
	}
	// Append MsgDecoderRestart to match the real snapshot format.
	envelope := syncproto.Envelope{
		Message: syncproto.MsgDecoderRestart{
			Message:              "End of compressed snapshot.",
			CompressionAlgorithm: syncproto.CompressionSnappy,
		},
	}
	if err := encoder.Encode(&envelope); err != nil {
		panic(err)
	}
	return buf.Bytes()
}

// compressSnappy compresses data using snappy (same as Typha's snappy.NewBufferedWriter).
func compressSnappy(data []byte) []byte {
	var buf bytes.Buffer
	w := snappy.NewBufferedWriter(&buf)
	_, _ = w.Write(data)
	_ = w.Close()
	return buf.Bytes()
}

// compressZstd compresses data using zstd at SpeedFastest (same as Typha's snap_precalc.go).
func compressZstd(data []byte) []byte {
	var buf bytes.Buffer
	w, err := zstd.NewWriter(&buf, zstd.WithEncoderLevel(zstd.SpeedFastest))
	if err != nil {
		panic(err)
	}
	_, _ = w.Write(data)
	_ = w.Close()
	return buf.Bytes()
}

// decompressSnappy decompresses snappy data.
func decompressSnappy(compressed []byte) []byte {
	r := snappy.NewReader(bytes.NewReader(compressed))
	data, err := io.ReadAll(r)
	if err != nil {
		panic(err)
	}
	return data
}

// decompressZstd decompresses zstd data.
func decompressZstd(compressed []byte) []byte {
	r, err := zstd.NewReader(bytes.NewReader(compressed))
	if err != nil {
		panic(err)
	}
	defer r.Close()
	data, err := io.ReadAll(r)
	if err != nil {
		panic(err)
	}
	return data
}

// TestCompressionComparison is a test (not a benchmark) that prints a
// human-readable comparison of snappy vs zstd compression on realistic
// Typha snapshot data at various sizes.
func TestCompressionComparison(t *testing.T) {
	rng := rand.New(rand.NewSource(42))

	for _, tc := range []struct {
		name     string
		numPods  int
		numConfs int
		numNodes int
	}{
		{"small cluster (100 pods, 50 configs, 10 nodes)", 100, 50, 10},
		{"medium cluster (1000 pods, 200 configs, 50 nodes)", 1000, 200, 50},
		{"large cluster (10000 pods, 500 configs, 200 nodes)", 10000, 500, 200},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var updates []api.Update
			for i := 0; i < tc.numPods; i++ {
				updates = append(updates, generateBenchPod(rng, i))
			}
			for i := 0; i < tc.numConfs; i++ {
				updates = append(updates, generateBenchConfig(rng, i))
			}
			for i := 0; i < tc.numNodes; i++ {
				updates = append(updates, generateBenchNode(rng, i))
			}

			rawData := gobEncodeUpdates(updates)
			rawSize := len(rawData)

			// Compress with both algorithms.
			start := time.Now()
			snappyData := compressSnappy(rawData)
			snappyCompressTime := time.Since(start)

			start = time.Now()
			zstdData := compressZstd(rawData)
			zstdCompressTime := time.Since(start)

			snappySize := len(snappyData)
			zstdSize := len(zstdData)

			snappyRatio := float64(rawSize) / float64(snappySize)
			zstdRatio := float64(rawSize) / float64(zstdSize)
			savings := 100.0 * (1.0 - float64(zstdSize)/float64(snappySize))

			// Decompress to measure decompression speed.
			start = time.Now()
			decompressSnappy(snappyData)
			snappyDecompressTime := time.Since(start)

			start = time.Now()
			decompressZstd(zstdData)
			zstdDecompressTime := time.Since(start)

			t.Logf("Scenario: %s", tc.name)
			t.Logf("  Total KV updates:  %d", len(updates))
			t.Logf("  Raw gob size:      %d bytes (%.1f KB)", rawSize, float64(rawSize)/1024)
			t.Logf("")
			t.Logf("  Snappy compressed: %d bytes (%.1f KB), ratio: %.2f:1", snappySize, float64(snappySize)/1024, snappyRatio)
			t.Logf("  Zstd compressed:   %d bytes (%.1f KB), ratio: %.2f:1", zstdSize, float64(zstdSize)/1024, zstdRatio)
			t.Logf("")
			t.Logf("  Zstd saves %.1f%% over snappy", savings)
			t.Logf("")
			t.Logf("  Compression speed:")
			t.Logf("    Snappy:  %v (%.0f MB/s)", snappyCompressTime, float64(rawSize)/snappyCompressTime.Seconds()/1e6)
			t.Logf("    Zstd:    %v (%.0f MB/s)", zstdCompressTime, float64(rawSize)/zstdCompressTime.Seconds()/1e6)
			t.Logf("")
			t.Logf("  Decompression speed:")
			t.Logf("    Snappy:  %v (%.0f MB/s)", snappyDecompressTime, float64(rawSize)/snappyDecompressTime.Seconds()/1e6)
			t.Logf("    Zstd:    %v (%.0f MB/s)", zstdDecompressTime, float64(rawSize)/zstdDecompressTime.Seconds()/1e6)
		})
	}
}

// BenchmarkSnappyCompress benchmarks snappy compression on 1000-pod Typha snapshot data.
func BenchmarkSnappyCompress(b *testing.B) {
	rng := rand.New(rand.NewSource(42))
	var updates []api.Update
	for i := 0; i < 1000; i++ {
		updates = append(updates, generateBenchPod(rng, i))
	}
	rawData := gobEncodeUpdates(updates)
	b.SetBytes(int64(len(rawData)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		compressSnappy(rawData)
	}
}

// BenchmarkZstdCompress benchmarks zstd compression (SpeedFastest) on 1000-pod Typha snapshot data.
func BenchmarkZstdCompress(b *testing.B) {
	rng := rand.New(rand.NewSource(42))
	var updates []api.Update
	for i := 0; i < 1000; i++ {
		updates = append(updates, generateBenchPod(rng, i))
	}
	rawData := gobEncodeUpdates(updates)
	b.SetBytes(int64(len(rawData)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		compressZstd(rawData)
	}
}

// BenchmarkSnappyDecompress benchmarks snappy decompression on 1000-pod Typha snapshot data.
func BenchmarkSnappyDecompress(b *testing.B) {
	rng := rand.New(rand.NewSource(42))
	var updates []api.Update
	for i := 0; i < 1000; i++ {
		updates = append(updates, generateBenchPod(rng, i))
	}
	rawData := gobEncodeUpdates(updates)
	compressed := compressSnappy(rawData)
	b.SetBytes(int64(len(rawData)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		decompressSnappy(compressed)
	}
}

// BenchmarkZstdDecompress benchmarks zstd decompression on 1000-pod Typha snapshot data.
func BenchmarkZstdDecompress(b *testing.B) {
	rng := rand.New(rand.NewSource(42))
	var updates []api.Update
	for i := 0; i < 1000; i++ {
		updates = append(updates, generateBenchPod(rng, i))
	}
	rawData := gobEncodeUpdates(updates)
	compressed := compressZstd(rawData)
	b.SetBytes(int64(len(rawData)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		decompressZstd(compressed)
	}
}

// TestCompressionRoundTrip verifies that both algorithms produce identical
// decompressed output (a correctness sanity check).
func TestCompressionRoundTrip(t *testing.T) {

	rng := rand.New(rand.NewSource(42))
	var updates []api.Update
	for i := 0; i < 500; i++ {
		updates = append(updates, generateBenchPod(rng, i))
	}
	rawData := gobEncodeUpdates(updates)

	snappyCompressed := compressSnappy(rawData)
	zstdCompressed := compressZstd(rawData)

	snappyDecompressed := decompressSnappy(snappyCompressed)
	zstdDecompressed := decompressZstd(zstdCompressed)

	if !bytes.Equal(rawData, snappyDecompressed) {
		t.Fatal("Snappy round-trip mismatch")
	}
	if !bytes.Equal(rawData, zstdDecompressed) {
		t.Fatal("Zstd round-trip mismatch")
	}
	t.Logf("Round-trip verified: raw=%d bytes, snappy=%d bytes, zstd=%d bytes",
		len(rawData), len(snappyCompressed), len(zstdCompressed))
}
