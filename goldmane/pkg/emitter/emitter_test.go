// Copyright (c) 2025 Tigera, Inc. All rights reserved.

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

package emitter_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ktypes "k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/projectcalico/calico/goldmane/pkg/aggregator"
	"github.com/projectcalico/calico/goldmane/pkg/emitter"
	"github.com/projectcalico/calico/goldmane/pkg/internal/types"
	"github.com/projectcalico/calico/goldmane/pkg/internal/utils"
	"github.com/projectcalico/calico/libcalico-go/lib/logutils"
)

var emt *emitter.Emitter

var configMapKey = ktypes.NamespacedName{Name: "flow-emitter-state", Namespace: "calico-system"}

func setupTest(t *testing.T, opts ...emitter.Option) func() {
	// Hook logrus into testing.T
	utils.ConfigureLogging("DEBUG")
	logCancel := logutils.RedirectLogrusToTestingT(t)

	// Run the emitter.
	stopCh := make(chan struct{})
	emt = emitter.NewEmitter(opts...)
	go emt.Run(stopCh)

	return func() {
		close(stopCh)
		emt = nil
		logCancel()
	}
}

func TestEmitterMainline(t *testing.T) {
	// Create a flow to send.
	flow := types.Flow{
		Key: &types.FlowKey{
			SourceName:      "test-src",
			SourceNamespace: "test-ns",
			DestName:        "test-dst",
			DestNamespace:   "test-dst-ns",
			Proto:           "tcp",
		},
		StartTime:             18,
		EndTime:               28,
		BytesIn:               100,
		BytesOut:              200,
		PacketsIn:             10,
		PacketsOut:            20,
		NumConnectionsStarted: 1,
	}
	expectedBody, err := json.Marshal(flow)
	require.NoError(t, err)

	// Creat a mock HTTP server to use as our sink.
	numBucketsEmitted := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify the request.
		require.Equal(t, "/path/to/flows", r.URL.Path)
		require.Equal(t, "POST", r.Method)

		// Read the body and assert it matches the expected flow.
		buf := new(bytes.Buffer)
		_, err := buf.ReadFrom(r.Body)
		require.NoError(t, err)
		require.Equal(t, buf.String(), string(expectedBody))
		w.WriteHeader(http.StatusOK)

		numBucketsEmitted++
	}))

	kcli := fake.NewFakeClient()
	opts := []emitter.Option{
		emitter.WithURL(fmt.Sprintf("%s/path/to/flows", server.URL)),
		emitter.WithServerName("test-server"),
		emitter.WithKubeClient(kcli),
	}
	defer server.Close()

	// Set up the test.
	defer setupTest(t, opts...)()

	// Send a bucket with a single flow.
	b := aggregator.NewAggregationBucket(time.Unix(15, 0), time.Unix(30, 0))
	b.AddFlow(&flow)
	emt.Receive(b)

	// Wait for the emitter to process the bucket. It should emit the flow to the mock server.
	require.Eventually(t, func() bool {
		return numBucketsEmitted == 1
	}, 5*time.Second, 500*time.Millisecond)

	// Verify that the emitter saved its state in a configmap.
	cm := &corev1.ConfigMap{}
	err = kcli.Get(context.Background(), configMapKey, cm)
	require.NoError(t, err)
	require.Equal(t, fmt.Sprintf("%d", b.EndTime), cm.Data["latestTimestamp"])
}

func TestEmitterRetry(t *testing.T) {
	// Create a flow to send.
	flow := types.Flow{
		Key: &types.FlowKey{
			SourceName:      "test-src",
			SourceNamespace: "test-ns",
			DestName:        "test-dst",
			DestNamespace:   "test-dst-ns",
			Proto:           "tcp",
		},
		StartTime:             18,
		EndTime:               28,
		BytesIn:               100,
		BytesOut:              200,
		PacketsIn:             10,
		PacketsOut:            20,
		NumConnectionsStarted: 1,
	}
	expectedBody, err := json.Marshal(flow)
	require.NoError(t, err)

	// Creat a mock HTTP server to use as our sink.
	numBucketsEmitted := 0
	numRequests := 0

	// For this test, we configure the server to fail the first request with a 500 error
	// and then succeed on subsequent requests. This verifies that the emitter retries in the case
	// of a failure.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if numRequests < 1 {
			w.WriteHeader(500)
			numRequests++
			return
		}
		numRequests++

		// Verify the request.
		require.Equal(t, "/path/to/flows", r.URL.Path)
		require.Equal(t, "POST", r.Method)

		// Read the body and assert it matches the expected flow.
		buf := new(bytes.Buffer)
		_, err := buf.ReadFrom(r.Body)
		require.NoError(t, err)
		require.Equal(t, buf.String(), string(expectedBody))
		w.WriteHeader(http.StatusOK)

		numBucketsEmitted++
	}))
	opts := []emitter.Option{
		emitter.WithURL(fmt.Sprintf("%s/path/to/flows", server.URL)),
		emitter.WithServerName("test-server"),
	}
	defer server.Close()

	// Set up the test.
	defer setupTest(t, opts...)()

	// Send a bucket with a single flow.
	b := aggregator.NewAggregationBucket(time.Unix(15, 0), time.Unix(30, 0))
	b.AddFlow(&flow)
	emt.Receive(b)

	// Wait for the emitter to process the bucket. It should emit the flow to the mock server.
	require.Eventually(t, func() bool {
		return numRequests >= 2
	}, 5*time.Second, 500*time.Millisecond, "Didn't retry the request?")
	require.Eventually(t, func() bool {
		return numBucketsEmitted == 1
	}, 5*time.Second, 500*time.Millisecond, "Didn't emit the flow?")
}

// TestStaleBuckets tests that the emitter can properly skip emission of buckets that predate its latest
// saved timestamp. This can happen, for example, when goldmane restarts and learns about already emitted
// flows.
func TestStaleBuckets(t *testing.T) {
	// Create a configmap which represents the latest timestamp emitted. This will be loaded by the emitter
	// to determine which buckets to skip.
	kcli := fake.NewFakeClient()
	cm := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "flow-emitter-state",
			Namespace: "calico-system",
		},
		Data: map[string]string{
			// latestTimestamp is AFTER the start / end times of the flow and bucket below.
			"latestTimestamp": "45",
		},
	}
	err := kcli.Create(context.Background(), cm)
	require.NoError(t, err)

	// Two flows to send - one before the latest timestamp, and one after.
	flow := types.Flow{
		Key: &types.FlowKey{
			SourceName:      "test-src",
			SourceNamespace: "test-ns",
			DestName:        "test-dst",
			DestNamespace:   "test-dst-ns",
			Proto:           "tcp",
		},
		StartTime:             18,
		EndTime:               28,
		BytesIn:               100,
		BytesOut:              200,
		PacketsIn:             10,
		PacketsOut:            20,
		NumConnectionsStarted: 1,
	}
	flowOK := types.Flow{
		Key: &types.FlowKey{
			SourceName:      "test-src",
			SourceNamespace: "test-ns",
			DestName:        "test-dst",
			DestNamespace:   "test-dst-ns",
			Proto:           "tcp",
		},
		StartTime:             61,
		EndTime:               65,
		BytesIn:               100,
		BytesOut:              200,
		PacketsIn:             10,
		PacketsOut:            20,
		NumConnectionsStarted: 1,
	}
	unexpectedBody, err := json.Marshal(flow)
	require.NoError(t, err)
	okBody, err := json.Marshal(flowOK)
	require.NoError(t, err)

	// Creat a mock HTTP server to use as our sink. We don't expect any requests to be made.
	numBucketsEmitted := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check the body. We don't expect the first flow to be sent.
		buf := new(bytes.Buffer)
		_, err := buf.ReadFrom(r.Body)
		require.NoError(t, err)
		if buf.String() == string(unexpectedBody) {
			require.Fail(t, "Unexpected flow sent to server")
		}
		require.Equal(t, buf.String(), string(okBody))

		numBucketsEmitted++
		w.WriteHeader(http.StatusOK)
	}))

	opts := []emitter.Option{
		emitter.WithURL(fmt.Sprintf("%s/path/to/flows", server.URL)),
		emitter.WithServerName("test-server"),
		emitter.WithKubeClient(kcli),
	}
	defer server.Close()

	// Set up the test.
	defer setupTest(t, opts...)()

	// Send a bucket with a single flow.
	b := aggregator.NewAggregationBucket(time.Unix(15, 0), time.Unix(30, 0))
	// Create a flow to send.
	b.AddFlow(&flow)
	emt.Receive(b)

	// The emitter should skip emitting the bucket, and the flow should not be sent to the server.
	// Wait a couple of seconds to confirm.
	time.Sleep(2 * time.Second)

	// The timestamp should not be updated.
	err = kcli.Get(context.Background(), configMapKey, cm)
	require.NoError(t, err)
	require.Equal(t, "45", cm.Data["latestTimestamp"])

	// Send a new bucket that is after the latest timestamp. This one should be sent.
	bOK := aggregator.NewAggregationBucket(time.Unix(60, 0), time.Unix(70, 0))
	bOK.AddFlow(&flowOK)
	emt.Receive(bOK)

	// Expect the flow to be sent to the server.
	require.Eventually(t, func() bool {
		return numBucketsEmitted == 1
	}, 5*time.Second, 500*time.Millisecond)

	// The timestamp should be updated.
	err = kcli.Get(context.Background(), configMapKey, cm)
	require.NoError(t, err)
	require.Equal(t, "70", cm.Data["latestTimestamp"])
}
