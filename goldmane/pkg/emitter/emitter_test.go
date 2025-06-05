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
	"sync"
	"testing"
	"unique"

	"github.com/stretchr/testify/require"
	goproto "google.golang.org/protobuf/proto"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ktypes "k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/projectcalico/calico/goldmane/pkg/emitter"
	"github.com/projectcalico/calico/goldmane/pkg/internal/utils"
	"github.com/projectcalico/calico/goldmane/pkg/storage"
	"github.com/projectcalico/calico/goldmane/pkg/types"
	"github.com/projectcalico/calico/goldmane/proto"
	"github.com/projectcalico/calico/lib/std/time"
	"github.com/projectcalico/calico/libcalico-go/lib/logutils"
)

var emt *emitter.Emitter

var configMapKey = ktypes.NamespacedName{Name: "flow-emitter-state", Namespace: "calico-system"}

func setupTest(t *testing.T, opts ...emitter.Option) func() {
	// Hook logrus into testing.T
	utils.ConfigureLogging("DEBUG")
	logCancel := logutils.RedirectLogrusToTestingT(t)

	// Run the emitter.
	ctx, cancel := context.WithCancel(context.Background())
	emt = emitter.NewEmitter(opts...)
	go emt.Run(ctx)

	return func() {
		cancel()
		emt = nil
		logCancel()
	}
}

func TestEmitterMainline(t *testing.T) {
	// Create a flow to send.
	flow := types.Flow{
		Key: types.NewFlowKey(
			&types.FlowKeySource{
				SourceName:      "test-src",
				SourceNamespace: "test-ns",
				SourceType:      proto.EndpointType_WorkloadEndpoint,
			},
			&types.FlowKeyDestination{
				DestName:      "test-dst",
				DestNamespace: "test-dst-ns",
				DestType:      proto.EndpointType_WorkloadEndpoint,
			},
			&types.FlowKeyMeta{
				Proto:  "tcp",
				Action: proto.Action_Allow,
			},
			&proto.PolicyTrace{
				EnforcedPolicies: []*proto.PolicyHit{
					{
						Kind:        proto.PolicyKind_NetworkPolicy,
						Name:        "cluster-dns",
						Namespace:   "kube-system",
						Tier:        "test-tier",
						Action:      proto.Action_Allow,
						PolicyIndex: 0,
						RuleIndex:   1,
					},
				},
				PendingPolicies: []*proto.PolicyHit{
					{
						Kind:        proto.PolicyKind_NetworkPolicy,
						Name:        "cluster-dns-staged",
						Namespace:   "kube-system",
						Tier:        "test-tier-staged",
						Action:      proto.Action_Deny,
						PolicyIndex: 0,
						RuleIndex:   1,
					},
				},
			},
		),
		StartTime:             18,
		EndTime:               28,
		SourceLabels:          unique.Make("src=label"),
		DestLabels:            unique.Make("dst=label"),
		BytesIn:               100,
		BytesOut:              200,
		PacketsIn:             10,
		PacketsOut:            20,
		NumConnectionsStarted: 1,
	}
	expectedBody, err := json.Marshal(types.FlowToProto(&flow))
	require.NoError(t, err)

	// Creat a mock HTTP server to use as our sink.
	numBucketsEmitted := 0
	mu := sync.Mutex{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()

		// Verify the request.
		require.Equal(t, "/path/to/flows", r.URL.Path)
		require.Equal(t, "POST", r.Method)

		// Read the body and assert it matches the expected flow.
		buf := new(bytes.Buffer)
		_, err := buf.ReadFrom(r.Body)
		require.NoError(t, err)
		require.Equal(t, buf.String(), string(expectedBody))
		w.WriteHeader(http.StatusOK)

		// Verify we can unpack into a proto struct.
		rp := &proto.Flow{}
		err = json.Unmarshal(buf.Bytes(), rp)
		require.NoError(t, err)
		require.True(t, goproto.Equal(rp, types.FlowToProto(&flow)), "Received flow didn't match")

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
	b := storage.NewFlowCollection(15, 30)
	b.AddFlow(flow)
	emt.Receive(b)

	// Wait for the emitter to process the bucket. It should emit the flow to the mock server.
	require.Eventually(t, func() bool {
		mu.Lock()
		defer mu.Unlock()
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
		Key: types.NewFlowKey(
			&types.FlowKeySource{
				SourceName:      "test-src",
				SourceNamespace: "test-ns",
			},
			&types.FlowKeyDestination{
				DestName:      "test-dst",
				DestNamespace: "test-dst-ns",
			},
			&types.FlowKeyMeta{
				Proto: "tcp",
			},
			&proto.PolicyTrace{
				EnforcedPolicies: []*proto.PolicyHit{
					{
						Kind:        proto.PolicyKind_NetworkPolicy,
						Name:        "cluster-dns",
						Namespace:   "kube-system",
						Tier:        "test-tier",
						Action:      proto.Action_Allow,
						PolicyIndex: 0,
						RuleIndex:   1,
					},
				},
				PendingPolicies: []*proto.PolicyHit{
					{
						Kind:        proto.PolicyKind_NetworkPolicy,
						Name:        "cluster-dns-staged",
						Namespace:   "kube-system",
						Tier:        "test-tier-staged",
						Action:      proto.Action_Deny,
						PolicyIndex: 0,
						RuleIndex:   1,
					},
				},
			},
		),
		StartTime:             18,
		EndTime:               28,
		SourceLabels:          unique.Make("src=label"),
		DestLabels:            unique.Make("dst=label"),
		BytesIn:               100,
		BytesOut:              200,
		PacketsIn:             10,
		PacketsOut:            20,
		NumConnectionsStarted: 1,
	}
	expectedBody, err := json.Marshal(types.FlowToProto(&flow))
	require.NoError(t, err)

	// Creat a mock HTTP server to use as our sink.
	numBucketsEmitted := 0
	numRequests := 0

	// For this test, we configure the server to fail the first request with a 500 error
	// and then succeed on subsequent requests. This verifies that the emitter retries in the case
	// of a failure.
	mu := sync.Mutex{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()

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
	b := storage.NewFlowCollection(15, 30)
	b.AddFlow(flow)
	emt.Receive(b)

	// Wait for the emitter to process the bucket. It should emit the flow to the mock server.
	require.Eventually(t, func() bool {
		mu.Lock()
		defer mu.Unlock()
		return numRequests >= 2
	}, 5*time.Second, 500*time.Millisecond, "Didn't retry the request?")
	require.Eventually(t, func() bool {
		mu.Lock()
		defer mu.Unlock()
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
		Key: types.NewFlowKey(
			&types.FlowKeySource{
				SourceName:      "test-src",
				SourceNamespace: "test-ns",
			},
			&types.FlowKeyDestination{
				DestName:      "test-dst",
				DestNamespace: "test-dst-ns",
			},
			&types.FlowKeyMeta{
				Proto: "tcp",
			},
			&proto.PolicyTrace{},
		),
		StartTime:             18,
		EndTime:               28,
		SourceLabels:          unique.Make("src=label"),
		DestLabels:            unique.Make("dst=label"),
		BytesIn:               100,
		BytesOut:              200,
		PacketsIn:             10,
		PacketsOut:            20,
		NumConnectionsStarted: 1,
	}
	flowOK := types.Flow{
		Key: types.NewFlowKey(
			&types.FlowKeySource{
				SourceName:      "test-src",
				SourceNamespace: "test-ns",
			},
			&types.FlowKeyDestination{
				DestName:      "test-dst",
				DestNamespace: "test-dst-ns",
			},
			&types.FlowKeyMeta{
				Proto: "tcp",
			},
			&proto.PolicyTrace{
				EnforcedPolicies: []*proto.PolicyHit{
					{
						Kind:        proto.PolicyKind_NetworkPolicy,
						Name:        "cluster-dns",
						Namespace:   "kube-system",
						Tier:        "test-tier",
						Action:      proto.Action_Allow,
						PolicyIndex: 0,
						RuleIndex:   1,
					},
				},
				PendingPolicies: []*proto.PolicyHit{
					{
						Kind:        proto.PolicyKind_NetworkPolicy,
						Name:        "cluster-dns-staged",
						Namespace:   "kube-system",
						Tier:        "test-tier-staged",
						Action:      proto.Action_Deny,
						PolicyIndex: 0,
						RuleIndex:   1,
					},
				},
			},
		),
		StartTime:             61,
		EndTime:               65,
		SourceLabels:          unique.Make("src=label"),
		DestLabels:            unique.Make("dst=label"),
		BytesIn:               100,
		BytesOut:              200,
		PacketsIn:             10,
		PacketsOut:            20,
		NumConnectionsStarted: 1,
	}
	unexpectedBody, err := json.Marshal(types.FlowToProto(&flow))
	require.NoError(t, err)
	okBody, err := json.Marshal(types.FlowToProto(&flowOK))
	require.NoError(t, err)

	// Creat a mock HTTP server to use as our sink. We don't expect any requests to be made.
	numBucketsEmitted := 0
	mu := sync.Mutex{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()

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
	b := storage.NewFlowCollection(15, 30)
	b.AddFlow(flow)
	emt.Receive(b)

	// The emitter should skip emitting the bucket, and the flow should not be sent to the server.
	// Wait a couple of seconds to confirm.
	time.Sleep(2 * time.Second)

	// The timestamp should not be updated.
	err = kcli.Get(context.Background(), configMapKey, cm)
	require.NoError(t, err)
	require.Equal(t, "45", cm.Data["latestTimestamp"])

	// Send a new bucket that is after the latest timestamp. This one should be sent.
	bOK := storage.NewFlowCollection(60, 70)
	bOK.AddFlow(flowOK)
	emt.Receive(bOK)

	// Expect the flow to be sent to the server.
	require.Eventually(t, func() bool {
		mu.Lock()
		defer mu.Unlock()
		return numBucketsEmitted == 1
	}, 5*time.Second, 500*time.Millisecond)

	// The timestamp should be updated.
	err = kcli.Get(context.Background(), configMapKey, cm)
	require.NoError(t, err)
	require.Equal(t, "70", cm.Data["latestTimestamp"])
}
