// Copyright (c) 2026 Tigera, Inc. All rights reserved.

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

package emitter

import (
	"bytes"
	"encoding/json"
	"fmt"
	"testing"
	"unique"

	"github.com/projectcalico/calico/goldmane/pkg/storage"
	"github.com/projectcalico/calico/goldmane/pkg/types"
	"github.com/projectcalico/calico/goldmane/proto"
)

func buildFlowCollection(n int) *storage.FlowCollection {
	fc := storage.NewFlowCollection(100, 200)
	for i := range n {
		f := types.Flow{
			Key: types.NewFlowKey(
				&types.FlowKeySource{
					SourceName:      fmt.Sprintf("src-%d", i),
					SourceNamespace: "default",
					SourceType:      proto.EndpointType_WorkloadEndpoint,
				},
				&types.FlowKeyDestination{
					DestName:      fmt.Sprintf("dst-%d", i),
					DestNamespace: "default",
					DestType:      proto.EndpointType_WorkloadEndpoint,
					DestPort:      8080,
				},
				&types.FlowKeyMeta{
					Proto:    "TCP",
					Reporter: proto.Reporter_Src,
					Action:   proto.Action_Allow,
				},
				&proto.PolicyTrace{},
			),
			StartTime:             100,
			EndTime:               200,
			SourceLabels:          unique.Make("app=frontend,env=prod,team=platform"),
			DestLabels:            unique.Make("app=backend,env=prod,team=platform"),
			PacketsIn:             100,
			PacketsOut:            200,
			BytesIn:               10000,
			BytesOut:              20000,
			NumConnectionsStarted: 5,
		}
		fc.AddFlow(f)
	}
	return fc
}

// collectionToReaderOld is the original implementation using []byte{} with repeated append.
func collectionToReaderOld(bucket *storage.FlowCollection) (*bytes.Reader, error) {
	body := []byte{}
	for _, flow := range bucket.Flows {
		if len(body) != 0 {
			body = append(body, []byte("\n")...)
		}
		f := types.FlowToProto(&flow)
		flowJSON, err := json.Marshal(f)
		if err != nil {
			return nil, fmt.Errorf("error marshalling flow: %w", err)
		}
		body = append(body, flowJSON...)
	}
	return bytes.NewReader(body), nil
}

// collectionToReaderNew is the new implementation using a pre-sized bytes.Buffer.
func collectionToReaderNew(bucket *storage.FlowCollection) (*bytes.Reader, error) {
	buf := bytes.NewBuffer(make([]byte, 0, len(bucket.Flows)*512))
	for i, flow := range bucket.Flows {
		if i > 0 {
			buf.WriteByte('\n')
		}
		f := types.FlowToProto(&flow)
		flowJSON, err := json.Marshal(f)
		if err != nil {
			return nil, fmt.Errorf("error marshalling flow: %w", err)
		}
		buf.Write(flowJSON)
	}
	return bytes.NewReader(buf.Bytes()), nil
}

func BenchmarkCollectionToReader(b *testing.B) {
	for _, n := range []int{10, 100, 500} {
		fc := buildFlowCollection(n)

		b.Run(fmt.Sprintf("old/%d_flows", n), func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				if _, err := collectionToReaderOld(fc); err != nil {
					b.Fatal(err)
				}
			}
		})

		b.Run(fmt.Sprintf("new/%d_flows", n), func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				if _, err := collectionToReaderNew(fc); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
