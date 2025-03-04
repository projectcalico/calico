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

package flowgen

import (
	"context"
	"math/rand/v2"
	"os"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/projectcalico/calico/goldmane/pkg/client"
	"github.com/projectcalico/calico/goldmane/proto"
)

func Start() {
	logrus.Info("Starting flow generator")
	defer func() {
		logrus.Info("Stopping flow generator")
	}()

	// Create a flow client.
	server := "127.0.0.1"
	if s := os.Getenv("SERVER"); s != "" {
		server = s
	}
	logrus.WithField("server", server).Info("Connecting to server")
	flowClient := client.NewFlowClient(server)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Create a gRPC client conn.
	cc, err := grpc.NewClient(server, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		logrus.WithError(err).Fatal("Failed to dial server")
	}
	go flowClient.Run(ctx, cc)

	// Create a new test gen.
	gen := &flowGenerator{
		flogsByIndex: make(map[int]*proto.Flow),
		outChan:      make(chan *proto.Flow, 10000),
	}

	// Start a goroutine to generate flows.
	go gen.generateFlogs()

	// Send new logs as they are generated.
	for flog := range gen.outChan {
		flowClient.Push(flog)
	}
}

// flowGenerator implements a basic FlowLogAPI implementation for testing and developing purposes.
type flowGenerator struct {
	sync.Mutex
	flogsByIndex map[int]*proto.Flow
	outChan      chan *proto.Flow
}

func (t *flowGenerator) generateFlogs() {
	srcNames := map[int]string{
		0: "client-aggr-1",
		1: "client-aggr-2",
		2: "client-aggr-3",
		3: "client-aggr-4",
	}
	dstNames := map[int]string{
		0: "server-aggr-1",
		1: "server-aggr-2",
		2: "server-aggr-3",
		3: "server-aggr-4",
	}
	actions := map[int]proto.Action{
		0: proto.Action_Allow,
		1: proto.Action_Deny,
	}
	reporters := map[int]proto.Reporter{
		0: proto.Reporter_Src,
		1: proto.Reporter_Dst,
	}
	services := map[int]string{
		0: "frontend-service",
		1: "backend-service",
		2: "db-service",
	}

	// Periodically add flows to the server for testing, incrementing the index each time.
	index := 0
	for {
		// Use a 15 second aggregation interval for each flow.
		startTime := time.Now()
		endTime := time.Now().Add(15 * time.Second)

		wait := time.After(15 * time.Second)

		// Generate Several flows during this interval.
		num := rand.IntN(30)
		for i := 0; i < num; i++ {
			t.Lock()
			// Use some randomness to simulate different flows.
			t.outChan <- &proto.Flow{
				Key: &proto.FlowKey{
					Proto:                "TCP",
					SourceName:           randomFrommap(srcNames),
					SourceNamespace:      "default",
					SourceType:           proto.EndpointType_WorkloadEndpoint,
					DestName:             randomFrommap(dstNames),
					DestNamespace:        "default",
					DestType:             proto.EndpointType_WorkloadEndpoint,
					DestServiceName:      randomFrommap(services),
					DestServicePort:      443,
					DestServicePortName:  "https",
					DestServiceNamespace: "default",
					Reporter:             randomFrommap(reporters),
					Action:               randomFrommap(actions),
				},
				StartTime:  int64(startTime.Unix()),
				EndTime:    int64(endTime.Unix()),
				BytesIn:    int64(rand.IntN(1000)),
				BytesOut:   int64(rand.IntN(1000)),
				PacketsIn:  int64(rand.IntN(100)),
				PacketsOut: int64(rand.IntN(100)),
			}
			index++
			t.Unlock()
			wait := 13 * time.Second / time.Duration(num)
			time.Sleep(wait)
		}

		<-wait

	}
}

func randomFrommap[E any](m map[int]E) E {
	// Generate a random number within the size of the map.
	return m[rand.IntN(len(m))]
}
