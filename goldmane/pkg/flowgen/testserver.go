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
	"fmt"
	"math/rand/v2"
	"os"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
	goproto "google.golang.org/protobuf/proto"

	"github.com/projectcalico/calico/goldmane/pkg/client"
	"github.com/projectcalico/calico/goldmane/pkg/types"
	"github.com/projectcalico/calico/goldmane/proto"
)

const (
	// number of flows to generate per 15s interval.
	flowsPerInterval = 300

	// Configuration for flow generation. We need to balance this - too much generation
	// can overwhelm a single client and backpressure will be applied. Scaling horizontally
	// allows us to generate more load, simulating multiple nodes sending expedited flow data.
	//
	// In a production system, nodes won't attempt to send an entire hour's worth of flow data at once,
	// but we want to do so here to burden Goldmane.
	numNodes       = 30
	flowsPerWorker = flowsPerInterval / numNodes
	numWorkers     = numNodes

	// configuration for random flow generation.
	numClients    = 100
	numServers    = 100
	numNamespaces = 4
	numLabels     = 5
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

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Create a new test gen.
	gen := newFlowGenerator()

	// Send new logs as they are generated across a fleet of virtual nodes.
	for range numNodes {
		// Create the flow client, and wait for it to connect.
		c, err := client.NewFlowClient(
			server,
			os.Getenv("CLIENT_CERT"),
			os.Getenv("CLIENT_KEY"),
			os.Getenv("CA_FILE"),
		)
		if err != nil {
			logrus.WithError(err).Fatal("Failed to dial server")
		}
		<-c.Connect(ctx)

		// Start a goroutine to push logs to the server.
		go func(flowClient *client.FlowClient) {
			for flog := range gen.outChan {
				flowClient.PushWait(types.ProtoToFlow(flog))
			}
			flowClient.Close()
		}(c)
	}

	// Start a goroutine to generate flows.
	go gen.generateFlogs()

	// Wait for the context to be canceled.
	<-ctx.Done()
}

func newFlowGenerator() *flowGenerator {
	return &flowGenerator{
		outChan: make(chan *proto.Flow, 10000),

		flowsPerInterval: flowsPerInterval,
		numClients:       numClients,
		numServers:       numServers,
		numNamespaces:    numNamespaces,
		numLabels:        numLabels,
	}
}

// flowGenerator implements a basic FlowLogAPI implementation for testing and developing purposes.
type flowGenerator struct {
	sync.Mutex
	outChan chan *proto.Flow

	flowsPerInterval int
	numClients       int
	numServers       int
	numNamespaces    int
	numLabels        int
}

func (t *flowGenerator) generateFlogs() {
	// Split the work of generating flows across multiple workers, each generating a subset of the total number of flows.
	logrus.WithFields(logrus.Fields{
		"numWorkers":     numWorkers,
		"flowsPerWorker": flowsPerWorker,
	}).Info("Starting flow generation workers")
	for range numWorkers {
		go t.flowGenWorker(flowsPerWorker)
	}
}

func (t *flowGenerator) flowGenWorker(numPairs int) {
	// Start by backfilling a full hour of flows. Typically, flow data is largely consistent over time, so
	// we will start by building some flow pairs and then sending those same flows every 15s until the end of the hour.
	startTime := time.Now().UTC().Add(-45 * time.Minute)
	endTime := startTime.Add(15 * time.Second)

	flowPairs := [][]*proto.Flow{}
	for range numPairs {
		flows, err := t.randomFlows(startTime.Unix(), endTime.Unix())
		if err != nil {
			logrus.WithError(err).Fatal("Failed to generate flows")
		}
		flowPairs = append(flowPairs, flows)
	}

	logrus.Info("Backfilling an hour of flow data")
	for {
		logrus.WithFields(logrus.Fields{
			"start": startTime,
			"end":   endTime,
		}).Info("Filling bucket")
		for _, pair := range flowPairs {
			for _, flog := range pair {
				flog.StartTime = startTime.Unix()
				flog.EndTime = endTime.Unix()
				t.outChan <- flog
				time.Sleep(5 * time.Millisecond)
			}
		}

		// Update start and end times.
		startTime = endTime
		endTime = endTime.Add(15 * time.Second)

		if endTime.After(time.Now().UTC()) {
			break
		}
	}
	logrus.Info("Backfill complete")

	// At this point, we've backfilled all of Goldmane's in-memory storage with a full hour of flow data.
	// We can now start generating new flows every 15s.
	logrus.Info("Starting to generate new flows")
	for {
		endTime = time.Now().UTC()
		startTime = endTime.Add(-15 * time.Second)

		for _, pair := range flowPairs {
			for _, flog := range pair {
				flog.StartTime = startTime.Unix()
				flog.EndTime = endTime.Unix()
				t.outChan <- flog
			}
		}

		time.Sleep(15 * time.Second)
	}
}

func (t *flowGenerator) randomFlows(s, e int64) ([]*proto.Flow, error) {
	srcNames := map[int]string{}
	srcLabelsMap := map[string][]string{}
	for i := range t.numClients {
		name := fmt.Sprintf("client-%d", i)
		srcNames[i] = name

		l := []string{}
		for j := range t.numLabels {
			l = append(l, fmt.Sprintf("label-key-%d = label-value-%d", j, j))
		}
		srcLabelsMap[name] = l
	}

	dstNames := map[int]string{}
	dstLabelsMap := map[string][]string{}
	for i := range t.numServers {
		name := fmt.Sprintf("server-%d", i)
		dstNames[i] = name

		l := []string{}
		for j := range t.numLabels {
			l = append(l, fmt.Sprintf("label-key-%d = label-value-%d", j, j))
		}
		dstLabelsMap[name] = l
	}

	namespaces := map[int]string{}
	for i := range t.numNamespaces {
		namespaces[i] = fmt.Sprintf("namespace-%d", i)
	}

	actions := map[int]proto.Action{
		0: proto.Action_Allow,
		1: proto.Action_Deny,
	}

	protos := map[int]string{
		0: "TCP",
		1: "UDP",
		2: "ICMP",
	}

	// Use some randomness to simulate different flows. For each flow, we generate both a record
	// for both the Source and Destination reporter.
	dstNs := randomFrommap(namespaces)
	srcNs := randomFrommap(namespaces)
	srcName := randomFrommap(srcNames)
	dstName := randomFrommap(dstNames)
	srcLabels := srcLabelsMap[srcName]
	dstLabels := dstLabelsMap[dstName]
	action := randomFrommap(actions)

	enf := []*proto.PolicyHit{
		{
			Name:        "policy-1",
			Namespace:   srcNs,
			Kind:        proto.PolicyKind_NetworkPolicy,
			Tier:        "mytier",
			Action:      action,
			PolicyIndex: 0,
			RuleIndex:   1,
		},
	}
	pen := []*proto.PolicyHit{
		{
			Name:        "pending-policy-0",
			Namespace:   "",
			Kind:        proto.PolicyKind_GlobalNetworkPolicy,
			Tier:        "pending-tier",
			Action:      action,
			PolicyIndex: 0,
			RuleIndex:   1,
		},
	}

	srcFlow := proto.Flow{
		Key: &proto.FlowKey{
			Proto:                randomFrommap(protos),
			SourceName:           srcName,
			SourceNamespace:      srcNs,
			SourceType:           proto.EndpointType_WorkloadEndpoint,
			DestName:             dstName,
			DestNamespace:        dstNs,
			DestType:             proto.EndpointType_WorkloadEndpoint,
			DestServiceName:      randomFrommap(dstNames),
			DestServicePort:      443,
			DestServicePortName:  "https",
			DestServiceNamespace: dstNs,
			Reporter:             proto.Reporter_Src,
			Action:               action,
			Policies: &proto.PolicyTrace{
				EnforcedPolicies: enf,
				PendingPolicies:  pen,
			},
		},
		StartTime:               int64(s),
		EndTime:                 int64(e),
		SourceLabels:            srcLabels,
		DestLabels:              dstLabels,
		BytesIn:                 int64(rand.IntN(1000)),
		BytesOut:                int64(rand.IntN(1000)),
		PacketsIn:               int64(rand.IntN(100)),
		PacketsOut:              int64(rand.IntN(100)),
		NumConnectionsStarted:   int64(rand.IntN(10)),
		NumConnectionsLive:      int64(rand.IntN(10)),
		NumConnectionsCompleted: int64(rand.IntN(10)),
	}

	dstFlow := goproto.Clone(&srcFlow).(*proto.Flow)
	dstFlow.Key.Reporter = proto.Reporter_Dst

	return []*proto.Flow{&srcFlow, dstFlow}, nil
}

func randomFrommap[E any](m map[int]E) E {
	// Generate a random number within the size of the map.
	return m[rand.IntN(len(m))]
}
