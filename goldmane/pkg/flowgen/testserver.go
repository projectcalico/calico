package flowgen

import (
	"context"
	"os"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
	"golang.org/x/exp/rand"

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
	go flowClient.Run(ctx)

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
	actions := map[int]string{
		0: "allow",
		1: "deny",
	}
	reporters := map[int]string{
		0: "src",
		1: "dst",
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
		num := rand.Intn(30)
		for i := 0; i < num; i++ {
			t.Lock()
			// Use some randomness to simulate different flows.
			t.outChan <- &proto.Flow{
				Key: &proto.FlowKey{
					Proto:                "TCP",
					SourceName:           randomFrommap(srcNames),
					SourceNamespace:      "default",
					SourceType:           "wep",
					DestName:             randomFrommap(dstNames),
					DestNamespace:        "default",
					DestType:             "wep",
					DestServiceName:      randomFrommap(services),
					DestServicePort:      443,
					DestServicePortName:  "https",
					DestServiceNamespace: "default",
					Reporter:             randomFrommap(reporters),
					Action:               randomFrommap(actions),
				},
				StartTime:  int64(startTime.Unix()),
				EndTime:    int64(endTime.Unix()),
				BytesIn:    int64(rand.Intn(1000)),
				BytesOut:   int64(rand.Intn(1000)),
				PacketsIn:  int64(rand.Intn(100)),
				PacketsOut: int64(rand.Intn(100)),
			}
			index++
			t.Unlock()
			wait := 13 * time.Second / time.Duration(num)
			time.Sleep(wait)
		}

		<-wait

	}
}

func randomFrommap(m map[int]string) string {
	// Generate a random number within the size of the map.
	return m[rand.Intn(len(m))]
}
