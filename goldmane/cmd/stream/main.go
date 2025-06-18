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

package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"

	"github.com/sirupsen/logrus"
	"google.golang.org/grpc"

	"github.com/projectcalico/calico/goldmane/pkg/client"
	"github.com/projectcalico/calico/goldmane/proto"
)

var (
	clientCert = "./tls.crt"
	clientKey  = "./tls.key"
	clientCA   = "./ca.crt"

	// The endpoint to connect to. This relies on /etc/hosts or DNS resolution resolving this name
	// correctly, so that TLS certificate verification passes.
	endpoint = "goldmane:7443"
)

var startTime int64

func init() {
	flag.Int64Var(&startTime, "start", 0, "Start time to use for the stream")
}

// main is an entrypoint for the stream client utility application, which is helpful for debugging. It initiates a stream
// connection with Goldmane and prints the received flows to stdout.
func main() {
	flag.Parse()

	// Create a stream client.
	// Generate credentials for the Goldmane client.
	creds, err := client.ClientCredentials(clientCert, clientKey, clientCA)
	if err != nil {
		logrus.WithError(err).Fatal("Failed to create goldmane TLS credentials.")
	}

	// Create a client to interact with Flows.
	c, err := client.NewFlowsAPIClient(endpoint, grpc.WithTransportCredentials(creds))
	if err != nil {
		panic(err)
	}

	// Connect to the stream.
	stream, err := c.Stream(context.Background(), &proto.FlowStreamRequest{StartTimeGte: startTime})
	if err != nil {
		panic(err)
	}

	// Read from the stream.
	for {
		flow, err := stream.Recv()
		if err != nil {
			panic(err)
		}

		// Print the flow.
		j, err := json.MarshalIndent(flow, "", "  ")
		if err != nil {
			panic(err)
		}
		fmt.Println(string(j))
	}
}
