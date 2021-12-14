// Copyright (c) 2019 Tigera, Inc. All rights reserved.

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
	"flag"
	"fmt"
	"os"

	"github.com/projectcalico/calico/app-policy/proto"
	"github.com/projectcalico/calico/app-policy/uds"

	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc"
)

const DefaultDialPath = "/var/run/dikastes/dikastes.sock"

func main() {
	var dialPath string
	flag.StringVar(&dialPath, "dialPath", DefaultDialPath, "Path to health check gRPC service")
	flag.Parse()

	opts := uds.GetDialOptions()
	conn, err := grpc.Dial(dialPath, opts...)
	if err != nil {
		log.Fatalf("fail to dial: %v", err)
	}
	defer conn.Close()
	c := proto.NewHealthzClient(conn)
	if len(flag.Args()) == 0 {
		_, _ = fmt.Fprintf(os.Stderr, "Usage: %s (liveness|readiness)\n", os.Args[0])
		os.Exit(1)
	}

	var resp *proto.HealthCheckResponse
	switch flag.Arg(0) {
	case "liveness":
		resp, err = c.CheckLiveness(context.Background(), &proto.HealthCheckRequest{})
	case "readiness":
		resp, err = c.CheckReadiness(context.Background(), &proto.HealthCheckRequest{})
	default:
		_, _ = fmt.Fprintf(os.Stderr, "Usage: %s (liveness|readiness)\n", os.Args[0])
		os.Exit(1)
	}

	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "Error getting healthz %s: %s\n", flag.Arg(0), err)
		os.Exit(2)
	}
	if !resp.Healthy {
		_, _ = fmt.Fprintf(os.Stderr, "healthz endpoint returned unhealthy\n")
		os.Exit(3)
	}
}
