// Copyright (c) 2019-2026 Tigera, Inc. All rights reserved.
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

package healthz

import (
	"context"
	"fmt"
	"os"

	"github.com/sirupsen/logrus"
	"google.golang.org/grpc"

	dikastesproto "github.com/projectcalico/calico/app-policy/proto"
	"github.com/projectcalico/calico/app-policy/uds"
)

const DefaultDialPath = "/var/run/dikastes/dikastes.sock"

// Run performs a health check against the dikastes gRPC service. The check argument
// must be "liveness" or "readiness". Exits with code 1 for invalid arguments, 2 for
// gRPC errors, 3 for unhealthy status, and 0 for healthy.
func Run(dialPath, check string) {
	opts := uds.GetDialOptions()
	conn, err := grpc.NewClient(dialPath, opts...)
	if err != nil {
		logrus.WithError(err).Fatal("Failed to dial")
	}
	defer func() { _ = conn.Close() }()
	c := dikastesproto.NewHealthzClient(conn)

	var resp *dikastesproto.HealthCheckResponse
	switch check {
	case "liveness":
		resp, err = c.CheckLiveness(context.Background(), &dikastesproto.HealthCheckRequest{})
	case "readiness":
		resp, err = c.CheckReadiness(context.Background(), &dikastesproto.HealthCheckRequest{})
	default:
		fmt.Fprintf(os.Stderr, "Invalid check type %q, expected \"liveness\" or \"readiness\"\n", check)
		os.Exit(1)
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "Error getting healthz %s: %s\n", check, err)
		os.Exit(2)
	}
	if !resp.Healthy {
		fmt.Fprintf(os.Stderr, "healthz endpoint returned unhealthy\n")
		os.Exit(3)
	}
}
