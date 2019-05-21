// Copyright (c) 2018-2019 Tigera, Inc. All rights reserved.

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
	"fmt"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/projectcalico/app-policy/checker"
	"github.com/projectcalico/app-policy/health"
	"github.com/projectcalico/app-policy/policystore"
	"github.com/projectcalico/app-policy/proto"
	"github.com/projectcalico/app-policy/syncher"
	"github.com/projectcalico/app-policy/uds"

	"github.com/docopt/docopt-go"
	authz "github.com/envoyproxy/data-plane-api/envoy/service/auth/v2"
	authzv2alpha "github.com/envoyproxy/data-plane-api/envoy/service/auth/v2alpha"
	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc"
)

const usage = `Dikastes - the decider.

Usage:
  dikastes server [options]
  dikastes client <namespace> <account> [--method <method>] [options]

Options:
  <namespace>            Service account namespace.
  <account>              Service account name.
  -h --help              Show this screen.
  -l --listen <port>     Unix domain socket path [default: /var/run/dikastes/dikastes.sock]
  -d --dial <target>     Target to dial. [default: localhost:50051]
  --debug                Log at Debug level.`

var VERSION string

const NODE_NAME_ENV = "K8S_NODENAME"

func main() {
	arguments, err := docopt.Parse(usage, nil, true, VERSION, false)
	if err != nil {
		println(usage)
		return
	}
	if arguments["--debug"].(bool) {
		log.SetLevel(log.DebugLevel)
	}
	if arguments["server"].(bool) {
		runServer(arguments)
	} else if arguments["client"].(bool) {
		runClient(arguments)
	}
	return
}

func runServer(arguments map[string]interface{}) {
	filePath := arguments["--listen"].(string)
	dial := arguments["--dial"].(string)
	_, err := os.Stat(filePath)
	if !os.IsNotExist(err) {
		// file exists, try to delete it.
		err := os.Remove(filePath)
		if err != nil {
			log.WithFields(log.Fields{
				"listen": filePath,
				"err":    err,
			}).Fatal("File exists and unable to remove.")
		}
	}
	lis, err := net.Listen("unix", filePath)
	if err != nil {
		log.WithFields(log.Fields{
			"listen": filePath,
			"err":    err,
		}).Fatal("Unable to listen.")
	}
	defer lis.Close()
	err = os.Chmod(filePath, 0777) // Anyone on system can connect.
	if err != nil {
		log.Fatal("Unable to set write permission on socket.")
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Check server
	gs := grpc.NewServer()
	stores := make(chan *policystore.PolicyStore)
	checkServer := checker.NewServer(ctx, stores)
	authz.RegisterAuthorizationServer(gs, checkServer)
	authzv2alpha.RegisterAuthorizationServer(gs, checkServer)

	// Synchronize the policy store
	opts := uds.GetDialOptions()
	syncClient := syncher.NewClient(dial, opts)

	// Register the health check service, which reports the syncClient's inSync status.
	proto.RegisterHealthzServer(gs, health.NewHealthCheckService(syncClient))

	go syncClient.Sync(ctx, stores)

	// Run gRPC server on separate goroutine so we catch any signals and clean up.
	go func() {
		if err := gs.Serve(lis); err != nil {
			log.Fatalf("failed to serve: %v", err)
		}
	}()

	// Use a buffered channel so we don't miss any signals
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, os.Kill, syscall.SIGTERM)

	// Block until a signal is received.
	log.Infof("Got signal: %v", <-c)
}

func runClient(arguments map[string]interface{}) {
	dial := arguments["--dial"].(string)
	namespace := arguments["<namespace>"].(string)
	account := arguments["<account>"].(string)
	useMethod := arguments["--method"].(bool)
	method := arguments["<method>"].(string)

	opts := uds.GetDialOptions()
	conn, err := grpc.Dial(dial, opts...)
	if err != nil {
		log.Fatalf("fail to dial: %v", err)
	}
	defer conn.Close()
	client := authz.NewAuthorizationClient(conn)
	req := authz.CheckRequest{
		Attributes: &authz.AttributeContext{
			Source: &authz.AttributeContext_Peer{
				Principal: fmt.Sprintf("spiffe://cluster.local/ns/%s/sa/%s",
					namespace, account),
			},
		},
	}
	if useMethod {
		req.Attributes.Request = &authz.AttributeContext_Request{
			Http: &authz.AttributeContext_HttpRequest{
				Method: method,
			},
		}
	}
	resp, err := client.Check(context.Background(), &req)
	if err != nil {
		log.Fatalf("Failed %v", err)
	}
	log.Infof("Check response:\n %v", resp)
	return
}
