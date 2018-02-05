// Copyright (c) 2018 Tigera, Inc. All rights reserved.

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
	"time"

	"github.com/projectcalico/app-policy/checker"
	"github.com/projectcalico/app-policy/policystore"
	"github.com/projectcalico/app-policy/syncher"

	docopt "github.com/docopt/docopt-go"
	authz "github.com/envoyproxy/data-plane-api/api/auth"
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
const version = "0.1"
const NODE_NAME_ENV = "K8S_NODENAME"

func main() {
	arguments, err := docopt.Parse(usage, nil, true, version, false)
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
	gs := grpc.NewServer()
	store := policystore.NewPolicyStore()
	checkServer := checker.NewServer(store)
	authz.RegisterAuthorizationServer(gs, checkServer)

	// Synchronize the policy store
	opts := getDialOptions()
	syncClient := syncher.NewClient(dial, opts)
	syncContext, cancelSync := context.WithCancel(context.Background())
	defer cancelSync()
	go syncClient.Sync(syncContext, store)

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
	log.Infof("Got signal:", <-c)
}

func runClient(arguments map[string]interface{}) {
	dial := arguments["--dial"].(string)
	namespace := arguments["<namespace>"].(string)
	account := arguments["<account>"].(string)
	useMethod := arguments["--method"].(bool)
	method := arguments["<method>"].(string)

	opts := getDialOptions()
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
			Http: &authz.AttributeContext_HTTPRequest{
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

func getDialer(proto string) func(string, time.Duration) (net.Conn, error) {
	return func(target string, timeout time.Duration) (net.Conn, error) {
		return net.DialTimeout(proto, target, timeout)
	}
}

func getDialOptions() []grpc.DialOption {
	return []grpc.DialOption{
		grpc.WithInsecure(),
		grpc.WithDialer(getDialer("unix"))}
}
