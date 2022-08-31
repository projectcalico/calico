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
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/projectcalico/calico/app-policy/checker"
	"github.com/projectcalico/calico/app-policy/health"
	"github.com/projectcalico/calico/app-policy/policystore"
	"github.com/projectcalico/calico/app-policy/proto"
	"github.com/projectcalico/calico/app-policy/syncher"
	"github.com/projectcalico/calico/app-policy/uds"
	"github.com/projectcalico/calico/libcalico-go/lib/seedrng"

	"github.com/docopt/docopt-go"
	authz_v2 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v2"
	authz_v2alpha "github.com/envoyproxy/go-control-plane/envoy/service/auth/v2alpha"
	authz "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
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

func main() {
	// Make sure the RNG is seeded.
	seedrng.EnsureSeeded()

	arguments, err := docopt.ParseArgs(usage, nil, VERSION)
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
	checkServerV2 := checkServer.V2Compat()
	authz_v2alpha.RegisterAuthorizationServer(gs, checkServerV2)
	authz_v2.RegisterAuthorizationServer(gs, checkServerV2)

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

	th := httpTerminationHandler{make(chan bool, 1)}
	if httpServerPort := os.Getenv("DIKASTES_HTTP_BIND_PORT"); httpServerPort != "" {
		httpServerAddr := os.Getenv("DIKASTES_HTTP_BIND_ADDR")
		if httpServer, httpServerWg, err := th.RunHTTPServer(httpServerAddr, httpServerPort); err == nil {
			defer httpServerWg.Wait()
			defer func() {
				ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				defer cancel()
				if err = httpServer.Shutdown(ctx); err != nil {
					log.Fatalf("error while shutting down HTTP server: %v", err)
				}
			}()
		} else {
			log.Fatal(err)
		}
	}

	// Use a buffered channel so we don't miss any signals
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	// Block until a signal is received.
	select {
	case sig := <-sigChan:
		log.Infof("Got signal: %v", sig)
	case <-th.termChan:
		log.Info("Received HTTP termination request")
	}

	gs.GracefulStop()
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
}

type httpTerminationHandler struct {
	termChan chan bool
}

func (h *httpTerminationHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.termChan <- true
	if _, err := io.WriteString(w, "terminating Dikastes\n"); err != nil {
		log.Fatalf("error writing HTTP response: %v", err)
	}
}

func (h *httpTerminationHandler) RunHTTPServer(addr string, port string) (*http.Server, *sync.WaitGroup, error) {
	if i, err := strconv.Atoi(port); err != nil {
		err = fmt.Errorf("error parsing provided HTTP listen port: %v", err)
		return nil, nil, err
	} else if i < 1 {
		err = fmt.Errorf("please provide non-zero, non-negative port number for HTTP listening port")
		return nil, nil, err
	}

	if addr != "" {
		if ip := net.ParseIP(addr); ip == nil {
			err := fmt.Errorf("invalid HTTP bind address \"%v\"", addr)
			return nil, nil, err
		}
	}

	httpServerSockAddr := fmt.Sprintf("%s:%s", addr, port)
	httpServerMux := http.NewServeMux()
	httpServerMux.Handle("/terminate", h)
	httpServer := &http.Server{Addr: httpServerSockAddr, Handler: httpServerMux}
	httpServerWg := &sync.WaitGroup{}
	httpServerWg.Add(1)

	go func() {
		defer httpServerWg.Done()
		log.Infof("starting HTTP server on %v", httpServer.Addr)
		if err := httpServer.ListenAndServe(); err != http.ErrServerClosed {
			log.Fatalf("HTTP server closed unexpectedly: %v", err)
		}
	}()
	return httpServer, httpServerWg, nil
}
