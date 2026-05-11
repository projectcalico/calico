// Copyright (c) 2018-2026 Tigera, Inc. All rights reserved.
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

package dikastes

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

	authz "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	"github.com/sirupsen/logrus"
	"google.golang.org/grpc"

	"github.com/projectcalico/calico/app-policy/checker"
	"github.com/projectcalico/calico/app-policy/health"
	"github.com/projectcalico/calico/app-policy/policystore"
	"github.com/projectcalico/calico/app-policy/proto"
	"github.com/projectcalico/calico/app-policy/syncher"
	"github.com/projectcalico/calico/app-policy/uds"
)

const (
	DefaultListenPath = "/var/run/dikastes/dikastes.sock"
	DefaultDialTarget = "localhost:50051"
)

// RunServer starts the dikastes authorization server. It listens on the given Unix domain
// socket path, syncs policy from the given dial target, and blocks until a signal is received.
func RunServer(listenPath, dialTarget string) {
	_, err := os.Stat(listenPath)
	if !os.IsNotExist(err) {
		if err := os.Remove(listenPath); err != nil {
			logrus.WithFields(logrus.Fields{
				"listen": listenPath,
			}).WithError(err).Fatal("File exists and unable to remove.")
		}
	}
	lis, err := net.Listen("unix", listenPath)
	if err != nil {
		logrus.WithFields(logrus.Fields{
			"listen": listenPath,
		}).WithError(err).Fatal("Unable to listen.")
	}
	defer func() { _ = lis.Close() }()
	if err := os.Chmod(listenPath, 0o777); err != nil {
		logrus.WithError(err).Fatal("Unable to set write permission on socket.")
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	gs := grpc.NewServer()
	storeManager := policystore.NewPolicyStoreManager()
	NewCheckServer(ctx, gs, storeManager)

	opts := uds.GetDialOptions()
	syncClient := syncher.NewClient(dialTarget, storeManager, opts)

	proto.RegisterHealthzServer(gs, health.NewHealthCheckService(syncClient))

	go syncClient.Sync(ctx)

	go func() {
		if err := gs.Serve(lis); err != nil {
			logrus.WithError(err).Fatal("Failed to serve")
		}
	}()

	th := HTTPTerminationHandler{TermChan: make(chan bool, 1)}
	if httpServerPort := os.Getenv("DIKASTES_HTTP_BIND_PORT"); httpServerPort != "" {
		httpServerAddr := os.Getenv("DIKASTES_HTTP_BIND_ADDR")
		if httpServer, httpServerWg, err := th.RunHTTPServer(httpServerAddr, httpServerPort); err == nil {
			defer httpServerWg.Wait()
			defer func() {
				ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				defer cancel()
				if err = httpServer.Shutdown(ctx); err != nil {
					logrus.WithError(err).Fatal("Error while shutting down HTTP server")
				}
			}()
		} else {
			logrus.WithError(err).Fatal("Failed to start HTTP server")
		}
	}

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	select {
	case sig := <-sigChan:
		logrus.Infof("Got signal: %v", sig)
	case <-th.TermChan:
		logrus.Info("Received HTTP termination request")
	}

	gs.GracefulStop()
}

// RunClient sends a test authorization check to the dikastes server.
func RunClient(dialTarget, namespace, account, method string) {
	opts := uds.GetDialOptions()
	conn, err := grpc.NewClient(dialTarget, opts...)
	if err != nil {
		logrus.WithError(err).Fatal("Failed to dial")
	}
	defer func() { _ = conn.Close() }()
	client := authz.NewAuthorizationClient(conn)
	req := authz.CheckRequest{
		Attributes: &authz.AttributeContext{
			Source: &authz.AttributeContext_Peer{
				Principal: fmt.Sprintf("spiffe://cluster.local/ns/%s/sa/%s", namespace, account),
			},
		},
	}
	if method != "" {
		req.Attributes.Request = &authz.AttributeContext_Request{
			Http: &authz.AttributeContext_HttpRequest{
				Method: method,
			},
		}
	}
	resp, err := client.Check(context.Background(), &req)
	if err != nil {
		logrus.WithError(err).Fatal("Check failed")
	}
	logrus.Infof("Check response:\n %v", resp)
}

// NewCheckServer creates the ext_authz check server with the default set of check providers
// and registers it on the given gRPC server.
func NewCheckServer(ctx context.Context, gs *grpc.Server, storeManager policystore.PolicyStoreManager) {
	checkServer := checker.NewServer(ctx, storeManager,
		checker.WithRegisteredCheckProvider(checker.NewALPCheckProvider()),
	)
	checkServer.RegisterGRPCServices(gs)
}

// HTTPTerminationHandler listens for HTTP termination requests and signals on its channel.
type HTTPTerminationHandler struct {
	TermChan chan bool
}

func (h *HTTPTerminationHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.TermChan <- true
	if _, err := io.WriteString(w, "terminating Dikastes\n"); err != nil {
		logrus.WithError(err).Fatal("Error writing HTTP response")
	}
}

// RunHTTPServer starts an HTTP server on the given address and port for termination requests.
func (h *HTTPTerminationHandler) RunHTTPServer(addr string, port string) (*http.Server, *sync.WaitGroup, error) {
	if i, err := strconv.Atoi(port); err != nil {
		return nil, nil, fmt.Errorf("error parsing provided HTTP listen port: %w", err)
	} else if i < 1 {
		return nil, nil, fmt.Errorf("please provide non-zero, non-negative port number for HTTP listening port")
	}

	if addr != "" {
		if ip := net.ParseIP(addr); ip == nil {
			return nil, nil, fmt.Errorf("invalid HTTP bind address %q", addr)
		}
	}

	httpServerSockAddr := net.JoinHostPort(addr, port)
	httpServerMux := http.NewServeMux()
	httpServerMux.Handle("/terminate", h)
	httpServer := &http.Server{Addr: httpServerSockAddr, Handler: httpServerMux}
	httpServerWg := &sync.WaitGroup{}

	httpServerWg.Go(func() {
		logrus.Infof("starting HTTP server on %v", httpServer.Addr)
		if err := httpServer.ListenAndServe(); err != http.ErrServerClosed {
			logrus.WithError(err).Fatal("HTTP server closed unexpectedly")
		}
	})
	return httpServer, httpServerWg, nil
}
