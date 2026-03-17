// Copyright (c) 2025-2026 Tigera, Inc. All rights reserved.

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

package emitter

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"sync"

	"github.com/sirupsen/logrus"

	calicotls "github.com/projectcalico/calico/crypto/pkg/tls"
	"github.com/projectcalico/calico/goldmane/pkg/internal/utils"
	"github.com/projectcalico/calico/lib/std/time"
)

const ContentTypeMultilineJSON = "application/x-ndjson"

func newHTTPClient(caCert, clientKey, clientCert, serverName string) (*http.Client, error) {
	// Create a new HTTP client.
	tlsConfig, err := calicotls.NewTLSConfig()
	if err != nil {
		return nil, fmt.Errorf("failed to create TLS Config: %w", err)
	}
	tlsConfig.ServerName = serverName
	if caCert != "" {
		caCertPool := x509.NewCertPool()
		caCert, err := os.ReadFile(caCert)
		if err != nil {
			return nil, fmt.Errorf("error reading CA file: %s", err)
		}
		ok := caCertPool.AppendCertsFromPEM(caCert)
		if !ok {
			return nil, fmt.Errorf("failed to parse root certificate")
		}
		tlsConfig.RootCAs = caCertPool
	}

	// Create a custom dialer so that we can configure a dial timeout.
	// If we can't connect to the server within 10 seconds, something is up.
	// Note: this is not the same as the request timeout, which is handled via the
	// provided context on a per-request basis.
	dialWithTimeout := func(network, addr string) (net.Conn, error) {
		return net.DialTimeout(network, addr, 10*time.Second)
	}
	httpTransport := &http.Transport{
		Dial:            dialWithTimeout,
		TLSClientConfig: tlsConfig,
	}

	if clientKey != "" && clientCert != "" {
		clientCert, err := tls.LoadX509KeyPair(clientCert, clientKey)
		if err != nil {
			return nil, fmt.Errorf("error load cert key pair for emitter client: %s", err)
		}
		httpTransport.TLSClientConfig.Certificates = []tls.Certificate{clientCert}
		logrus.Info("Using provided client certificates for mTLS")
	}
	return &http.Client{
		Transport: httpTransport,
	}, nil
}

func newEmitterClient(url, caCert, clientKey, clientCert, serverName string) (*emitterClient, error) {
	// Create an initial HTTP client, and a function to help encapsualte the reload logic.
	client, err := newHTTPClient(caCert, clientKey, clientCert, serverName)
	if err != nil {
		return nil, err
	}
	return &emitterClient{
		url:        url,
		client:     client,
		caCert:     caCert,
		clientKey:  clientKey,
		clientCert: clientCert,
		serverName: serverName,
	}, nil
}

// watchCerts starts goroutines to watch for certificate file changes and reload the HTTP client
// when they change. The goroutines exit when ctx is cancelled.
func (e *emitterClient) watchCerts(ctx context.Context) error {
	if e.caCert == "" && e.clientKey == "" && e.clientCert == "" {
		return nil
	}

	updChan := make(chan struct{}, 1)

	// Start a goroutine to read from the channel and update the client.
	go func() {
		for range updChan {
			logrus.Info("Reloading client after certificate change")
			client, err := newHTTPClient(e.caCert, e.clientKey, e.clientCert, e.serverName)
			if err != nil {
				logrus.WithError(err).Error("Failed to reload client after certificate change")
				continue
			}
			e.setClient(client)
		}
	}()

	// Start a goroutine to watch for changes to the CA cert file and feed
	// them into the update channel. When ctx is cancelled, the watcher exits
	// and closes updChan, which causes the reload goroutine above to exit.
	monitorFn, err := utils.WatchFilesFn(updChan, 30*time.Second, e.caCert, e.clientCert, e.clientKey)
	if err != nil {
		return fmt.Errorf("error setting up CA cert file watcher: %w", err)
	}
	go monitorFn(ctx)
	return nil
}

type emitterClient struct {
	// The mutex must be held when accessing the client.
	sync.Mutex
	client *http.Client

	url        string
	caCert     string
	clientKey  string
	clientCert string
	serverName string
}

func (e *emitterClient) setClient(client *http.Client) {
	e.Lock()
	defer e.Unlock()
	e.client = client
}

func (e *emitterClient) Post(body io.Reader) error {
	e.Lock()
	defer e.Unlock()

	resp, err := e.client.Post(e.url, ContentTypeMultilineJSON, body)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status code: %s", resp.Status)
	}
	logrus.WithField("body", resp.Body).Debug("Successfully posted flows")
	return nil
}
