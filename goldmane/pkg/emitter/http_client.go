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
	"time"

	"github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/goldmane/pkg/internal/utils"
	"github.com/projectcalico/calico/lib/std/chanutil"
)

const ContentTypeMultilineJSON = "application/x-ndjson"

func newHTTPClient(caCert, clientKey, clientCert, serverName string) (*http.Client, error) {
	// Create a new HTTP client.
	tlsConfig := &tls.Config{ServerName: serverName}
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

	// We only reload the client when we need to use it, but the file watcher may generate events at any time - sometimes
	// several in quick succession. To handle this, we use a small deduplicator goroutine to ensure we're servicing the
	// channel.
	updChan := make(chan struct{}, 1)
	reloadClient := make(chan struct{})
	go func() {
		defer logrus.Info("File watcher deduplicator closed")
		for range updChan {
			logrus.Info("Got certificate update, will adjust next request")
			_ = chanutil.WriteNonBlocking(reloadClient, struct{}{})
		}
	}()

	getClient := func() (*http.Client, error) {
		select {
		case _, ok := <-updChan:
			if ok {
				// Only reload the client if the channel is still open. If the filewatcher
				// has been closed, we'll just continue using the existing client as best-effort.
				logrus.Info("Reloading client after certificate change")
				client, err = newHTTPClient(caCert, clientKey, clientCert, serverName)
				if err != nil {
					return nil, fmt.Errorf("error reloading CA cert: %s", err)
				}
			} else {
				logrus.Warn("Ignoring certificate updates - file watcher closed")
			}
		default:
			// No change, return the existing client.
		}
		return client, nil
	}

	if caCert != "" || clientKey != "" || clientCert != "" {
		// Start a goroutine to watch for changes to the CA cert file and feed
		// them into the update channel.
		monitorFn, err := utils.WatchFilesFn(updChan, caCert, clientCert, clientKey)
		if err != nil {
			return nil, fmt.Errorf("error setting up CA cert file watcher: %s", err)
		}
		go monitorFn(context.Background())
	}

	return &emitterClient{
		url:       url,
		getClient: getClient,
	}, nil
}

type emitterClient struct {
	url       string
	getClient func() (*http.Client, error)
}

func (e *emitterClient) Post(body io.Reader) error {
	client, err := e.getClient()
	if err != nil {
		return err
	}
	resp, err := client.Post(e.url, ContentTypeMultilineJSON, body)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status code: %s", resp.Status)
	}
	logrus.WithField("body", resp.Body).Debug("Successfully posted flows")
	return nil
}
