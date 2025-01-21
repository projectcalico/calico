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
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/sirupsen/logrus"
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
	client, err := newHTTPClient(caCert, clientKey, clientCert, serverName)
	if err != nil {
		return nil, err
	}
	return &emitterClient{url: url, client: client}, nil
}

type emitterClient struct {
	url    string
	client *http.Client
}

func (e *emitterClient) Post(body io.Reader) error {
	resp, err := e.client.Post(e.url, ContentTypeMultilineJSON, body)
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
