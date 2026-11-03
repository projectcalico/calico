// Copyright (c) 2026 Tigera, Inc. All rights reserved.
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

package utils

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net/http"
	"time"

	corev1 "k8s.io/api/core/v1"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"
)

// GatewayClient issues HTTPS requests to a Calico Ingress Gateway listener through a
// port-forward. The listener is SNI-scoped, so every request carries the gateway
// hostname as both the TLS server name and the Host header, and the cluster CA that
// signed the listener certificate is trusted.
type GatewayClient struct {
	hostname string
	client   *http.Client
}

// NewGatewayClient trusts the cluster CA bundle from backendNamespace and pins the
// gateway hostname for SNI and the Host header.
func NewGatewayClient(ctx context.Context, cli ctrlclient.Client, backendNamespace, hostname string) (*GatewayClient, error) {
	bundle := &corev1.ConfigMap{}
	if err := cli.Get(ctx, ctrlclient.ObjectKey{Namespace: backendNamespace, Name: "tigera-ca-bundle"}, bundle); err != nil {
		return nil, fmt.Errorf("failed to read tigera-ca-bundle: %w", err)
	}
	roots := x509.NewCertPool()
	appended := false
	for _, pem := range bundle.Data {
		if roots.AppendCertsFromPEM([]byte(pem)) {
			appended = true
		}
	}
	if !appended {
		return nil, fmt.Errorf("no CA certificates found in tigera-ca-bundle")
	}
	return &GatewayClient{
		hostname: hostname,
		client: &http.Client{
			Timeout: 10 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{RootCAs: roots, ServerName: hostname},
			},
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
	}, nil
}

// Get fetches url and returns the response body, status code and any error. url points at
// the local port-forward; the Host header is set to the gateway hostname so Envoy routes it.
func (g *GatewayClient) Get(url string) (string, int, error) {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return "", 0, err
	}
	req.Host = g.hostname

	resp, err := g.client.Do(req)
	if err != nil {
		return "", 0, err
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", resp.StatusCode, err
	}
	return string(body), resp.StatusCode, nil
}

// HTTPClient exposes the underlying client so WaitForPortForward can poll the listener
// with the same SNI and CA trust.
func (g *GatewayClient) HTTPClient() *http.Client { return g.client }
