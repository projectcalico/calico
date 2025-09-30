// Copyright (c) 2023 Tigera, Inc. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package metricsserver

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/sirupsen/logrus"

	calicotls "github.com/projectcalico/calico/crypto/pkg/tls"
)

func ServePrometheusMetricsHTTP(host string, port int) {
	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.Handler())
	addr := fmt.Sprintf("[%v]:%v", host, port)

	for {
		logrus.WithFields(logrus.Fields{
			"host": host,
			"port": port,
		}).Info("Starting prometheus metrics endpoint")
		err := http.ListenAndServe(addr, mux)
		logrus.WithError(err).Error(
			"Prometheus http metrics endpoint failed, trying to restart it...")
		time.Sleep(1 * time.Second)
	}
}

// ServePrometheusMetricsHTTPS starts a secure Prometheus metrics server with dynamic TLS certificate reloading.
func ServePrometheusMetricsHTTPS(host string, port int, certFile, keyFile, clientAuthType, caFile string) error {
	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.Handler())
	addr := fmt.Sprintf("[%v]:%v", host, port)

	// Initial TLS config loading to catch errors early.
	tlsConfig, err := calicotls.NewMutualTLSConfig(certFile, keyFile, caFile)
	if err != nil {
		return fmt.Errorf("Failed to load initial TLS configuration: %v", err)
	}

	// Set the client authentication type if provided.
	authType, err := calicotls.StringToTLSClientAuthType(clientAuthType)
	if err != nil {
		return fmt.Errorf("Failed to convert ClientAuthType %v", err)
	}
	tlsConfig.ClientAuth = authType

	// Enable dynamic certificate reloading.
	tlsConfig.GetConfigForClient = func(*tls.ClientHelloInfo) (*tls.Config, error) {
		tlsConfig, err := calicotls.NewMutualTLSConfig(certFile, keyFile, caFile)
		if err != nil {
			logrus.WithError(err).Error("Failed to reload TLS configuration")
			return nil, err
		}
		// Set the client authentication type if provided.
		authType, err := calicotls.StringToTLSClientAuthType(clientAuthType)
		if err != nil {
			return nil, err
		}
		tlsConfig.ClientAuth = authType
		return tlsConfig, nil
	}

	server := &http.Server{
		Addr:      addr,
		TLSConfig: tlsConfig,
		Handler:   mux,
	}

	// Restart server on failure.
	for {
		logrus.WithFields(logrus.Fields{
			"host": host,
			"port": port,
		}).Info("Starting Prometheus metrics endpoint with TLS")

		err = server.ListenAndServeTLS("", "")
		if err != nil {
			logrus.WithError(err).Error("Prometheus https metrics endpoint failed, restarting...")
			time.Sleep(200 * time.Millisecond)
		}
	}
}
