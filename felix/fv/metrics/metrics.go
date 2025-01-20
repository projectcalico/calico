// Copyright (c) 2017-2025 Tigera, Inc. All rights reserved.
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

package metrics

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/typha/pkg/tlsutils"
)

func init() {
	http.DefaultClient.Timeout = 1 * time.Second
}

var Port = 9091

func PortString() string {
	return strconv.Itoa(Port)
}

func GetRawMetrics(ip string, port int, caFile, certFile, keyFile string) (out string, err error) {
	httpClient := http.Client{Timeout: time.Second}
	defer httpClient.CloseIdleConnections()
	method := "http"
	// Client setup for TLS.
	if certFile != "" {
		// Start with default HTTP transport.
		transport := http.Transport{
			Proxy: http.ProxyFromEnvironment,
			DialContext: (&net.Dialer{
				Timeout:   30 * time.Second,
				KeepAlive: 30 * time.Second,
			}).DialContext,
			ForceAttemptHTTP2:     true,
			MaxIdleConns:          100,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
		}
		// Add client's key/cert pair.
		cert, err := tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			log.WithError(err).Error("Failed to read cert/key files")
			return "", err
		}
		transport.TLSClientConfig = &tls.Config{
			Certificates: []tls.Certificate{cert},
		}
		// If caFile given, verify the server.
		if caFile != "" {
			// Set InsecureSkipVerify true, because when it's false crypto/tls insists
			// on verifying the server's hostname or IP address against
			// tlsConfig.ServerName, and we don't want that.  We will do certificate
			// chain verification ourselves inside CertificateVerifier.
			transport.TLSClientConfig.InsecureSkipVerify = true
			caPEMBlock, err := os.ReadFile(caFile)
			if err != nil {
				log.WithError(err).Error("Failed to read CA data")
				return "", err
			}
			transport.TLSClientConfig.RootCAs = x509.NewCertPool()
			ok := transport.TLSClientConfig.RootCAs.AppendCertsFromPEM(caPEMBlock)
			if !ok {
				log.Error("Failed to add CA data to pool")
				return "", errors.New("Failed to add CA data to pool")
			}
			transport.TLSClientConfig.VerifyPeerCertificate = tlsutils.CertificateVerifier(
				log.WithField("caFile", caFile),
				transport.TLSClientConfig.RootCAs,
				"",
				"",
			)
		} else {
			transport.TLSClientConfig.InsecureSkipVerify = true
		}
		httpClient.Transport = &transport
		method = "https"
	} else {
		// Use a dedicated transport to avoid sharing connections between attempts.
		httpClient.Transport = &http.Transport{}
	}
	var resp *http.Response
	resp, err = httpClient.Get(fmt.Sprintf("%v://%v:%v/metrics", method, ip, port))
	if err != nil {
		return
	}
	log.WithField("resp", resp).Debug("Metric response")
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		err = fmt.Errorf("Bad response (%v) from metrics server", resp.StatusCode)
		return
	}

	all, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	return string(all), nil
}

func GetMetric(ip string, port int, name, caFile, certFile, keyFile string) (metric string, err error) {
	metrics, err := GetRawMetrics(ip, port, caFile, certFile, keyFile)
	if err != nil {
		return "", fmt.Errorf("failed to load metrics: %w", err)
	}
	scanner := bufio.NewScanner(bytes.NewBufferString(metrics))
	found := false
	for scanner.Scan() {
		line := scanner.Text()
		log.WithField("line", line).Debug("Line")
		if strings.HasPrefix(line, name) {
			log.WithField("line", line).Info("Line")
			metric = strings.TrimSpace(strings.TrimPrefix(line, name))
			found = true
			break
		}
	}
	err = scanner.Err()
	if !found {
		return "", fmt.Errorf("metric %q not found in\n%s", name, metrics)
	}
	return
}

func GetFelixMetric(felixIP, name string) (metric string, err error) {
	metric, err = GetMetric(felixIP, Port, name, "", "", "")
	return
}

func GetFelixMetricInt(felixIP, name string) (metric int, err error) {
	s, err := GetFelixMetric(felixIP, name)
	if err != nil {
		return 0, err
	}
	return strconv.Atoi(s)
}

func GetFelixMetricIntFn(felixIP, name string) func() (metric int, err error) {
	return func() (metric int, err error) {
		return GetFelixMetricInt(felixIP, name)
	}
}

func GetFelixMetricFloat(felixIP, name string) (metric float64, err error) {
	s, err := GetFelixMetric(felixIP, name)
	if err != nil {
		return 0, err
	}
	return strconv.ParseFloat(s, 64)
}
