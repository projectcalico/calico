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

package fv

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"sync"
	"testing"

	. "github.com/onsi/gomega"
	"github.com/sirupsen/logrus"

	gmdaemon "github.com/projectcalico/calico/goldmane/pkg/daemon"
	"github.com/projectcalico/calico/lib/std/time"
	"github.com/projectcalico/calico/whisker-backend/cmd/whiskerbackend"
	whiskerv1 "github.com/projectcalico/calico/whisker-backend/pkg/apis/v1"
	wconfig "github.com/projectcalico/calico/whisker-backend/pkg/config"
)

// Verifies that whisker-backend serves HTTPS and rejects plain HTTP on the
// same port.
func TestServerTLS(t *testing.T) {
	var wg sync.WaitGroup
	defer func() {
		logrus.Info("Waiting for goroutines to finish...")
		wg.Wait()
		logrus.Info("Finished waiting for goroutines to finish.")
	}()

	ctx, teardown := setup(t)
	defer teardown()

	tmpDir := os.TempDir()

	// Generate a self-signed certificate for Goldmane.
	gmCertFile, gmKeyFile := createKeyCertPair(tmpDir)
	defer func() { _ = gmCertFile.Close() }()
	defer func() { _ = gmKeyFile.Close() }()

	// Generate a self-signed certificate for Whisker's Goldmane client mTLS.
	clientCertFile, clientKeyFile := createKeyCertPair(tmpDir)
	defer func() { _ = clientCertFile.Close() }()
	defer func() { _ = clientKeyFile.Close() }()

	// Generate a self-signed certificate for Whisker's HTTPS server.
	serverCertFile, serverKeyFile := createKeyCertPair(tmpDir)
	defer func() { _ = serverCertFile.Close() }()
	defer func() { _ = serverKeyFile.Close() }()

	gmCfg := gmdaemon.Config{
		LogLevel:          "debug",
		Port:              5445,
		AggregationWindow: time.Second * 5,
		ServerCertPath:    gmCertFile.Name(),
		ServerKeyPath:     gmKeyFile.Name(),
		CACertPath:        clientCertFile.Name(),
	}

	wg.Go(func() {
		gmdaemon.Run(ctx, gmCfg)
	})

	whiskerCfg := &wconfig.Config{
		Port:              "8090",
		LogLevel:          "debug",
		GoldmaneHost:      "localhost:5445",
		CACertPath:        gmCertFile.Name(),
		TLSCertPath:       clientCertFile.Name(),
		TLSKeyPath:        clientKeyFile.Name(),
		ServerTLSCertPath: serverCertFile.Name(),
		ServerTLSKeyPath:  serverKeyFile.Name(),
	}
	whiskerCfg.ConfigureLogging()

	wg.Go(func() {
		whiskerbackend.Run(ctx, whiskerCfg)
	})

	httpsClient := newHTTPSClient(serverCertFile.Name())

	url := fmt.Sprintf("https://localhost:8090/%s?type=SourceName", whiskerv1.FlowsFilterHintsPath)
	Eventually(func() error {
		resp, err := httpsClient.Get(url)
		if err != nil {
			return err
		}
		defer func() { _ = resp.Body.Close() }()
		body, _ := io.ReadAll(resp.Body)
		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("unexpected status %d: %s", resp.StatusCode, body)
		}
		return nil
	}, "30s", "1s").Should(Succeed(), "expected whisker-backend to serve HTTPS")

	// Plain HTTP on the TLS port is rejected by the server.
	resp, err := http.Get(fmt.Sprintf("http://localhost:8090/%s?type=SourceName", whiskerv1.FlowsFilterHintsPath))
	Expect(err).ShouldNot(HaveOccurred())
	defer func() { _ = resp.Body.Close() }()
	Expect(resp.StatusCode).Should(Equal(http.StatusBadRequest))
}
