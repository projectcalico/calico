// Copyright (c) 2025 Tigera, Inc. All rights reserved.
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
	"time"

	. "github.com/onsi/gomega"
	"github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/goldmane/pkg/client"
	gmdaemon "github.com/projectcalico/calico/goldmane/pkg/daemon"
	"github.com/projectcalico/calico/goldmane/proto"
	"github.com/projectcalico/calico/lib/httpmachinery/pkg/apiutil"
	"github.com/projectcalico/calico/lib/std/chanutil"
	jsontestutil "github.com/projectcalico/calico/lib/std/testutils/json"
	"github.com/projectcalico/calico/whisker-backend/cmd/app"
	whiskerv1 "github.com/projectcalico/calico/whisker-backend/pkg/apis/v1"
	wconfig "github.com/projectcalico/calico/whisker-backend/pkg/config"
)

// This is a simple integration test to ensure that whisker and goldmane interact correctly for streaming flows.
func TestGoldmaneIntegration_FlowWatching(t *testing.T) {
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
	certFile, keyFile := createKeyCertPair(tmpDir)
	defer certFile.Close()
	defer keyFile.Close()

	// Generate a self-signed certificate for Whisker and the client to use.
	clientCertFile, clientKeyFile := createKeyCertPair(tmpDir)
	defer certFile.Close()
	defer keyFile.Close()

	cfg := gmdaemon.Config{
		LogLevel:          "debug",
		Port:              5444,
		AggregationWindow: time.Second * 5,
		ServerCertPath:    certFile.Name(),
		ServerKeyPath:     keyFile.Name(),
		CACertPath:        clientCertFile.Name(),
	}

	wg.Add(1)
	go func() {
		defer wg.Done()
		gmdaemon.Run(ctx, cfg)
	}()

	whiskerCfg := &wconfig.Config{
		Port:         "8080",
		LogLevel:     "debug",
		GoldmaneHost: "localhost:5444",
		CACertPath:   certFile.Name(),
		TLSCertPath:  clientCertFile.Name(),
		TLSKeyPath:   clientKeyFile.Name(),
	}
	whiskerCfg.ConfigureLogging()
	wg.Add(1)
	go func() {
		defer wg.Done()
		app.Run(ctx, whiskerCfg)
	}()

	cli, err := client.NewFlowClient("localhost:5444", clientCertFile.Name(), clientKeyFile.Name(), certFile.Name())
	Expect(err).ShouldNot(HaveOccurred())

	// Wait for initial connection
	_, err = chanutil.ReadWithDeadline(ctx, cli.Connect(ctx), time.Minute*20)
	Expect(err).Should(Equal(chanutil.ErrChannelClosed))

	req, err := http.NewRequest(http.MethodGet, "http://localhost:8080/flows", nil)
	Expect(err).ShouldNot(HaveOccurred())

	query := req.URL.Query()
	query.Set("filters", jsontestutil.MustMarshal(t, whiskerv1.Filters{
		SourceNames: whiskerv1.FilterMatches[string]{{V: "test-source-2"}},
	}))
	query.Set("watch", "true")
	req.URL.RawQuery = query.Encode()
	req.Header.Set("Accept", "text/event-stream")

	resp, err := http.DefaultClient.Do(req)

	Expect(err).ShouldNot(HaveOccurred())

	go func() {
		<-ctx.Done()
		resp.Body.Close()
	}()

	Expect(resp.StatusCode).Should(Equal(http.StatusOK))

	scanner := newSSEScanner[whiskerv1.FlowResponse](t, resp.Body)

	cli.Push(&proto.Flow{
		Key: &proto.FlowKey{
			SourceName:      "test-source-2",
			SourceNamespace: "test-namespace-3",
			Action:          proto.Action_Deny,
		},
		StartTime: time.Now().Add(-1 * time.Second).Unix(),
		EndTime:   time.Now().Unix(),
	})

	obj, err := chanutil.ReadWithDeadline(ctx, scanner, time.Second*30)
	Expect(err).ShouldNot(HaveOccurred())

	Expect(obj.Err).ShouldNot(HaveOccurred())
	Expect(obj.Obj.Action).Should(Equal(whiskerv1.Action(proto.Action_Deny)))
}

// This is a simple integration test to ensure whisker and goldmane interact correctly for getting filter hints.
func TestGoldmaneIntegration_FilterHints(t *testing.T) {
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
	certFile, keyFile := createKeyCertPair(tmpDir)
	defer certFile.Close()
	defer keyFile.Close()

	// Generate a self-signed certificate for Whisker and the client to use.
	clientCertFile, clientKeyFile := createKeyCertPair(tmpDir)
	defer certFile.Close()
	defer keyFile.Close()

	cfg := gmdaemon.Config{
		LogLevel:          "debug",
		Port:              5444,
		AggregationWindow: time.Second * 5,
		ServerCertPath:    certFile.Name(),
		ServerKeyPath:     keyFile.Name(),
		CACertPath:        clientCertFile.Name(),
	}

	wg.Add(1)
	go func() {
		defer wg.Done()
		gmdaemon.Run(ctx, cfg)
	}()

	whiskerCfg := &wconfig.Config{
		Port:         "8080",
		LogLevel:     "debug",
		GoldmaneHost: "localhost:5444",
		CACertPath:   certFile.Name(),
		TLSCertPath:  clientCertFile.Name(),
		TLSKeyPath:   clientKeyFile.Name(),
	}
	whiskerCfg.ConfigureLogging()

	wg.Add(1)
	go func() {
		defer wg.Done()
		app.Run(ctx, whiskerCfg)
	}()

	cli, err := client.NewFlowClient("localhost:5444", clientCertFile.Name(), clientKeyFile.Name(), certFile.Name())
	Expect(err).ShouldNot(HaveOccurred())

	// Wait for initial connection
	_, err = chanutil.ReadWithDeadline(ctx, cli.Connect(ctx), time.Minute*20)
	Expect(err).Should(Equal(chanutil.ErrChannelClosed))

	cli.Push(&proto.Flow{
		Key: &proto.FlowKey{
			SourceName:      "test-source-2",
			SourceNamespace: "test-namespace-3",
			Action:          proto.Action_Deny,
		},
		StartTime: time.Now().Add(-1 * time.Second).Unix(),
		EndTime:   time.Now().Unix(),
	})

	cli.Push(&proto.Flow{
		Key: &proto.FlowKey{
			SourceName:      "test-source-3",
			SourceNamespace: "test-namespace-3",
			Action:          proto.Action_Deny,
		},
		StartTime: time.Now().Add(-1 * time.Second).Unix(),
		EndTime:   time.Now().Unix(),
	})

	cli.Push(&proto.Flow{
		Key: &proto.FlowKey{
			SourceName:      "test-source-3",
			SourceNamespace: "test-namespace-4",
			Action:          proto.Action_Deny,
		},
		StartTime: time.Now().Add(-1 * time.Second).Unix(),
		EndTime:   time.Now().Unix(),
	})

	req, err := http.NewRequest(http.MethodGet, fmt.Sprintf("http://localhost:8080/%s", whiskerv1.FlowsFilterHintsPath), nil)
	Expect(err).ShouldNot(HaveOccurred())

	query := req.URL.Query()
	query.Set("type", "SourceName")
	query.Set("filters", jsontestutil.MustMarshal(t, whiskerv1.Filters{
		SourceNamespaces: whiskerv1.FilterMatches[string]{{V: "test-namespace", Type: whiskerv1.MatchType(proto.MatchType_Fuzzy)}},
	}))
	req.URL.RawQuery = query.Encode()

	time.Sleep(time.Second * 5)

	resp, err := http.DefaultClient.Do(req)
	Expect(err).ShouldNot(HaveOccurred())
	defer resp.Body.Close()
	byts, err := io.ReadAll(resp.Body)
	Expect(err).ShouldNot(HaveOccurred())
	Expect(resp.StatusCode).Should(Equal(http.StatusOK), string(byts))

	hints := jsontestutil.MustUnmarshal[apiutil.List[whiskerv1.FlowFilterHintResponse]](t, byts)
	Expect(hints.Items).Should(Equal([]whiskerv1.FlowFilterHintResponse{
		{Value: "test-source-2"},
		{Value: "test-source-3"},
	}))
}
