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
	"bufio"
	"crypto/x509"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	. "github.com/onsi/gomega"

	"github.com/projectcalico/calico/goldmane/pkg/client"
	gmdaemon "github.com/projectcalico/calico/goldmane/pkg/daemon"
	"github.com/projectcalico/calico/goldmane/proto"
	"github.com/projectcalico/calico/lib/std/chanutil"
	"github.com/projectcalico/calico/lib/std/cryptoutils"
	jsontestutil "github.com/projectcalico/calico/lib/std/testutils/json"
	"github.com/projectcalico/calico/whisker-backend/cmd/app"
	whiskerv1 "github.com/projectcalico/calico/whisker-backend/pkg/apis/v1"
	wconfig "github.com/projectcalico/calico/whisker-backend/pkg/config"
)

func TestGoldmaneIntegration(t *testing.T) {
	ctx, teardown := setup(t)
	defer teardown()

	// Generate a self-signed certificate for Goldmane.
	tmpDir := os.TempDir()
	certPEM, keyPEM, err := cryptoutils.GenerateSelfSignedCert(
		cryptoutils.WithDNSNames("localhost"),
		cryptoutils.WithExtKeyUsages(x509.ExtKeyUsageAny))
	Expect(err).ShouldNot(HaveOccurred())

	certFile, err := os.CreateTemp(tmpDir, "cert.pem")
	Expect(err).ShouldNot(HaveOccurred())
	defer certFile.Close()

	keyFile, err := os.CreateTemp(tmpDir, "key.pem")
	Expect(err).ShouldNot(HaveOccurred())
	defer keyFile.Close()

	_, err = certFile.Write(certPEM)
	Expect(err).ShouldNot(HaveOccurred())
	_, err = keyFile.Write(keyPEM)
	Expect(err).ShouldNot(HaveOccurred())

	// Generate a self-signed certificate for Whisker and the client to use.
	certPEM, keyPEM, err = cryptoutils.GenerateSelfSignedCert(
		cryptoutils.WithDNSNames("localhost"),
		cryptoutils.WithExtKeyUsages(x509.ExtKeyUsageAny))
	Expect(err).ShouldNot(HaveOccurred())

	clientCertFile, err := os.CreateTemp(tmpDir, "whisker-cert.pem")
	Expect(err).ShouldNot(HaveOccurred())
	defer certFile.Close()

	clientKeyFile, err := os.CreateTemp(tmpDir, "whisker-key.pem")
	Expect(err).ShouldNot(HaveOccurred())
	defer keyFile.Close()

	_, err = clientCertFile.Write(certPEM)
	Expect(err).ShouldNot(HaveOccurred())

	_, err = clientKeyFile.Write(keyPEM)
	Expect(err).ShouldNot(HaveOccurred())

	cfg := gmdaemon.Config{
		LogLevel:          "debug",
		Port:              5444,
		AggregationWindow: time.Second * 5,
		ServerCertPath:    certFile.Name(),
		ServerKeyPath:     keyFile.Name(),
		CACertPath:        clientCertFile.Name(),
	}

	go gmdaemon.Run(ctx, cfg)

	whiskerCfg := &wconfig.Config{
		Port:         "8080",
		LogLevel:     "debug",
		GoldmaneHost: "localhost:5444",
		CACertPath:   certFile.Name(),
		TLSCertPath:  clientCertFile.Name(),
		TLSKeyPath:   clientKeyFile.Name(),
	}
	whiskerCfg.ConfigureLogging()

	go app.Run(ctx, whiskerCfg)

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

type ObjWithErr[T any] struct {
	Obj T
	Err error
}

// newSSEScanner creates a new scanner for reading "Server Side Events".
func newSSEScanner[E any](t *testing.T, r io.Reader) <-chan ObjWithErr[*E] {
	scanner := bufio.NewScanner(r)
	responseChan := make(chan ObjWithErr[*E])
	go func() {
		defer close(responseChan)
		for scanner.Scan() {
			line := scanner.Text()

			if strings.HasPrefix(line, "data:") {
				data := strings.TrimPrefix(line, "data:")
				fmt.Println("Event Data: ", strings.TrimSpace(data))

				responseChan <- ObjWithErr[*E]{Obj: jsontestutil.MustUnmarshal[E](t, []byte(data))}
			} else {
				responseChan <- ObjWithErr[*E]{Err: fmt.Errorf("unexpected line: %s", line)}
			}
		}
	}()

	return responseChan
}
