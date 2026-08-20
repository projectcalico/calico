package fv

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"

	//nolint:staticcheck // Ignore ST1001: should not use dot imports
	. "github.com/onsi/gomega"
	"google.golang.org/grpc"

	"github.com/projectcalico/calico/goldmane/pkg/client"
	"github.com/projectcalico/calico/lib/std/cryptoutils"
	jsontestutil "github.com/projectcalico/calico/lib/std/testutils/json"
	whiskerv1 "github.com/projectcalico/calico/whisker-backend/pkg/apis/v1"
	wconfig "github.com/projectcalico/calico/whisker-backend/pkg/config"
	goldmaneupstream "github.com/projectcalico/calico/whisker-backend/pkg/upstream/goldmane"
)

type ObjWithErr[T any] struct {
	Obj T
	Err error
}

// newGoldmaneFlowsBackend builds the Goldmane flows backend Run would wire
// itself, so tests can pass it via WithFlowsBackend — the enterprise
// newFlowsBackend requires an in-cluster Kubernetes environment for
// authentication.
func newGoldmaneFlowsBackend(cfg *wconfig.Config) whiskerv1.FlowsBackend {
	creds, err := client.ClientCredentials(cfg.TLSCertPath, cfg.TLSKeyPath, cfg.CACertPath)
	Expect(err).ShouldNot(HaveOccurred())

	gmCli, err := client.NewFlowsAPIClient(cfg.GoldmaneHost, grpc.WithTransportCredentials(creds))
	Expect(err).ShouldNot(HaveOccurred())

	return goldmaneupstream.NewBackend(gmCli)
}

func createKeyCertPair(dir string) (*os.File, *os.File) {
	certPEM, keyPEM, err := cryptoutils.GenerateSelfSignedCert(
		cryptoutils.WithDNSNames("localhost"),
		cryptoutils.WithExtKeyUsages(x509.ExtKeyUsageAny))
	Expect(err).ShouldNot(HaveOccurred())

	certFile, err := os.CreateTemp(dir, "cert.pem")
	Expect(err).ShouldNot(HaveOccurred())
	defer func() { _ = certFile.Close() }()

	keyFile, err := os.CreateTemp(dir, "key.pem")
	Expect(err).ShouldNot(HaveOccurred())
	defer func() { _ = keyFile.Close() }()

	_, err = certFile.Write(certPEM)
	Expect(err).ShouldNot(HaveOccurred())
	_, err = keyFile.Write(keyPEM)
	Expect(err).ShouldNot(HaveOccurred())

	return certFile, keyFile
}

// newHTTPSClient returns a client that trusts the certificate at the given path.
func newHTTPSClient(certPath string) *http.Client {
	certPEM, err := os.ReadFile(certPath)
	Expect(err).ShouldNot(HaveOccurred())

	rootCAs := x509.NewCertPool()
	Expect(rootCAs.AppendCertsFromPEM(certPEM)).Should(BeTrue())

	return &http.Client{
		Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: rootCAs}},
	}
}

// newSSEScanner creates a new scanner for reading "Server Side Events".
func newSSEScanner[E any](t *testing.T, r io.Reader) <-chan ObjWithErr[*E] {
	scanner := bufio.NewScanner(r)
	responseChan := make(chan ObjWithErr[*E])
	go func() {
		defer close(responseChan)
		for scanner.Scan() {
			line := scanner.Text()

			if after, ok := strings.CutPrefix(line, "data:"); ok {
				data := after
				fmt.Println("Event Data: ", strings.TrimSpace(data))

				responseChan <- ObjWithErr[*E]{Obj: jsontestutil.MustUnmarshal[E](t, []byte(data))}
			} else if line == "" {
				continue
			} else {
				responseChan <- ObjWithErr[*E]{Err: fmt.Errorf("unexpected line: %s", line)}
			}
		}
	}()

	return responseChan
}
