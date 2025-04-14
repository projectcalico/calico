package fv

import (
	"context"
	"crypto/x509"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"sync"
	"testing"
	"time"

	. "github.com/onsi/gomega"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"

	"github.com/projectcalico/calico/goldmane/pkg/client"
	"github.com/projectcalico/calico/goldmane/pkg/daemon"
	"github.com/projectcalico/calico/goldmane/pkg/testutils"
	"github.com/projectcalico/calico/goldmane/pkg/types"
	"github.com/projectcalico/calico/goldmane/proto"
	"github.com/projectcalico/calico/lib/std/cryptoutils"
	"github.com/projectcalico/calico/libcalico-go/lib/logutils"
)

var (
	ctx         context.Context
	goldmaneURL string
	clientCA    string
	clientCert  string
	clientKey   string

	emitted *emissionCounter
)

func daemonSetup(t *testing.T, cfg daemon.Config) func() {
	RegisterTestingT(t)
	logrus.SetLevel(logrus.DebugLevel)
	logutils.ConfigureFormatter("daemonfv")
	logCancel := logutils.RedirectLogrusToTestingT(t)

	// The context acts as a global timeout for the test to make sure we don't hang.
	var cancel context.CancelFunc
	ctx, cancel = context.WithTimeout(context.Background(), 30*time.Second)

	// Create TLS credentials for Goldmane.
	cert, key := createKeyCertPair(os.TempDir())

	// Create TLS credentials for the client.
	cliCert, cliKey := createKeyCertPair(os.TempDir())

	// Store the file paths for the client certificates.
	clientCA = cert.Name()
	clientKey = cliKey.Name()
	clientCert = cliCert.Name()

	// Augment the configuration with the paths to the certificates.
	cfg.ServerCertPath = cert.Name()
	cfg.ServerKeyPath = key.Name()
	cfg.CACertPath = cliCert.Name()

	// Start a test HTTP server that we can point the emitter at to verify
	// flows are being emitted.
	emitted = &emissionCounter{}
	testServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		logrus.WithField("path", r.URL.Path).Info("[TEST] Received request")
		emitted.Inc()
	}))
	cfg.PushURL = testServer.URL

	// Run the daemon.
	go daemon.Run(ctx, cfg)

	goldmaneURL = fmt.Sprintf("localhost:%d", cfg.Port)

	return func() {
		logCancel()
		cancel()
	}
}

type emissionCounter struct {
	sync.Mutex
	flows int
}

func (t *emissionCounter) Inc() {
	t.Lock()
	defer t.Unlock()
	t.flows++
}

func (t *emissionCounter) Count() int {
	t.Lock()
	defer t.Unlock()
	return t.flows
}

func createKeyCertPair(dir string) (*os.File, *os.File) {
	certPEM, keyPEM, err := cryptoutils.GenerateSelfSignedCert(
		cryptoutils.WithDNSNames("localhost"),
		cryptoutils.WithExtKeyUsages(x509.ExtKeyUsageAny),
	)
	Expect(err).ShouldNot(HaveOccurred())

	certFile, err := os.CreateTemp(dir, "cert.pem")
	Expect(err).ShouldNot(HaveOccurred())
	defer certFile.Close()

	keyFile, err := os.CreateTemp(dir, "key.pem")
	Expect(err).ShouldNot(HaveOccurred())
	defer keyFile.Close()

	_, err = certFile.Write(certPEM)
	Expect(err).ShouldNot(HaveOccurred())
	_, err = keyFile.Write(keyPEM)
	Expect(err).ShouldNot(HaveOccurred())

	return certFile, keyFile
}

// TestDaemonCanary acts as a baseline test to ensure we can start the daemon and connect to it.
// If this test fails, it likely means something fundamental is wrong.
func TestDaemonCanary(t *testing.T) {
	cfg := daemon.Config{
		LogLevel:                 "debug",
		Port:                     8988,
		AggregationWindow:        time.Second * 1,
		EmitAfterSeconds:         2,
		EmitterAggregationWindow: time.Second * 2,
	}
	defer daemonSetup(t, cfg)()

	// Generate credentials for the Goldmane client.
	creds, err := client.ClientCredentials(clientCert, clientKey, clientCA)
	if err != nil {
		logrus.WithError(err).Fatal("Failed to create goldmane TLS credentials.")
	}

	// Verify we can connect to the server.
	cli, err := client.NewFlowsAPIClient(goldmaneURL, grpc.WithTransportCredentials(creds))
	require.NoError(t, err)
	require.NotNil(t, cli)

	// Verify we can list flows.
	Eventually(func() error {
		_, _, err = cli.List(ctx, nil)
		return err
	}, 5*time.Second, 1*time.Second).Should(Succeed())
}

// TestFlows tests that we can ingest flows, that they show up in List reqeusts, and that they
// are emitted to the configured endpoint.
func TestFlows(t *testing.T) {
	cfg := daemon.Config{
		LogLevel:                 "debug",
		Port:                     8988,
		AggregationWindow:        time.Second * 1,
		EmitAfterSeconds:         2,
		EmitterAggregationWindow: time.Second * 2,
	}
	defer daemonSetup(t, cfg)()

	// Generate credentials for the Goldmane client.
	creds, err := client.ClientCredentials(clientCert, clientKey, clientCA)
	if err != nil {
		logrus.WithError(err).Fatal("Failed to create goldmane TLS credentials.")
	}

	// Create a client to interact with Flows.
	cli, err := client.NewFlowsAPIClient("localhost:8988", grpc.WithTransportCredentials(creds))
	require.NoError(t, err)
	require.NotNil(t, cli)

	// Create a client to pusher Flows.
	pusher, err := client.NewFlowClient(goldmaneURL, clientCert, clientKey, clientCA)
	require.NoError(t, err)

	connected := pusher.Connect(ctx)
	require.NoError(t, err)
	Eventually(connected, 5*time.Second, 100*time.Millisecond).Should(BeClosed())

	// Start a goroutine to continuously send flows.
	go func(ctx context.Context) {
		for {
			if ctx.Err() != nil {
				pusher.Close()
				return
			}
			f := testutils.NewRandomFlow(time.Now().Unix())
			pusher.Push(types.ProtoToFlow(f))
			time.Sleep(1 * time.Millisecond)
		}
	}(ctx)

	// Verify we can list flows.
	var flows []*proto.FlowResult
	Eventually(func() error {
		_, flows, err = cli.List(ctx, nil)
		if err != nil {
			return err
		}
		if len(flows) == 0 {
			return fmt.Errorf("no flows returned")
		}
		return nil
	}, 5*time.Second, 1*time.Second).Should(Succeed())

	// We should eventually see flows emitted.
	// Sincse we only emit after 2 seconds with an emitter aggregation window of 2 seconds, we
	// should see at least one flow emitted after 4 seconds. We'll wait for 10 seconds to be sure.
	Eventually(emitted.Count, 10*time.Second, 1*time.Second).Should(BeNumerically(">", 0))

	// We should be able to see flows emitted in the stream as well.
	streams := []proto.Flows_StreamClient{}
	for range 10 {
		s, err := cli.Stream(ctx, &proto.FlowStreamRequest{StartTimeGte: -300})
		require.NoError(t, err)
		streams = append(streams, s)
	}

	for _, s := range streams {
		for range 10 {
			// We should receive a flow.
			f, err := s.Recv()
			require.NoError(t, err)
			require.NotNil(t, f)
		}
	}
}

// TestHints tests that we can successfully retrieve hints from generated flows.
func TestHints(t *testing.T) {
	cfg := daemon.Config{
		LogLevel:                 "debug",
		Port:                     8988,
		AggregationWindow:        time.Second * 1,
		EmitAfterSeconds:         2,
		EmitterAggregationWindow: time.Second * 2,
	}
	defer daemonSetup(t, cfg)()

	// Generate credentials for the Goldmane client.
	creds, err := client.ClientCredentials(clientCert, clientKey, clientCA)
	if err != nil {
		logrus.WithError(err).Fatal("Failed to create goldmane TLS credentials.")
	}

	// Create a client to interact with Flows.
	cli, err := client.NewFlowsAPIClient("localhost:8988", grpc.WithTransportCredentials(creds))
	require.NoError(t, err)
	require.NotNil(t, cli)

	// Create a client to pusher Flows.
	pusher, err := client.NewFlowClient(goldmaneURL, clientCert, clientKey, clientCA)
	require.NoError(t, err)

	connected := pusher.Connect(ctx)
	require.NoError(t, err)
	Eventually(connected, 5*time.Second, 100*time.Millisecond).Should(BeClosed())

	// Start a goroutine to continuously send flows.
	go func(ctx context.Context) {
		for {
			if ctx.Err() != nil {
				pusher.Close()
				return
			}
			f := testutils.NewRandomFlow(time.Now().Unix())
			pusher.Push(types.ProtoToFlow(f))
			time.Sleep(100 * time.Millisecond)
		}
	}(ctx)

	// Verify we can list flows.
	var hints []*proto.FilterHint
	req := &proto.FilterHintsRequest{
		Type: proto.FilterType_FilterTypeDestNamespace,
	}
	Eventually(func() error {
		_, hints, err = cli.FilterHints(ctx, req)
		if err != nil {
			return err
		}
		if len(hints) == 0 {
			return fmt.Errorf("no hints returned")
		}
		return nil
	}, 5*time.Second, 1*time.Second).Should(Succeed())
}
