package fv_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	. "github.com/onsi/gomega"
	"golang.org/x/net/http2"

	calicotls "github.com/projectcalico/calico/crypto/pkg/tls"
	"github.com/projectcalico/calico/guardian/pkg/bimux"
	"github.com/projectcalico/calico/guardian/pkg/config"
	"github.com/projectcalico/calico/guardian/pkg/daemon"
	"github.com/projectcalico/calico/guardian/pkg/server"
	"github.com/projectcalico/calico/lib/std/cryptoutils"
)

func init() {
	var err error
	http2Transport, err = http2.ConfigureTransports(http.DefaultTransport.(*http.Transport))
	if err != nil {
		panic(err)
	}
}

var http2Transport *http2.Transport

func upstreamTLSConfig(tlsCert tls.Certificate, ca cryptoutils.CA) *tls.Config {
	tlsCfg, err := calicotls.NewTLSConfig()
	Expect(err).ShouldNot(HaveOccurred())

	tlsCfg.ClientAuth = tls.RequireAndVerifyClientCert
	tlsCfg.ClientCAs = x509.NewCertPool()
	Expect(ca.AddToCertPool(tlsCfg.ClientCAs)).ShouldNot(HaveOccurred())

	tlsCfg.Certificates = []tls.Certificate{tlsCert}
	return tlsCfg
}

func startDaemon(ctx context.Context, clientCert *tls.Certificate, serverCA cryptoutils.CA, targets []server.Target) chan struct{} {
	cfg := config.Config{
		LogLevel:                "DEBUG",
		TunnelDialRetryAttempts: -1,
		TunnelDialRetryInterval: 100 * time.Millisecond,
		TunnelDialTimeout:       5 * time.Second,
		VoltronURL:              "localhost:8443",
		KeepAliveEnable:         true,
		KeepAliveInterval:       1000000,
	}

	cfg.SetTLSConfigProvider(tlsConfigProvider(*clientCert, serverCA))

	daemonDoneSig := make(chan struct{})
	go func() {
		defer close(daemonDoneSig)

		daemon.Run(ctx, cfg, targets)
	}()

	return daemonDoneSig
}

func TestRequestsFromUpstreamToDownstream(t *testing.T) {
	setup(t)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	testSrvAddr := "localhost:8999"
	startTestService(testSrvAddr)

	clientCA, clientCert := createTLSConfigTLSConfig()
	serverCA, serverCert := createTLSConfigTLSConfig()

	daemonDoneSig := startDaemon(ctx, clientCert, serverCA, []server.Target{
		{Path: "/", Dest: MustParseURL("https://" + testSrvAddr), AllowInsecureTLS: true},
	})

	authenticator := &connAuthenticator{}
	sessionListener, err := bimux.NewSessionListener(":8443", upstreamTLSConfig(*serverCert, clientCA), authenticator)
	Expect(err).ShouldNot(HaveOccurred())

	ch, err := sessionListener.Listen(ctx)
	Expect(err).ShouldNot(HaveOccurred())
	session := <-ch

	req, err := http.NewRequest(http.MethodGet, "https://"+testSrvAddr+"/foobar", nil)
	Expect(err).ShouldNot(HaveOccurred())

	resp, err := sendToMuxRequest(session, req)
	Expect(err).ShouldNot(HaveOccurred())
	Expect(resp.StatusCode).Should(Equal(http.StatusOK))
	defer resp.Body.Close()

	var rspObj testServerResponse
	Expect(json.NewDecoder(resp.Body).Decode(&rspObj)).ShouldNot(HaveOccurred())
	Expect(rspObj.Message).Should(Equal("hello from the other side."))

	// Close the mux and allow guardian to try to reconnect, as we want to test that we can still use the tunnel after
	// reconnecting.
	t.Log("test that the guardian continuously tries to reconnect to the upstream server when the connection is closed")
	authenticator.rejectConnections = true   // Reject all connection requests from guardian
	authenticator.connectionRequestCount = 0 // Reset the request connect
	_ = session.Close()

	// Wait for guardian to try connecting at least 5 times to ensure the reconnection logic retries frequently based on
	// the configuration. The interval is set to 100 ms, so it should take any longer than 5 seconds for 5 attempts.
	Eventually(func() int { return authenticator.connectionRequestCount }, "5s").Should(BeNumerically(">=", 5))

	// Allow guardian to reconnect to the upstream server.
	authenticator.rejectConnections = false

	// Send a request to the upstream server and ensure it works after reconnecting.
	req, err = http.NewRequest(http.MethodGet, "https://localhost:8999/foobar", nil)
	Expect(err).ShouldNot(HaveOccurred())

	session = <-ch
	Expect(session).ShouldNot(BeNil())
	resp, err = sendToMuxRequest(session, req)
	Expect(err).ShouldNot(HaveOccurred())
	Expect(resp.StatusCode).Should(Equal(http.StatusOK))

	defer resp.Body.Close()

	rspObj = testServerResponse{}
	Expect(json.NewDecoder(resp.Body).Decode(&rspObj)).ShouldNot(HaveOccurred())
	Expect(rspObj.Message).Should(Equal("hello from the other side."))

	cancel()
	<-sessionListener.WaitForShutdown()
	<-daemonDoneSig
}

func TestRequestsFromDownstreamToUpstream(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	setup(t)

	clientCA, clientCert := createTLSConfigTLSConfig()
	serverCA, serverCert := createTLSConfigTLSConfig()

	daemonDoneSig := startDaemon(ctx, clientCert, serverCA, []server.Target{})

	tlsCfg := upstreamTLSConfig(*serverCert, clientCA)

	listener, err := bimux.NewDefaultSessionListener(":8443", tlsCfg)
	Expect(err).ShouldNot(HaveOccurred())

	sessionCh, err := listener.Listen(ctx)
	Expect(err).ShouldNot(HaveOccurred())

	session := <-sessionCh

	srv := http.Server{
		Addr: "localhost:9090",
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(testServerResponse{Message: "hello from the other side."})
		}),
	}
	go func() {
		_ = srv.Serve(session)
	}()

	cli := &http.Client{
		Transport: &http.Transport{TLSClientConfig: tlsCfg},
	}

	req, err := http.NewRequest(http.MethodGet, "http://localhost:9090/foobar", nil)
	Expect(err).ShouldNot(HaveOccurred())

	rspObj := sendRequest(cli, req)
	Expect(rspObj.Message).Should(Equal("hello from the other side."))

	cancel()
	<-daemonDoneSig
	<-listener.WaitForShutdown()
}

func sendRequest(cli *http.Client, req *http.Request) testServerResponse {
	resp, err := cli.Do(req)
	Expect(err).ShouldNot(HaveOccurred())
	defer resp.Body.Close()

	rspObj := testServerResponse{}
	Expect(json.NewDecoder(resp.Body).Decode(&rspObj)).ShouldNot(HaveOccurred())
	return rspObj
}

type testServerResponse struct {
	Message string `json:"message"`
}

func startTestService(addr string) {
	ca, err := cryptoutils.NewCA("test")
	Expect(err).ShouldNot(HaveOccurred())

	tlsCert, err := ca.CreateTLSCertificate("test-cert",
		cryptoutils.WithDNSNames("localhost"),
		cryptoutils.WithExtKeyUsages(x509.ExtKeyUsageAny),
	)
	Expect(err).ShouldNot(HaveOccurred())

	go func() {
		mux := http.NewServeMux()
		mux.HandleFunc("/foobar", func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(testServerResponse{Message: "hello from the other side."})
		})

		srv := http.Server{
			Addr:      addr,
			Handler:   mux,
			TLSConfig: &tls.Config{Certificates: []tls.Certificate{*tlsCert}},
		}

		if err := srv.ListenAndServeTLS("", ""); err != nil {
			panic(err)
		}
	}()
}

func createTLSConfigTLSConfig() (cryptoutils.CA, *tls.Certificate) {
	ca, err := cryptoutils.NewCA("ca-signer", cryptoutils.WithDNSNames("localhost"))
	Expect(err).ShouldNot(HaveOccurred())

	certificate, err := ca.CreateTLSCertificate("test-managed-cluster",
		cryptoutils.WithDNSNames("localhost"),
		cryptoutils.WithKeyUsages(x509.KeyUsageKeyEncipherment, x509.KeyUsageDigitalSignature),
		cryptoutils.WithExtKeyUsages(x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth),
	)
	Expect(err).ShouldNot(HaveOccurred())

	return ca, certificate
}
