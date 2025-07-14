package fv_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"net/http"
	"sync"
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

var (
	http2Transport *http2.Transport

	voltronURL = "localhost:8443"

	testSrvAddr = "localhost:8999"

	proxyAddr = "localhost:3128"
	proxyURL  = MustParseURL("https://" + proxyAddr)

	defaultCfg = config.Config{
		LogLevel:                "DEBUG",
		TunnelDialRetryAttempts: -1,
		TunnelDialRetryInterval: 100 * time.Millisecond,
		TunnelDialTimeout:       5 * time.Second,
		VoltronURL:              voltronURL,
		KeepAliveEnable:         true,
		KeepAliveInterval:       1000000,
		Listen:                  true,
		ListenPort:              "8080",
	}
)

func TestBasicInboundAndOutboundScenarios(t *testing.T) {
	setup(t)

	serverCA := cryptoutils.MustGetNewCA("server-signer", cryptoutils.WithDNSNames("localhost"))
	serverCert := serverCA.MustCreateTLSCertificate("management-cluster",
		cryptoutils.WithDNSNames("localhost"),
		cryptoutils.WithKeyUsages(x509.KeyUsageKeyEncipherment, x509.KeyUsageDigitalSignature),
		cryptoutils.WithExtKeyUsages(x509.ExtKeyUsageServerAuth),
	)

	clientCA := cryptoutils.MustGetNewCA("client-signer", cryptoutils.WithDNSNames("localhost"))
	clientCert := clientCA.MustCreateTLSCertificate("test-managed-cluster",
		cryptoutils.WithDNSNames("localhost"),
		cryptoutils.WithKeyUsages(x509.KeyUsageKeyEncipherment, x509.KeyUsageDigitalSignature),
		cryptoutils.WithExtKeyUsages(x509.ExtKeyUsageClientAuth),
	)

	proxyCA := cryptoutils.MustGetNewCA("proxy-signer", cryptoutils.WithDNSNames("localhost"))
	proxyCert := proxyCA.MustCreateTLSCertificate("proxy-server",
		cryptoutils.WithDNSNames("localhost"),
		cryptoutils.WithKeyUsages(x509.KeyUsageKeyEncipherment, x509.KeyUsageDigitalSignature),
		cryptoutils.WithExtKeyUsages(x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth),
	)

	tt := []struct {
		description string
		cfg         func(cfg config.Config) config.Config
	}{
		{
			description: "No proxy is enabled",
		},
		{
			description: "Proxy is enabled with TLS config",
			cfg: func(cfg config.Config) config.Config {
				cfg.ProxyURL = proxyURL
				cfg.ProxyTLSConfig = mustGetTLSConfig(proxyCert, proxyCA)

				return cfg
			},
		},
	}

	for _, tc := range tt {
		t.Run(tc.description, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			cfg := defaultCfg
			if tc.cfg != nil {
				cfg = tc.cfg(cfg)
			}

			cfg.SetTLSConfigProvider(tlsConfigProvider(*clientCert, serverCA))

			var wg sync.WaitGroup

			testSrv := createTestService(testSrvAddr)
			wg.Add(1)
			go func() {
				defer wg.Done()
				_ = testSrv.ListenAndServeTLS("", "")
			}()
			go func() {
				<-ctx.Done()
				_ = testSrv.Shutdown(ctx)
			}()

			var prxyServer *proxyServer
			if cfg.ProxyURL != nil {
				prxyServer = newProxyServer(proxyAddr, proxyCert, clientCA)

				wg.Add(1)
				go func() {
					defer wg.Done()
					_ = prxyServer.ListenAndServeTLS("", "")
				}()

				go func() {
					<-ctx.Done()
					_ = prxyServer.Shutdown(ctx)
				}()
			}

			wg.Add(1)
			go func() {
				defer wg.Done()

				daemon.Run(ctx, cfg, []server.Target{
					{Path: "/", Dest: MustParseURL("https://" + testSrvAddr), AllowInsecureTLS: true},
				})
			}()

			authenticator := &connAuthenticator{}
			sessionListener, err := bimux.NewSessionListener(":8443", upstreamTLSConfig(*serverCert, clientCA), authenticator)
			Expect(err).ShouldNot(HaveOccurred())

			sessionCh, err := sessionListener.Listen(ctx)
			Expect(err).ShouldNot(HaveOccurred())
			session := <-sessionCh

			t.Run("Test that the guardian can receive requests from an outside server and proxy to the destination.", func(t *testing.T) {
				req, err := http.NewRequest(http.MethodGet, "https://"+testSrvAddr+"/foobar", nil)
				Expect(err).ShouldNot(HaveOccurred())

				resp, err := sendToMuxRequest(session, req)
				Expect(err).ShouldNot(HaveOccurred())
				Expect(resp.StatusCode).Should(Equal(http.StatusOK))
				defer resp.Body.Close()

				var rspObj testServerResponse
				Expect(json.NewDecoder(resp.Body).Decode(&rspObj)).ShouldNot(HaveOccurred())
				Expect(rspObj.Message).Should(Equal("hello from the other side."))
			})

			// Close the mux and allow guardian to try to reconnect, as we want to test that we can still use the tunnel after
			// reconnecting.
			t.Run("Test that the guardian continuously tries to reconnect to the upstream server when the connection is closed.", func(t *testing.T) {
				authenticator.rejectConnections = true   // Reject all connection requests from guardian
				authenticator.connectionRequestCount = 0 // Reset the request connect
				_ = session.Close()

				// Wait for guardian to try connecting at least 5 times to ensure the reconnection logic retries frequently based on
				// the configuration. The interval is set to 100 ms, so it should take any longer than 5 seconds for 5 attempts.
				Eventually(func() int { return authenticator.connectionRequestCount }, "5s").Should(BeNumerically(">=", 5))

				// Allow guardian to reconnect to the upstream server.
				authenticator.rejectConnections = false

				// Send a request to the upstream server and ensure it works after reconnecting.
				req, err := http.NewRequest(http.MethodGet, "https://localhost:8999/foobar", nil)
				Expect(err).ShouldNot(HaveOccurred())

				session = <-sessionCh
				Expect(session).ShouldNot(BeNil())
				resp, err := sendToMuxRequest(session, req)
				Expect(err).ShouldNot(HaveOccurred())
				Expect(resp.StatusCode).Should(Equal(http.StatusOK))

				defer resp.Body.Close()

				rspObj := testServerResponse{}
				Expect(json.NewDecoder(resp.Body).Decode(&rspObj)).ShouldNot(HaveOccurred())
				Expect(rspObj.Message).Should(Equal("hello from the other side."))

				if prxyServer != nil {
					Expect(prxyServer.proxyCounter).Should(BeNumerically(">=", 1))
				}
			})

			t.Run("Test that the guardian can send requests outside the cluster.", func(t *testing.T) {
				srv := http.Server{
					Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
						w.WriteHeader(http.StatusOK)
						_ = json.NewEncoder(w).Encode(testServerResponse{Message: "hello from the outside."})
					}),
				}
				wg.Add(1)
				go func() {
					defer wg.Done()
					_ = srv.Serve(session)
				}()

				cli := &http.Client{}

				// Wait for the server to be ready.
				time.Sleep(500 * time.Millisecond)
				req, err := http.NewRequest(http.MethodGet, "http://localhost:8080", nil)
				Expect(err).ShouldNot(HaveOccurred())

				rspObj := sendRequest(cli, req)
				Expect(rspObj.Message).Should(Equal("hello from the outside."))
			})

			cancel()
			<-sessionListener.WaitForShutdown()
			wg.Wait()
		})
	}
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

func createTestService(addr string) *http.Server {
	ca, err := cryptoutils.NewCA("test")
	Expect(err).ShouldNot(HaveOccurred())

	tlsCert, err := ca.CreateTLSCertificate("test-cert",
		cryptoutils.WithDNSNames("localhost"),
		cryptoutils.WithExtKeyUsages(x509.ExtKeyUsageAny),
	)
	Expect(err).ShouldNot(HaveOccurred())

	mux := http.NewServeMux()
	mux.HandleFunc("/foobar", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(testServerResponse{Message: "hello from the other side."})
	})

	srv := &http.Server{
		Addr:      addr,
		Handler:   mux,
		TLSConfig: &tls.Config{Certificates: []tls.Certificate{*tlsCert}},
	}

	return srv
}

func upstreamTLSConfig(tlsCert tls.Certificate, ca cryptoutils.CA) *tls.Config {
	tlsCfg, err := calicotls.NewTLSConfig()
	Expect(err).ShouldNot(HaveOccurred())

	tlsCfg.ClientAuth = tls.RequireAndVerifyClientCert
	tlsCfg.ClientCAs = x509.NewCertPool()
	Expect(ca.AddToCertPool(tlsCfg.ClientCAs)).ShouldNot(HaveOccurred())

	tlsCfg.Certificates = []tls.Certificate{tlsCert}
	return tlsCfg
}
