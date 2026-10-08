package fv_test

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"net"
	"net/http"
	url2 "net/url"
	"os"
	"testing"
	"time"

	"github.com/hashicorp/yamux"
	. "github.com/onsi/gomega"
	log "github.com/sirupsen/logrus"

	calicotls "github.com/projectcalico/calico/crypto/pkg/tls"
	"github.com/projectcalico/calico/guardian/pkg/config"
	"github.com/projectcalico/calico/guardian/pkg/daemon"
	"github.com/projectcalico/calico/guardian/pkg/server"
	"github.com/projectcalico/calico/lib/logrusr"
	"github.com/projectcalico/calico/lib/std/cryptoutils"
)

func TestRequestsFromGuardianToUpstream(t *testing.T) {
	logrusr.ConfigureFormatter("guardian")
	logrusr.RedirectLogrusToTestingT(t)
	log.SetOutput(os.Stdout)
	log.SetLevel(log.DebugLevel)

	RegisterTestingT(t)

	tmpDir := os.TempDir()

	mgmtCertFile, err := os.Create(tmpDir + "/" + "management-cluster.crt")
	Expect(err).ShouldNot(HaveOccurred())
	defer func() { _ = mgmtCertFile.Close() }()

	mgmtKeyFile, err := os.Create(tmpDir + "/" + "management-cluster.key")
	Expect(err).ShouldNot(HaveOccurred())
	defer func() { _ = mgmtKeyFile.Close() }()

	ca, err := cryptoutils.NewCA("test")
	Expect(err).ShouldNot(HaveOccurred())

	serverCert, err := ca.CreateServerCert("test-server-cert", []string{"localhost"})
	Expect(err).ShouldNot(HaveOccurred())
	Expect(serverCert.WriteCertificates(mgmtCertFile)).ShouldNot(HaveOccurred())
	Expect(serverCert.WritePrivateKey(mgmtKeyFile)).ShouldNot(HaveOccurred())

	// Generate managed cluster certificates to send requests to the management cluster.
	createKeyCertPair(tmpDir, "managed-cluster.crt", "managed-cluster.key")

	type obj struct {
		Name string `json:"name"`
	}

	fooServerCert, fooServerKey := createKeyCertPair(tmpDir, "foo-server.crt", "foo-server.key")
	go func() {
		mux := http.NewServeMux()
		mux.HandleFunc("/foobar", func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(obj{Name: "test-server-cert"})
		})
		srv := http.Server{
			Addr:    "localhost:8999",
			Handler: mux,
		}
		if err := srv.ListenAndServeTLS(fooServerCert, fooServerKey); err != nil {
			panic(err)
		}
	}()

	cfg := config.Config{
		LogLevel:                "DEBUG",
		CertPath:                tmpDir,
		TunnelDialRetryAttempts: -1,
		TunnelDialRetryInterval: 5 * time.Second,
		TunnelDialTimeout:       5 * time.Second,
		VoltronURL:              "localhost:8443",
		KeepAliveEnable:         true,
		KeepAliveInterval:       1000000,
	}

	tlsCfg := getTLSConfig(mgmtCertFile.Name(), mgmtKeyFile.Name())

	upstreamSrv := newUpstreamServer(":8443", tlsCfg)
	defer func() { _ = upstreamSrv.listener.Close() }()

	ctx, cancel := context.WithCancel(context.Background())
	daemonDoneSig := make(chan struct{})
	go func() {
		defer close(daemonDoneSig)

		url, err := url2.Parse("https://localhost:8999")
		Expect(err).ShouldNot(HaveOccurred())
		daemon.Run(ctx, cfg, []server.Target{
			{Path: "/", Dest: url, AllowInsecureTLS: true},
		})
	}()

	mux := upstreamSrv.Accept()

	http2Conn := openHttp2TLSConn(mux)

	req, err := http.NewRequest(http.MethodGet, "https://localhost:8999/foobar", nil)
	Expect(err).ShouldNot(HaveOccurred())

	resp, err := http2Conn.RoundTrip(req)
	Expect(err).ShouldNot(HaveOccurred())
	Expect(resp.StatusCode).Should(Equal(http.StatusOK))

	defer func() { _ = resp.Body.Close() }()

	var rspObj obj
	Expect(json.NewDecoder(resp.Body).Decode(&rspObj)).ShouldNot(HaveOccurred())
	Expect(rspObj).Should(Equal(obj{Name: "test-server-cert"}))

	// Close the mux and allow guardian to try to reconnect, as we want to test that we can still use the tunnel after
	// reconnecting.
	t.Log("testing that we can use the tunnel after reconnecting")
	_ = mux.Close()
	upstreamSrv.Close()
	time.Sleep(10 * time.Second)

	upstreamSrv = newUpstreamServer(":8443", tlsCfg)
	mux = upstreamSrv.Accept()

	http2Conn = openHttp2TLSConn(mux)

	req, err = http.NewRequest(http.MethodGet, "https://localhost:8999/foobar", nil)
	Expect(err).ShouldNot(HaveOccurred())

	resp, err = http2Conn.RoundTrip(req)
	Expect(err).ShouldNot(HaveOccurred())
	Expect(resp.StatusCode).Should(Equal(http.StatusOK))

	defer func() { _ = resp.Body.Close() }()

	rspObj = obj{}
	Expect(json.NewDecoder(resp.Body).Decode(&rspObj)).ShouldNot(HaveOccurred())
	Expect(rspObj).Should(Equal(obj{Name: "test-server-cert"}))

	cancel()
	<-daemonDoneSig
}

func openHttp2TLSConn(mux *yamux.Session) *http.ClientConn {
	protocols := new(http.Protocols)
	protocols.SetHTTP2(true)

	transport := &http.Transport{
		Protocols:       protocols,
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		DialContext: func(context.Context, string, string) (net.Conn, error) {
			return mux.Open()
		},
	}

	http2Conn, err := transport.NewClientConn(context.Background(), "https", "localhost:8999")
	Expect(err).ShouldNot(HaveOccurred())

	return http2Conn
}

type upstreamServer struct {
	listener net.Listener
}

func newUpstreamServer(addr string, tlsCfg *tls.Config) *upstreamServer {
	serverListener := newTLSListener(addr, tlsCfg)

	return &upstreamServer{
		listener: serverListener,
	}
}

func (ups *upstreamServer) Accept() *yamux.Session {
	conn, err := ups.listener.Accept()
	Expect(err).ShouldNot(HaveOccurred())

	cfg := yamux.DefaultConfig()
	cfg.AcceptBacklog = 1000
	cfg.EnableKeepAlive = true
	cfg.KeepAliveInterval = 10000

	mux, err := yamux.Server(conn, cfg)
	Expect(err).ShouldNot(HaveOccurred())

	return mux
}

func (ups *upstreamServer) Close() {
	_ = ups.listener.Close()
}

func newTLSListener(addr string, tlsCfg *tls.Config) net.Listener {
	listener, err := net.Listen("tcp", addr)
	Expect(err).ShouldNot(HaveOccurred())

	return tls.NewListener(listener, tlsCfg)
}

func getTLSConfig(certPath, keyPath string) *tls.Config {
	pemCert, err := os.ReadFile(certPath)
	Expect(err).ShouldNot(HaveOccurred())

	pemKey, err := os.ReadFile(keyPath)
	Expect(err).ShouldNot(HaveOccurred())

	cert, err := tls.X509KeyPair(pemCert, pemKey)
	Expect(err).ShouldNot(HaveOccurred())

	tlsConfig, err := calicotls.NewTLSConfig()
	Expect(err).ShouldNot(HaveOccurred())
	tlsConfig.Certificates = []tls.Certificate{cert}
	return tlsConfig
}
