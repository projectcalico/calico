package fv_test

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"github.com/elazarl/goproxy"
	"io"
	"log"
	"net"
	"net/http"
	url2 "net/url"

	. "github.com/onsi/gomega"

	calicotls "github.com/projectcalico/calico/crypto/pkg/tls"
	"github.com/projectcalico/calico/guardian/pkg/bimux"
	"github.com/projectcalico/calico/guardian/pkg/config"
	"github.com/projectcalico/calico/lib/std/cryptoutils"
)

type connAuthenticator struct {
	rejectConnections      bool
	connectionRequestCount int
}

func (v *connAuthenticator) Authenticate(conn net.Conn) (*any, error) {
	v.connectionRequestCount++
	if v.rejectConnections {
		return nil, fmt.Errorf("rejecting requests")
	}

	return nil, nil
}

func sendToMuxRequest(mux bimux.Session, req *http.Request) (*http.Response, error) {
	conn, err := mux.Open()
	Expect(err).ShouldNot(HaveOccurred())

	tlsConn := tls.Client(conn, &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{"h2"},
	})

	// We never expect an error here, so something is wrong with the test if we get an error.
	if err := tlsConn.Handshake(); err != nil {
		return nil, err
	}

	http2Conn, err := http2Transport.NewClientConn(tlsConn)
	Expect(err).ShouldNot(HaveOccurred())

	return http2Conn.RoundTrip(req)
}

func tlsConfigProvider(tlsCert tls.Certificate, ca cryptoutils.CA, extraCAs ...cryptoutils.CA) config.TLSConfigProviderFunc {
	return func() (*tls.Config, *tls.Certificate, error) {
		tlsConfig, err := calicotls.NewTLSConfig()
		Expect(err).ShouldNot(HaveOccurred())

		tlsConfig.Certificates = []tls.Certificate{tlsCert}
		tlsConfig.RootCAs = x509.NewCertPool()
		tlsConfig.ServerName = ca.Certificate().DNSNames[0]

		Expect(ca.AddToCertPool(tlsConfig.RootCAs)).ShouldNot(HaveOccurred())
		for _, extraCA := range extraCAs {
			Expect(extraCA.AddToCertPool(tlsConfig.RootCAs)).ShouldNot(HaveOccurred())
		}
		return tlsConfig, &tlsCert, nil
	}
}

func MustParseURL(str string) *url2.URL {
	url, err := url2.Parse(str)
	if err != nil {
		panic(err)
	}

	return url
}

func mustGetTLSConfig(cert *tls.Certificate, rootCAs ...cryptoutils.CA) *tls.Config {
	tlsCfg, err := calicotls.NewTLSConfig()
	if err != nil {
		panic(err)
	}

	tlsCfg.Certificates = []tls.Certificate{*cert}
	tlsCfg.RootCAs = x509.NewCertPool()
	for _, ca := range rootCAs {
		Expect(ca.AddToCertPool(tlsCfg.RootCAs)).ShouldNot(HaveOccurred())
	}
	return tlsCfg
}

type proxyServer struct {
	*http.Server
	proxyCounter int
}

func newProxyServer(addr string, proxyCert *tls.Certificate, ca cryptoutils.CA) *proxyServer {
	httpProxy := goproxy.NewProxyHttpServer()
	srv := &proxyServer{
		Server: &http.Server{
			Addr:    addr,
			Handler: httpProxy,
			TLSConfig: &tls.Config{
				ServerName:   "foo",
				Certificates: []tls.Certificate{*proxyCert},
				RootCAs:      ca.MustAddToCertPool(x509.NewCertPool()),
			},
		},
	}

	httpProxy.OnRequest().HandleConnect(goproxy.FuncHttpsHandler(func(host string, ctx *goproxy.ProxyCtx) (*goproxy.ConnectAction, string) {
		srv.proxyCounter++
		return goproxy.OkConnect, host
	}))
	// Ensure the proxy does not try to dial through to the configured proxy (i.e. itself)
	httpProxy.ConnectDial = nil

	// Silence warnings from connections being closed. The proxy server lib only accepts the unstructured std logger.
	httpProxy.Logger = log.New(io.Discard, "", log.LstdFlags)

	return srv
}
