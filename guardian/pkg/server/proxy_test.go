package server_test

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"testing"

	. "github.com/onsi/gomega"

	"github.com/projectcalico/calico/guardian/pkg/server"
)

func TestProxyWithHTTP(t *testing.T) {
	RegisterTestingT(t)

	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		Expect(r.URL.Path).To(Equal("/test"))
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Hello"))
	}))
	defer mockServer.Close()

	targetURL, err := url.Parse(mockServer.URL)
	Expect(err).NotTo(HaveOccurred())

	targets := []server.Target{
		{
			Path: "/test",
			Dest: targetURL,
		},
	}

	proxy, err := server.NewProxy(targets)
	Expect(proxy).NotTo(BeNil())
	Expect(err).NotTo(HaveOccurred())

	t.Run("ServeHTTP proxies requests to the correct target", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		rec := httptest.NewRecorder()

		proxy.ServeHTTP(rec, req)

		Expect(rec.Code).To(Equal(http.StatusOK))
		Expect(rec.Body.String()).To(Equal("Hello"))
	})

	t.Run("ServeHTTP returns 404 for unmatched path", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/notfound", nil)
		rec := httptest.NewRecorder()

		proxy.ServeHTTP(rec, req)

		Expect(rec.Code).To(Equal(http.StatusNotFound))
	})
}

func TestProxyWithHTTPS(t *testing.T) {
	RegisterTestingT(t)

	mockServer := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Hello from HTTPS"))
	}))

	servercrt, err := filepath.Abs("../../test/certs/server.crt")
	Expect(err).NotTo(HaveOccurred())

	serverKey, err := filepath.Abs("../../test/certs/server.key")
	Expect(err).NotTo(HaveOccurred())

	cert, err := tls.LoadX509KeyPair(servercrt, serverKey)
	if err != nil {
		t.Fatalf("Failed to load server certificate and key: %v", err)
	}

	mockServer.TLS = &tls.Config{Certificates: []tls.Certificate{cert}}
	mockServer.StartTLS()
	defer mockServer.Close()

	t.Run("ServeHTTP proxies requests to the correct HTTPS target", func(t *testing.T) {
		targetURL, err := url.Parse(mockServer.URL)
		Expect(err).NotTo(HaveOccurred())

		cabundleCert, err := filepath.Abs("../../test/certs/rootCA.crt")
		Expect(err).NotTo(HaveOccurred())
		targets := []server.Target{
			{
				Path:   "/test",
				Dest:   targetURL,
				CAFile: cabundleCert,
			},
		}

		proxy, err := server.NewProxy(targets)
		Expect(err).NotTo(HaveOccurred())
		Expect(proxy).NotTo(BeNil())

		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		rec := httptest.NewRecorder()

		proxy.ServeHTTP(rec, req)

		Expect(http.StatusOK).To(Equal(rec.Code))
		Expect(rec.Body.String()).To(Equal("Hello from HTTPS"))
	})
}
