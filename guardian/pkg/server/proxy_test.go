package server_test

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"regexp"
	"testing"

	. "github.com/onsi/gomega"

	"github.com/projectcalico/calico/guardian/pkg/server"
	"github.com/projectcalico/calico/guardian/test/utils"
)

func TestProxyWithHTTP(t *testing.T) {
	RegisterTestingT(t)

	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		Expect(r.URL.Path).To(Equal("/test"))
		w.WriteHeader(http.StatusOK)
		_, err := w.Write([]byte("Hello"))
		Expect(err).NotTo(HaveOccurred())

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
		_, err := w.Write([]byte("Hello from HTTPS"))
		Expect(err).NotTo(HaveOccurred())
	}))

	tmpDir := os.TempDir()

	serverCrt, serverKey := utils.CreateKeyCertPair(tmpDir)
	defer serverCrt.Close()
	defer serverKey.Close()

	cert, err := tls.LoadX509KeyPair(serverCrt.Name(), serverKey.Name())
	if err != nil {
		t.Fatalf("Failed to load server certificate and key: %v", err)
	}

	mockServer.TLS = &tls.Config{Certificates: []tls.Certificate{cert}}
	mockServer.StartTLS()
	defer mockServer.Close()

	t.Run("ServeHTTP proxies requests to the correct HTTPS target", func(t *testing.T) {
		targetURL, err := url.Parse(mockServer.URL)
		Expect(err).NotTo(HaveOccurred())

		targets := []server.Target{
			{
				Path:   "/test",
				Dest:   targetURL,
				CAFile: serverCrt.Name(),
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

func TestProxyWithPathRegexp(t *testing.T) {
	RegisterTestingT(t)

	mockServer := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, err := w.Write([]byte(fmt.Sprintf("Received expected URL %s", r.URL.Path)))
		Expect(err).NotTo(HaveOccurred())
	}))
	defer mockServer.Close()

	tmpDir := os.TempDir()
	serverCrt, serverKey := utils.CreateKeyCertPair(tmpDir)
	defer serverCrt.Close()
	defer serverKey.Close()

	cert, err := tls.LoadX509KeyPair(serverCrt.Name(), serverKey.Name())
	Expect(err).NotTo(HaveOccurred())

	mockServer.TLS = &tls.Config{Certificates: []tls.Certificate{cert}}
	mockServer.StartTLS()
	defer mockServer.Close()

	regex, err := regexp.Compile("^/test$")
	Expect(err).NotTo(HaveOccurred())

	targetURL, err := url.Parse(mockServer.URL)
	Expect(err).NotTo(HaveOccurred())

	t.Run("Rejects request if PathRegexp does not match", func(t *testing.T) {
		targets := []server.Target{
			{
				Path:       "/invalid-path",
				PathRegexp: regex,
				Dest:       targetURL,
				CAFile:     serverCrt.Name(),
			},
		}

		proxy, err := server.NewProxy(targets)
		Expect(err).NotTo(HaveOccurred())
		Expect(proxy).NotTo(BeNil())

		req := httptest.NewRequest(http.MethodGet, "/invalid-path", nil)
		rec := httptest.NewRecorder()

		proxy.ServeHTTP(rec, req)

		Expect(rec.Code).To(Equal(http.StatusNotFound))
	})

	t.Run("Accepts request if PathRegexp does match", func(t *testing.T) {
		targets := []server.Target{
			{
				Path:       "/test",
				PathRegexp: regex,
				Dest:       targetURL,
				CAFile:     serverCrt.Name(),
			},
		}

		proxy, err := server.NewProxy(targets)
		Expect(err).NotTo(HaveOccurred())
		Expect(proxy).NotTo(BeNil())

		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		rec := httptest.NewRecorder()

		proxy.ServeHTTP(rec, req)

		Expect(rec.Code).To(Equal(http.StatusOK))
		Expect(rec.Body.String()).To(Equal("Received expected URL /test"))
	})

	t.Run("Replaces URL path using PathReplace", func(t *testing.T) {
		targets := []server.Target{
			{
				Path:        "/test",
				PathRegexp:  regex,
				PathReplace: []byte(`/new-path`),
				Dest:        targetURL,
				CAFile:      serverCrt.Name(),
			},
		}

		proxy, err := server.NewProxy(targets)
		Expect(err).NotTo(HaveOccurred())
		Expect(proxy).NotTo(BeNil())

		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		rec := httptest.NewRecorder()

		proxy.ServeHTTP(rec, req)

		Expect(rec.Code).To(Equal(http.StatusOK))
		Expect(rec.Body.String()).To(Equal("Received expected URL /new-path"))

	})

}
