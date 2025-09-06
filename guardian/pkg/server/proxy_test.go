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

func TestProxy(t *testing.T) {
	RegisterTestingT(t)
	t.Run("TestProxyWithHTTP", func(t *testing.T) {
		t.Parallel()

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

		tt := []struct {
			description     string
			expectedCode    int
			expectedMessage string
			requestPath     string
		}{
			{
				description:     "ServeHTTP proxies requests to the correct target",
				expectedCode:    http.StatusOK,
				expectedMessage: "Hello",
				requestPath:     "/test",
			},
			{
				description:     "ServeHTTP returns 404 for unmatched path",
				expectedCode:    http.StatusNotFound,
				expectedMessage: "404 page not found\n",
				requestPath:     "/notfound",
			},
		}
		for _, tc := range tt {
			t.Run(tc.description, func(t *testing.T) {
				rec := httptest.NewRecorder()
				req := httptest.NewRequest(http.MethodGet, tc.requestPath, nil)

				proxy.ServeHTTP(rec, req)

				Expect(rec.Code).To(Equal(tc.expectedCode))
				Expect(rec.Body.String()).To(Equal(tc.expectedMessage))
			})
		}
	})

	t.Run("Test Proxy With HTTPS", func(t *testing.T) {
		t.Parallel()

		mockServer := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, err := fmt.Fprintf(w, "Hello from HTTPS, with expected URL %s", r.URL.Path)
			Expect(err).NotTo(HaveOccurred())
		}))

		tmpDir := os.TempDir()

		serverCrt, serverKey := utils.CreateKeyCertPair(tmpDir)
		defer func() { _ = serverCrt.Close() }()
		defer func() { _ = serverKey.Close() }()

		cert, err := tls.LoadX509KeyPair(serverCrt.Name(), serverKey.Name())
		if err != nil {
			t.Fatalf("Failed to load server certificate and key: %v", err)
		}

		mockServer.TLS = &tls.Config{Certificates: []tls.Certificate{cert}}
		mockServer.StartTLS()
		defer mockServer.Close()
		targetURL, err := url.Parse(mockServer.URL)
		Expect(err).NotTo(HaveOccurred())

		regex, err := regexp.Compile("^/test$")
		Expect(err).NotTo(HaveOccurred())
		tt := []struct {
			description     string
			target          server.Target
			expectedMessage string
			expectedCode    int
		}{
			{
				description: "ServeHTTP proxies requests to the correct HTTPS target",
				target: server.Target{
					Path:   "/test",
					Dest:   targetURL,
					CAFile: serverCrt.Name()},
				expectedCode:    http.StatusOK,
				expectedMessage: "Hello from HTTPS, with expected URL /test",
			},
			{
				description: "Regexp - Rejects request if PathRegexp does not match",
				target: server.Target{
					Path:       "/invalid-path",
					PathRegexp: regex,
					Dest:       targetURL,
					CAFile:     serverCrt.Name()},
				expectedCode:    http.StatusNotFound,
				expectedMessage: "Not found\n",
			},
			{
				description: "Regexp - Accepts request if PathRegexp does match",
				target: server.Target{
					Path:       "/test",
					PathRegexp: regex,
					Dest:       targetURL,
					CAFile:     serverCrt.Name(),
				},
				expectedCode:    http.StatusOK,
				expectedMessage: "Hello from HTTPS, with expected URL /test",
			},
			{
				description: "Regexp - Replaces URL path using PathReplace",
				target: server.Target{
					Path:        "/test",
					PathRegexp:  regex,
					PathReplace: []byte(`/new-path`),
					Dest:        targetURL,
					CAFile:      serverCrt.Name(),
				},
				expectedCode:    http.StatusOK,
				expectedMessage: "Hello from HTTPS, with expected URL /new-path",
			},
		}

		for _, tc := range tt {
			t.Run(tc.description, func(t *testing.T) {
				proxy, err := server.NewProxy([]server.Target{tc.target})
				Expect(err).NotTo(HaveOccurred())
				Expect(proxy).NotTo(BeNil())

				req := httptest.NewRequest(http.MethodGet, tc.target.Path, nil)
				rec := httptest.NewRecorder()

				proxy.ServeHTTP(rec, req)

				Expect(rec.Code).To(Equal(tc.expectedCode))
				Expect(rec.Body.String()).To(Equal(tc.expectedMessage))
			})
		}
	})
}
