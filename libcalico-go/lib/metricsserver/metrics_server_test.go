package metricsserver

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"os"
	"sync"
	"testing"
	"time"

	. "github.com/onsi/gomega"
	"github.com/prometheus/client_golang/prometheus"
)

// TestServePrometheusMetricsHTTPS unit test for ServePrometheusMetricsHTTPS.
func TestServePrometheusMetricsHTTPS(t *testing.T) {
	RegisterTestingT(t)
	host := "127.0.0.1"

	certFile, keyFile, caFile, caKeyFile, cleanup := createTestCertFiles(t)
	defer cleanup()

	// Prepare test cases
	for _, tt := range []struct {
		name                 string
		certFile             string
		keyFile              string
		clientAuthType       string
		caFile               string
		clientHasCert        bool
		expectedStatus       int
		expectedError        []string
		rotateCertificates   bool
		rotateExpectedError  []string
		rotateExpectedStatus int
	}{
		{
			name:           "Valid TLS: NoClientCert",
			certFile:       certFile,
			keyFile:        keyFile,
			clientAuthType: "NoClientCert",
			caFile:         caFile,
			clientHasCert:  false,
			expectedStatus: http.StatusOK,
		},
		{
			name:           "Missing Certificate: NoClientCert",
			certFile:       "missing.crt",
			keyFile:        keyFile,
			clientAuthType: "NoClientCert",
			caFile:         caFile,
			clientHasCert:  false,
			expectedError:  []string{"Failed to load initial TLS configuration: failed to load x509 key pair: open missing.crt: no such file or directory"},
		},
		{
			name:           "Missing Private Key: NoClientCert",
			certFile:       certFile,
			keyFile:        "missing.key",
			clientAuthType: "NoClientCert",
			caFile:         caFile,
			clientHasCert:  false,
			expectedError:  []string{"Failed to load initial TLS configuration: failed to load x509 key pair: open missing.key: no such file or directory"},
		},
		{
			name:                 "Valid TLS: NoClientCert, Rotate Certificates",
			certFile:             certFile,
			keyFile:              keyFile,
			clientAuthType:       "NoClientCert",
			caFile:               caFile,
			clientHasCert:        false,
			expectedStatus:       http.StatusOK,
			rotateCertificates:   true,
			rotateExpectedStatus: http.StatusOK,
		},
		{
			name:           "Valid TLS: RequireAndVerifyClientCert, Client has valid CA",
			certFile:       certFile,
			keyFile:        keyFile,
			clientAuthType: "RequireAndVerifyClientCert",
			caFile:         caFile,
			clientHasCert:  true,
			expectedStatus: http.StatusOK,
		},
		{
			name:                 "Valid TLS: RequireAndVerifyClientCert, Client has valid CA, Rotate Certificates",
			certFile:             certFile,
			keyFile:              keyFile,
			clientAuthType:       "RequireAndVerifyClientCert",
			caFile:               caFile,
			clientHasCert:        true,
			expectedStatus:       http.StatusOK,
			rotateCertificates:   true,
			rotateExpectedStatus: http.StatusOK,
		},
		{
			name:           "Valid TLS: RequireAndVerifyClientCert, Client is missing CA",
			certFile:       certFile,
			keyFile:        keyFile,
			clientAuthType: "RequireAndVerifyClientCert",
			caFile:         caFile,
			clientHasCert:  false,
			expectedError:  []string{"Get \"https://127.0.0.1:", "remote error: tls: certificate required"},
		},
		{
			name:           "Invalid clientAuth Type",
			certFile:       certFile,
			keyFile:        keyFile,
			clientAuthType: "InvalidType",
			caFile:         caFile,
			clientHasCert:  false,
			expectedError:  []string{"Failed to convert ClientAuthType invalid client authentication type: InvalidType. Defaulting to RequireAndVerifyClientCert"},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			RegisterTestingT(t)
			errorChannel := make(chan error, 1)
			var once sync.Once
			recordConnectionError := func(err error) {
				once.Do(func() {
					errorChannel <- err
				})
			}
			err := error(nil)

			// Dynamically find an open port
			listener, err := net.Listen("tcp", ":0")
			if err != nil {
				t.Fatalf("Failed to find an open port %v", err)
			}
			port := listener.Addr().(*net.TCPAddr).Port
			listener.Close()

			done := make(chan error, 1)
			go func() {
				err = ServePrometheusMetricsHTTPS(prometheus.DefaultGatherer, host, port, tt.certFile, tt.keyFile, tt.clientAuthType, tt.caFile)
				done <- err
			}()

			select {
			case err := <-done:
				recordConnectionError(err)
			case <-time.After(1 * time.Second):
				// Success: the server is still running.
			}
			close(done)

			if err != nil && len(tt.expectedError) > 0 {
				Expect(err).To(HaveOccurred())
				for _, expected := range tt.expectedError {
					Expect(err.Error()).To(ContainSubstring(expected))
				}
				return
			}

			// Load CA cert for client auth
			caCert, err := os.ReadFile(tt.caFile)
			if err != nil {
				t.Fatalf("Failed to read CA cert for client use: %v", err)
			}
			caCertPool := x509.NewCertPool()
			if !caCertPool.AppendCertsFromPEM(caCert) {
				t.Fatal("Failed to parse CA cert for client use")
			}

			// Configure client tls
			clientTLSConfig := &tls.Config{
				RootCAs: caCertPool,
			}
			if tt.clientHasCert {
				clientTLSConfig.Certificates = []tls.Certificate{loadTestClientCert(t, certFile, keyFile)}
			}

			client := &http.Client{
				Timeout: 10 * time.Second,
				Transport: &http.Transport{
					TLSClientConfig: clientTLSConfig,
					// Allow connection reuse
					MaxIdleConns:        10,
					IdleConnTimeout:     30 * time.Second,
					DisableCompression:  true,
					TLSHandshakeTimeout: 10 * time.Second,
				},
			}

			resp, err := getResponseFromMetricsEndpoint(client, host, port)
			if err != nil && len(tt.expectedError) > 0 {
				Expect(err).To(HaveOccurred())
				for _, expected := range tt.expectedError {
					Expect(err.Error()).To(ContainSubstring(expected))
				}
				return
			} else {
				Expect(resp.StatusCode).To(Equal(tt.expectedStatus))
			}

			if tt.rotateCertificates {
				// Rotate certificates
				err = rotateCertificates(certFile, keyFile, caFile, caKeyFile)
				if err != nil {
					t.Fatalf("Failed to rotate certificates: %v", err)
				}

				resp, err = getResponseFromMetricsEndpoint(client, host, port)
				if err != nil {
					t.Fatalf("Failed to get response from metrics endpoint: %v", err)
				}

				Expect(resp.StatusCode).To(Equal(tt.rotateExpectedStatus))
			}

			if len(tt.expectedError) > 0 || len(tt.rotateExpectedError) > 0 {
				t.Fatalf("Test should have failed but didn't")
			}
			close(errorChannel)
		})
	}
}

func getResponseFromMetricsEndpoint(client *http.Client, host string, port int) (*http.Response, error) {
	// Retry logic for certificate rotation
	var resp *http.Response
	var err error
	maxRetries := 10
	retryDelay := 100 * time.Millisecond

	for range maxRetries {
		resp, err = client.Get(fmt.Sprintf("https://%s:%d/metrics", host, port))
		if err == nil {
			break
		}
		time.Sleep(retryDelay)
	}
	if resp != nil && resp.Body != nil {
		defer resp.Body.Close()
	}
	return resp, err
}

func createTestCertFiles(t *testing.T) (certFile, keyFile, caFile, caKeyFile string, cleanup func()) {
	// Generate CA certificate
	caCert, caKey, err := generateCA()
	if err != nil {
		t.Fatalf("Failed to generate CA certificate: %v", err)
	}

	// Generate server certificate signed by CA
	cert, key, err := generateCert(caCert, caKey)
	if err != nil {
		t.Fatalf("Failed to generate server certificate: %v", err)
	}

	// Write certificates to temporary files
	certFile = writeTempFile(t, string(cert))
	keyFile = writeTempFile(t, string(key))
	caFile = writeTempFile(t, string(caCert))
	caKeyFile = writeTempFile(t, string(caKey))

	// Return cleanup function to remove files
	cleanup = func() {
		os.Remove(certFile)
		os.Remove(keyFile)
		os.Remove(caFile)
		os.Remove(caKeyFile)
	}
	return certFile, keyFile, caFile, caKeyFile, cleanup
}

func generateCA() ([]byte, []byte, error) {
	ca := &x509.Certificate{
		SerialNumber: big.NewInt(2025),
		Subject: pkix.Name{
			Organization: []string{"Test CA"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}

	caPrivKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return nil, nil, err
	}

	caBytes, err := x509.CreateCertificate(rand.Reader, ca, ca, &caPrivKey.PublicKey, caPrivKey)
	if err != nil {
		return nil, nil, err
	}

	caPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: caBytes,
	})

	caPrivKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(caPrivKey),
	})

	return caPEM, caPrivKeyPEM, nil
}

func generateCert(caCertPEM, caKeyPEM []byte) ([]byte, []byte, error) {
	caCertBlock, _ := pem.Decode(caCertPEM)
	caCert, err := x509.ParseCertificate(caCertBlock.Bytes)
	if err != nil {
		return nil, nil, err
	}

	caKeyBlock, _ := pem.Decode(caKeyPEM)
	caKey, err := x509.ParsePKCS1PrivateKey(caKeyBlock.Bytes)
	if err != nil {
		return nil, nil, err
	}

	cert := &x509.Certificate{
		SerialNumber: big.NewInt(2025),
		Subject: pkix.Name{
			Organization: []string{"Test Server"},
		},
		DNSNames:    []string{"localhost"},
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().AddDate(10, 0, 0),
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
	}

	certPrivKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return nil, nil, err
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, cert, caCert, &certPrivKey.PublicKey, caKey)
	if err != nil {
		return nil, nil, err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certBytes,
	})

	certPrivKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(certPrivKey),
	})

	return certPEM, certPrivKeyPEM, nil
}

func loadTestClientCert(t *testing.T, certFile, keyFile string) tls.Certificate {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		t.Fatalf("Failed to load client certificate: %v", err)
	}
	return cert
}

func writeTempFile(t *testing.T, content string) string {
	tmpFile, err := os.CreateTemp("", "testcert")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer tmpFile.Close()

	if _, err := tmpFile.WriteString(content); err != nil {
		t.Fatalf("Failed to write to temp file: %v", err)
	}
	return tmpFile.Name()
}

func rotateCertificates(certFile, keyFile, caFile, caKeyFile string) error {
	// Read CA certificate and key
	caCertPEM, err := os.ReadFile(caFile)
	if err != nil {
		return fmt.Errorf("failed to read CA certificate: %w", err)
	}
	caKeyPEM, err := os.ReadFile(caKeyFile)
	if err != nil {
		return fmt.Errorf("failed to read CA key: %w", err)
	}
	// Generate new certificates
	newCert, newKey, err := generateCert(caCertPEM, caKeyPEM)
	if err != nil {
		return fmt.Errorf("failed to generate new certificates: %w", err)
	}

	// Write new certificates to the specified files
	if err := os.WriteFile(certFile, newCert, 0o644); err != nil {
		return fmt.Errorf("failed to write new certificate: %w", err)
	}
	if err := os.WriteFile(keyFile, newKey, 0o644); err != nil {
		return fmt.Errorf("failed to write new key: %w", err)
	}

	return nil
}
