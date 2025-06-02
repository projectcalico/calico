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
	"testing"
	"time"

	. "github.com/onsi/gomega"
)

// TestServePrometheusMetricsHTTPS unit test for .
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
		minTLSVersion        string
		clientAuthType       string
		caFile               string
		clientHasCA          bool
		expectedStatus       int
		expectError          bool
		rotateCertificates   bool
		rotateExpectError    bool
		rotateExpectedStatus int
	}{
		{
			name:           "Valid TLS: NoClientCert, TLS13",
			certFile:       certFile,
			keyFile:        keyFile,
			minTLSVersion:  "TLS13",
			clientAuthType: "NoClientCert",
			caFile:         "",
			clientHasCA:    false,
			expectedStatus: 200,
			expectError:    false,
		},
		{
			name:                 "Valid TLS: NoClientCert, TLS13, Rotate Certificates",
			certFile:             certFile,
			keyFile:              keyFile,
			minTLSVersion:        "TLS13",
			clientAuthType:       "NoClientCert",
			caFile:               "",
			clientHasCA:          false,
			expectedStatus:       200,
			expectError:          false,
			rotateCertificates:   true,
			rotateExpectError:    false,
			rotateExpectedStatus: 200,
		},
		{
			name:           "Valid TLS: NoClientCert, TLS12",
			certFile:       certFile,
			keyFile:        keyFile,
			minTLSVersion:  "TLS12",
			clientAuthType: "NoClientCert",
			caFile:         "",
			clientHasCA:    false,
			expectedStatus: 200,
			expectError:    false,
		},
		{
			name:           "Valid TLS: RequireAndVerifyClientCert, TLS13",
			certFile:       certFile,
			keyFile:        keyFile,
			minTLSVersion:  "TLS13",
			clientAuthType: "RequireAndVerifyClientCert",
			caFile:         caFile,
			clientHasCA:    true,
			expectedStatus: 200,
			expectError:    false,
		},
		{
			name:                 "Valid TLS: RequireAndVerifyClientCert, TLS13, Rotate Certificates",
			certFile:             certFile,
			keyFile:              keyFile,
			minTLSVersion:        "TLS13",
			clientAuthType:       "RequireAndVerifyClientCert",
			caFile:               caFile,
			clientHasCA:          true,
			expectedStatus:       200,
			expectError:          false,
			rotateCertificates:   true,
			rotateExpectError:    false,
			rotateExpectedStatus: 200,
		},
		{
			name:           "Valid TLS: RequireAndVerifyClientCert, TLS12",
			certFile:       certFile,
			keyFile:        keyFile,
			minTLSVersion:  "TLS12",
			clientAuthType: "RequireAndVerifyClientCert",
			caFile:         caFile,
			clientHasCA:    true,
			expectedStatus: 200,
			expectError:    false,
		},
		{
			name:           "Valid TLS: RequireAndVerifyClientCert, TLS13, Client missing valid CA",
			certFile:       certFile,
			keyFile:        keyFile,
			minTLSVersion:  "TLS12",
			clientAuthType: "RequireAndVerifyClientCert",
			caFile:         caFile,
			clientHasCA:    false,
			expectError:    true,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			RegisterTestingT(t)

			// Dynamically find an open port
			listener, err := net.Listen("tcp", ":0")
			if err != nil {
				t.Fatalf("Failed to find an open port %v", err)
			}
			port := listener.Addr().(*net.TCPAddr).Port
			listener.Close()

			// Start the HTTPS metrics server in a goroutine
			go ServePrometheusMetricsHTTPS(host, port, tt.certFile, tt.keyFile, tt.minTLSVersion, tt.clientAuthType, tt.caFile)

			// Wait for the server to start
			time.Sleep(1 * time.Second)

			// Configure client tls
			clientTlsConfig := &tls.Config{
				InsecureSkipVerify: true,
			}
			// Load CA certificate
			if tt.caFile != "" && tt.clientHasCA {
				// Load CA cert for client auth
				caCert, err := os.ReadFile(tt.caFile)
				if err != nil {
					t.Fatalf("Failed to read CA cert: %v", err)
				}
				caCertPool := x509.NewCertPool()
				if !caCertPool.AppendCertsFromPEM(caCert) {
					t.Fatal("Failed to parse CA cert")
				}
				clientTlsConfig.RootCAs = caCertPool
				clientTlsConfig.Certificates = []tls.Certificate{loadTestClientCert(t, certFile, keyFile)}
			}

			client := &http.Client{
				Timeout: 10 * time.Second,
				Transport: &http.Transport{
					TLSClientConfig: clientTlsConfig,
					// Allow connection reuse
					MaxIdleConns:        10,
					IdleConnTimeout:     30 * time.Second,
					DisableCompression:  true,
					TLSHandshakeTimeout: 10 * time.Second,
				},
			}

			// Make request to metrics endpoint
			resp, err := client.Get(fmt.Sprintf("https://%s:%d/metrics", host, port))
			if tt.expectError {
				Expect(err).To(HaveOccurred())
				return
			}

			defer resp.Body.Close()
			Expect(resp.StatusCode).To(Equal(tt.expectedStatus))

			if tt.rotateCertificates {
				// Rotate certificates
				err = rotateCertificates(certFile, keyFile, caFile, caKeyFile)
				if err != nil {
					t.Fatalf("Failed to rotate certificates: %v", err)
				}
				time.Sleep(1 * time.Second)

				// Make request to metrics endpoint
				resp, err := client.Get(fmt.Sprintf("https://%s:%d/metrics", host, port))
				if tt.rotateExpectError {
					Expect(err).To(HaveOccurred())
					return
				}

				defer resp.Body.Close()
				Expect(resp.StatusCode).To(Equal(tt.rotateExpectedStatus))
			}
		})
	}
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
	if err := os.WriteFile(certFile, newCert, 0644); err != nil {
		return fmt.Errorf("failed to write new certificate: %w", err)
	}
	if err := os.WriteFile(keyFile, newKey, 0644); err != nil {
		return fmt.Errorf("failed to write new key: %w", err)
	}

	return nil
}
