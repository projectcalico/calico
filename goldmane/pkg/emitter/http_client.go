package emitter

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/linseed/pkg/client/rest"
)

func newHTTPClient(caCert, clientKey, clientCert, serverName string) (*http.Client, error) {
	// Create a new HTTP client.
	tlsConfig := &tls.Config{ServerName: serverName}
	if caCert != "" {
		caCertPool := x509.NewCertPool()
		caCert, err := os.ReadFile(caCert)
		if err != nil {
			return nil, fmt.Errorf("error reading CA file: %s", err)
		}
		ok := caCertPool.AppendCertsFromPEM(caCert)
		if !ok {
			return nil, fmt.Errorf("failed to parse root certificate")
		}
		tlsConfig.RootCAs = caCertPool
	}

	// Create a custom dialer so that we can configure a dial timeout.
	// If we can't connect to the server within 10 seconds, something is up.
	// Note: this is not the same as the request timeout, which is handled via the
	// provided context on a per-request basis.
	dialWithTimeout := func(network, addr string) (net.Conn, error) {
		return net.DialTimeout(network, addr, 10*time.Second)
	}
	httpTransport := &http.Transport{
		Dial:            dialWithTimeout,
		TLSClientConfig: tlsConfig,
	}

	if clientKey != "" && clientCert != "" {
		clientCert, err := tls.LoadX509KeyPair(clientCert, clientKey)
		if err != nil {
			return nil, fmt.Errorf("error load cert key pair for linseed client: %s", err)
		}
		httpTransport.TLSClientConfig.Certificates = []tls.Certificate{clientCert}
		logrus.Info("Using provided client certificates for mTLS")
	}
	return &http.Client{
		Transport: httpTransport,
	}, nil
}

func newEmitterClient(url, caCert, clientKey, clientCert, serverName string) (*emitterClient, error) {
	client, err := newHTTPClient(caCert, clientKey, clientCert, serverName)
	if err != nil {
		return nil, err
	}
	return &emitterClient{url: url, client: client}, nil
}

type emitterClient struct {
	url    string
	client *http.Client
}

func (e *emitterClient) Post(body io.Reader) error {
	resp, err := e.client.Post(e.url, rest.ContentTypeMultilineJSON, body)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status code: %s", resp.Status)
	}
	logrus.WithField("body", resp.Body).Debug("Successfully posted flows")
	return nil
}
