// Copyright (c) 2026 Tigera, Inc. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package syncclient_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/projectcalico/calico/typha/pkg/discovery"
	"github.com/projectcalico/calico/typha/pkg/syncclient"
	"github.com/projectcalico/calico/typha/pkg/syncproto"
)

// TestStop_WhileTLSDialBlocks is the regression test for the promotion stall.
//
// When the upstream leader Typha dies, a follower promoting to leader must tear
// down its upstream syncclient promptly.  Production Typha-to-Typha connections
// are mTLS, and the dead leader's endpoint accepts the TCP connection (or the
// address is still routable) but never completes the TLS handshake, so the
// client blocks inside the dial/handshake.  Previously the client dialed with a
// fixed timeout that ignored context cancellation (net.DialTimeout /
// tls.DialWithDialer), so Stop() blocked for the whole dial timeout (~10s),
// which surfaced as a >9s role-transition stall in the felix FV.  The dial now
// uses a context-aware dialer, so cancelling the context (what Stop() does) must
// abort the in-flight handshake promptly.
func TestStop_WhileTLSDialBlocks(t *testing.T) {
	certDir := t.TempDir()
	keyFile, certFile := writeTestCert(t, certDir)

	// Listener that accepts the raw TCP connection but never speaks TLS, so the
	// client's TLS handshake (part of the dial) blocks waiting for the server's
	// response.
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer l.Close()
	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			// Hold the connection open without ever completing the TLS handshake.
			_ = conn
		}
	}()

	c := syncclient.New(
		discovery.New(discovery.WithAddrOverride(l.Addr().String())),
		"v", "h", "i",
		&restartAwareRecorder{},
		&syncclient.Options{
			SyncerType: syncproto.SyncerTypeFelix,
			KeyFile:    keyFile,
			CertFile:   certFile,
			CAFile:     certFile,
			ServerCN:   "typha",
		},
	)

	// Start synchronously connects; because the handshake never completes it
	// returns an error, but the point under test is that Stop() / context
	// cancellation aborts the in-flight handshake promptly rather than blocking
	// for the dial timeout.  Run Start in a goroutine and cancel via Stop.
	startReturned := make(chan struct{})
	go func() {
		_ = c.Start(context.Background())
		close(startReturned)
	}()

	// Give the client time to enter the blocking TLS handshake.
	time.Sleep(200 * time.Millisecond)

	start := time.Now()
	stopped := make(chan struct{})
	go func() {
		c.Stop()
		close(stopped)
	}()

	select {
	case <-stopped:
		if elapsed := time.Since(start); elapsed > 2*time.Second {
			t.Fatalf("Stop took %v; expected it to abort the in-flight TLS handshake promptly "+
				"(dial timeout is 10s, so a regression to a ctx-ignoring dialer would block ~10s)", elapsed)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Stop blocked while client was stuck in the TLS handshake to a silent server")
	}

	select {
	case <-startReturned:
	case <-time.After(2 * time.Second):
		t.Fatal("Start did not return after Stop aborted the handshake")
	}
}

// writeTestCert generates a throwaway self-signed cert/key into dir and returns
// the key and cert file paths.  It is only used to satisfy the client's TLS
// option loading; the handshake under test never reaches verification because
// the test server never responds.
func writeTestCert(t *testing.T, dir string) (keyFile, certFile string) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "typha"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		IsCA:         true,
		DNSNames:     []string{"typha"},
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}

	certFile = filepath.Join(dir, "cert.pem")
	keyFile = filepath.Join(dir, "key.pem")
	if err := os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatalf("write cert: %v", err)
	}
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}
	return keyFile, certFile
}
