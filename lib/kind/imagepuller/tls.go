// Copyright (c) 2026 Tigera, Inc. All rights reserved.

package imagepuller

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"time"
)

// kindBridgeGatewayIP is the address kind nodes use to reach a service
// running on the docker host. With the default kind network this is
// 172.18.0.1. The MutatingWebhookConfiguration we register points the
// apiserver at https://172.18.0.1:<port>, so the server cert must list
// this IP as a SAN.
const kindBridgeGatewayIP = "172.18.0.1"

// generateWebhookTLSCerts mints a fresh self-signed CA and a server cert
// signed by it, scoped to the kind bridge gateway IP. The returned PEMs
// are consumed by the in-process webhook server (cert + key) and by the
// MutatingWebhookConfiguration (caBundle) so the apiserver trusts the
// server it dials.
func generateWebhookTLSCerts() (certPEM, keyPEM, caPEM []byte, err error) {
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, nil, err
	}
	caSerial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, nil, err
	}
	now := time.Now()
	caTpl := &x509.Certificate{
		SerialNumber: caSerial,
		Subject: pkix.Name{
			CommonName:   "kind-image-webhook CA",
			Organization: []string{"kind-image-webhook"},
		},
		NotBefore:             now.Add(-5 * time.Minute),
		NotAfter:              now.Add(365 * 24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		MaxPathLenZero:        true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTpl, caTpl, &caKey.PublicKey, caKey)
	if err != nil {
		return nil, nil, nil, err
	}
	caPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})

	srvKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, nil, err
	}
	srvSerial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, nil, err
	}
	srvTpl := &x509.Certificate{
		SerialNumber: srvSerial,
		Subject: pkix.Name{
			CommonName:   "kind-image-webhook",
			Organization: []string{"kind-image-webhook"},
		},
		NotBefore:             now.Add(-5 * time.Minute),
		NotAfter:              now.Add(90 * 24 * time.Hour),
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		IPAddresses:           []net.IP{net.ParseIP(kindBridgeGatewayIP)},
		BasicConstraintsValid: true,
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		return nil, nil, nil, err
	}
	srvDER, err := x509.CreateCertificate(rand.Reader, srvTpl, caCert, &srvKey.PublicKey, caKey)
	if err != nil {
		return nil, nil, nil, err
	}
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srvDER})

	keyDER, err := x509.MarshalECPrivateKey(srvKey)
	if err != nil {
		return nil, nil, nil, err
	}
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	return certPEM, keyPEM, caPEM, nil
}
