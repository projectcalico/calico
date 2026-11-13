// Copyright (c) 2026 Tigera, Inc. All rights reserved.

package istio

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"sort"
	"time"
)

const (
	// CACertsSecretName is the Secret istiod reads its signing CA and trust roots from.
	CACertsSecretName = "cacerts"
	// OperatorCASecretName is the Secret in the operator namespace that persists the
	// operator-managed CA across reconciles and Istio CR lifetimes.
	OperatorCASecretName = "tigera-istio-ca"
	// IstioSelfSignedCASecretName is where istiod persists the CA it generates itself.
	IstioSelfSignedCASecretName = "istio-ca-secret"
	// SelfSignedCARetiredAnnotation marks istio-ca-secret once the mesh no
	// longer trusts its root, with the fingerprints of that root, so a Secret
	// istiod writes again with a new root does not read as retired.
	SelfSignedCARetiredAnnotation = "operator.tigera.io/istio-ca-retired"
	// TrustAnchorsConfigMapName publishes this cluster's own roots and trust domain
	// for its peers to read.
	TrustAnchorsConfigMapName = "istio-trust-anchors"

	// Keys of Istio's plug-in CA layout, used by cacerts and by the operator CA Secret.
	CACertKey    = "ca-cert.pem"
	CAKeyKey     = "ca-key.pem"
	CertChainKey = "cert-chain.pem"
	RootCertKey  = "root-cert.pem"
	// TrustDomainKey holds the trust domain in the published ConfigMap.
	TrustDomainKey = "trust-domain"

	// CACertsLabel marks a cacerts Secret the operator rendered, so it can be told
	// from one a user made. Its value is the CASource the bundle was built from.
	CACertsLabel = "operator.tigera.io/istio-cacerts"
	// CACertsHashAnnotation on the istiod pod template rolls istiod when cacerts changes.
	CACertsHashAnnotation = "hash.operator.tigera.io/cacerts"

	DefaultTrustDomain = "cluster.local"

	// The operator-managed CA takes the key type and validity istiod gives its own
	// self-signed CA, so the two kinds of root behave the same in a mesh.
	operatorCAKeyBits    = 2048
	operatorCAValidity   = 3650 * 24 * time.Hour
	operatorCANamePrefix = "tigera-operator-istio-ca"

	pemTypeCertificate = "CERTIFICATE"
)

// CASource names where the local CA came from.
type CASource string

const (
	CASourceOperatorManaged CASource = "operatorManaged"
	// CASourceSelfSigned is the CA istiod generated for itself, read from
	// istio-ca-secret; it signs only until a transition away from it switches.
	CASourceSelfSigned CASource = "selfSigned"
	// CASourceUnmanaged is a cacerts Secret the operator did not create.
	CASourceUnmanaged CASource = "unmanaged"
)

// CA is a validated signing CA together with the roots it is trusted through.
type CA struct {
	// CertPEM is the signing certificate and KeyPEM its private key.
	CertPEM []byte
	KeyPEM  []byte
	// Chain is the signing certificate followed by its issuers, ending with a root.
	Chain []*x509.Certificate
	// Roots are the roots the signing certificate chains to. They are what this
	// cluster publishes for its peers.
	Roots []*x509.Certificate
}

// GenerateCA makes a self-signed root CA for the trust domain.
func GenerateCA(trustDomain string) (*CA, error) {
	key, err := rsa.GenerateKey(rand.Reader, operatorCAKeyBits)
	if err != nil {
		return nil, fmt.Errorf("generating the CA key: %w", err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("generating the CA serial number: %w", err)
	}
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			Organization: []string{trustDomain},
			CommonName:   fmt.Sprintf("%s@%d", operatorCANamePrefix, now.Unix()),
		},
		NotBefore:             now,
		NotAfter:              now.Add(operatorCAValidity),
		KeyUsage:              x509.KeyUsageCertSign,
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return nil, fmt.Errorf("creating the CA certificate: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("parsing the CA certificate: %w", err)
	}
	return &CA{
		CertPEM: EncodeCertificates(cert),
		KeyPEM:  pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}),
		Chain:   []*x509.Certificate{cert},
		Roots:   []*x509.Certificate{cert},
	}, nil
}

// SecretData returns the CA in Istio's plug-in layout, trusting only its own roots.
func (c *CA) SecretData() map[string][]byte {
	return map[string][]byte{
		CACertKey:    c.CertPEM,
		CAKeyKey:     c.KeyPEM,
		CertChainKey: EncodeCertificates(c.Chain...),
		RootCertKey:  ComposeRootBundle(c.Roots),
	}
}

// LoadCA reads a CA from Secret data in Istio's plug-in layout (ca-cert.pem,
// ca-key.pem, cert-chain.pem, root-cert.pem). It is accepted only when the
// private key matches the certificate, the certificate is a CA and it chains to
// a root in the supplied roots.
func LoadCA(data map[string][]byte) (*CA, error) {
	certPEM, keyPEM, chainPEM, rootPEM := data[CACertKey], data[CAKeyKey], data[CertChainKey], data[RootCertKey]
	certKey, keyKey, rootKey := CACertKey, CAKeyKey, RootCertKey
	if len(certPEM) == 0 || len(keyPEM) == 0 || len(rootPEM) == 0 {
		return nil, fmt.Errorf("expected keys %s, %s and %s (with %s)", CACertKey, CAKeyKey, RootCertKey, CertChainKey)
	}

	certs, err := ParseCertificates(certPEM)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", certKey, err)
	}
	cert := certs[0]
	if !cert.BasicConstraintsValid || !cert.IsCA {
		return nil, fmt.Errorf("%s: the certificate is not a CA", certKey)
	}
	// Go's chain verification ignores key usage, but ztunnel does not accept a
	// certificate from a CA that may not sign certificates.
	if cert.KeyUsage != 0 && cert.KeyUsage&x509.KeyUsageCertSign == 0 {
		return nil, fmt.Errorf("%s: the key usage does not allow certificate signing", certKey)
	}
	key, err := parsePrivateKey(keyPEM)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", keyKey, err)
	}
	if !publicKeysEqual(cert.PublicKey, key.Public()) {
		return nil, fmt.Errorf("%s does not match the certificate in %s", keyKey, certKey)
	}
	roots, err := ParseCACertificates(rootPEM)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", rootKey, err)
	}

	intermediates := x509.NewCertPool()
	for _, c := range certs[1:] {
		intermediates.AddCert(c)
	}
	if len(chainPEM) > 0 {
		chain, err := ParseCertificates(chainPEM)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", CertChainKey, err)
		}
		for _, c := range chain {
			intermediates.AddCert(c)
		}
	}
	rootPool := x509.NewCertPool()
	for _, r := range roots {
		rootPool.AddCert(r)
	}
	// A workload certificate is both a TLS client and a TLS server, and an
	// extended key usage on the CA or an issuer limits what it may sign. One
	// verification per usage, because Verify accepts a chain that allows any one.
	var chains [][]*x509.Certificate
	for _, usage := range []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth} {
		chains, err = cert.Verify(x509.VerifyOptions{
			Roots:         rootPool,
			Intermediates: intermediates,
			KeyUsages:     []x509.ExtKeyUsage{usage},
		})
		var invalid x509.CertificateInvalidError
		if errors.As(err, &invalid) && invalid.Reason == x509.IncompatibleUsage {
			return nil, fmt.Errorf("%s: the extended key usage of the chain does not allow TLS client and server authentication", certKey)
		}
		if err != nil {
			return nil, fmt.Errorf("%s does not chain to a root in %s: %w", certKey, rootKey, err)
		}
	}

	ca := &CA{CertPEM: EncodeCertificates(cert), KeyPEM: keyPEM, Chain: chains[0]}
	own := map[string]bool{}
	for _, chain := range chains {
		root := chain[len(chain)-1]
		if !own[string(root.Raw)] {
			own[string(root.Raw)] = true
			ca.Roots = append(ca.Roots, root)
		}
	}
	return ca, nil
}

// ParseCertificates decodes every PEM block, each of which must be a CERTIFICATE.
func ParseCertificates(pemData []byte) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	for rest := pemData; ; {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != pemTypeCertificate {
			return nil, fmt.Errorf("PEM block %d is a %s, not a CERTIFICATE", len(certs)+1, block.Type)
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("certificate %d: %w", len(certs)+1, err)
		}
		certs = append(certs, cert)
	}
	if len(certs) == 0 {
		return nil, errors.New("no PEM certificate found")
	}
	return certs, nil
}

// ParseCACertificates is ParseCertificates requiring every certificate to be a CA.
func ParseCACertificates(pemData []byte) ([]*x509.Certificate, error) {
	certs, err := ParseCertificates(pemData)
	if err != nil {
		return nil, err
	}
	for i, c := range certs {
		if !c.BasicConstraintsValid || !c.IsCA {
			return nil, fmt.Errorf("certificate %d is not a CA", i+1)
		}
	}
	return certs, nil
}

// ComposeRootBundle PEM-encodes the union of the given roots, deduplicated by DER
// bytes and sorted by them, so the same set always gives the same bytes.
func ComposeRootBundle(roots ...[]*x509.Certificate) []byte {
	seen := map[string]bool{}
	var unique []*x509.Certificate
	for _, set := range roots {
		for _, r := range set {
			if !seen[string(r.Raw)] {
				seen[string(r.Raw)] = true
				unique = append(unique, r)
			}
		}
	}
	sort.Slice(unique, func(i, j int) bool { return bytes.Compare(unique[i].Raw, unique[j].Raw) < 0 })
	return EncodeCertificates(unique...)
}

// EncodeCertificates PEM-encodes the certificates in the order given.
func EncodeCertificates(certs ...*x509.Certificate) []byte {
	var out []byte
	for _, c := range certs {
		out = append(out, pem.EncodeToMemory(&pem.Block{Type: pemTypeCertificate, Bytes: c.Raw})...)
	}
	return out
}

func parsePrivateKey(pemData []byte) (crypto.Signer, error) {
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, errors.New("no PEM private key found")
	}
	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	if key, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		signer, ok := key.(crypto.Signer)
		if !ok {
			return nil, errors.New("the private key type cannot sign")
		}
		return signer, nil
	}
	if key, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	return nil, errors.New("the private key is not PKCS#1, PKCS#8 or SEC 1 encoded")
}

func publicKeysEqual(a, b crypto.PublicKey) bool {
	eq, ok := a.(interface{ Equal(crypto.PublicKey) bool })
	return ok && eq.Equal(b)
}
