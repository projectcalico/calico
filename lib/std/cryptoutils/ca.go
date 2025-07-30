package cryptoutils

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	mathrand "math/rand"
	"net"
	"time"
)

type CA interface {
	AddToCertPool(pool *x509.CertPool) error
	CreateServerCert(name string, hosts []string) (*TLSCertificate, error)
	SignCertificate(template *x509.Certificate, requestKey crypto.PublicKey) (*x509.Certificate, error)
	WriteCertificates(w io.Writer) error
}

type certificateAuthority struct {
	cfg *TLSCertificate
}

type TLSCertificate struct {
	certs []*x509.Certificate
	key   crypto.PrivateKey
}

func NewCA(name string) (CA, error) {
	rootCAPublicKey, rootCAPrivateKey, publicKeyHash, err := newKeyPairWithHash()
	if err != nil {
		return nil, err
	}

	subject := pkix.Name{CommonName: name}

	// AuthorityKeyId and SubjectKeyId should match for a self-signed CA
	authorityKeyId := publicKeyHash
	subjectKeyId := publicKeyHash

	caLifetime := 10 * 365 * 24 * time.Hour

	rootCATemplate := &x509.Certificate{
		Subject: subject,

		SignatureAlgorithm: x509.SHA256WithRSA,

		NotBefore: time.Now().Add(-1 * time.Second),
		NotAfter:  time.Now().Add(caLifetime),

		// Specify a random serial number to avoid the same issuer+serial
		// number referring to different certs in a chain of trust if the
		// signing certificate is ever rotated.
		SerialNumber: big.NewInt(randomSerialNumber()),

		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,

		AuthorityKeyId: authorityKeyId,
		SubjectKeyId:   subjectKeyId,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, rootCATemplate, rootCATemplate, rootCAPublicKey, rootCAPrivateKey)
	if err != nil {
		return nil, err
	}
	certs, err := x509.ParseCertificates(derBytes)
	if err != nil {
		return nil, err
	}
	if len(certs) != 1 {
		return nil, errors.New("expected a single certificate")
	}

	rootCACert := certs[0]

	return &certificateAuthority{
		cfg: &TLSCertificate{
			certs: []*x509.Certificate{rootCACert},
			key:   rootCAPrivateKey,
		},
	}, nil
}

func (ca *certificateAuthority) CreateServerCert(name string, hosts []string) (*TLSCertificate, error) {
	serverPublicKey, serverPrivateKey, publicKeyHash, err := newKeyPairWithHash()
	if err != nil {
		return nil, err
	}

	authorityKeyId := ca.cfg.certs[0].SubjectKeyId
	subjectKeyId := publicKeyHash

	subject := pkix.Name{CommonName: name}
	caLifetime := 10 * 365 * 24 * time.Hour
	serverTemplate := &x509.Certificate{
		Subject: subject,

		SignatureAlgorithm: x509.SHA256WithRSA,

		NotBefore:    time.Now().Add(-1 * time.Second),
		NotAfter:     time.Now().Add(caLifetime),
		SerialNumber: big.NewInt(1),

		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,

		AuthorityKeyId: authorityKeyId,
		SubjectKeyId:   subjectKeyId,
	}

	serverTemplate.IPAddresses, serverTemplate.DNSNames = ipAddressesDNSNames(hosts)

	serverCrt, err := ca.SignCertificate(serverTemplate, serverPublicKey)
	if err != nil {
		return nil, err
	}

	return &TLSCertificate{
		certs: append([]*x509.Certificate{serverCrt}, ca.cfg.certs...),
		key:   serverPrivateKey,
	}, nil
}

func (ca *certificateAuthority) SignCertificate(template *x509.Certificate, requestKey crypto.PublicKey) (*x509.Certificate, error) {
	// Increment and persist serial
	serial := randomSerialNumber()

	template.SerialNumber = big.NewInt(serial)
	return signCertificate(template, requestKey, ca.cfg.certs[0], ca.cfg.key)
}

func (ca *certificateAuthority) AddToCertPool(pool *x509.CertPool) error {
	for _, cert := range ca.cfg.certs {
		pool.AddCert(cert)
	}

	return nil
}

func (ca *certificateAuthority) WriteCertificates(w io.Writer) error {
	byts, err := encodeCertificates(ca.cfg.certs...)
	if err != nil {
		return err
	}
	if _, err := w.Write(byts); err != nil {
		return err
	}
	return nil
}

func (cert *TLSCertificate) WriteCertificates(w io.Writer) error {
	byts, err := encodeCertificates(cert.certs...)
	if err != nil {
		return err
	}
	if _, err := w.Write(byts); err != nil {
		return err
	}
	return nil
}

func encodeCertificates(certs ...*x509.Certificate) ([]byte, error) {
	b := bytes.Buffer{}
	for _, cert := range certs {
		if err := pem.Encode(&b, &pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}); err != nil {
			return []byte{}, err
		}
	}
	return b.Bytes(), nil
}

func (cert *TLSCertificate) WritePrivateKey(w io.Writer) error {
	byts, err := encodeKey(cert.key)
	if err != nil {
		return err
	}
	if _, err := w.Write(byts); err != nil {
		return err
	}

	return nil
}

func encodeKey(key crypto.PrivateKey) ([]byte, error) {
	b := bytes.Buffer{}
	switch key := key.(type) {
	case *ecdsa.PrivateKey:
		keyBytes, err := x509.MarshalECPrivateKey(key)
		if err != nil {
			return []byte{}, err
		}
		if err := pem.Encode(&b, &pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes}); err != nil {
			return b.Bytes(), err
		}
	case *rsa.PrivateKey:
		if err := pem.Encode(&b, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}); err != nil {
			return []byte{}, err
		}
	default:
		return []byte{}, errors.New("unrecognized key type")

	}
	return b.Bytes(), nil
}

func signCertificate(template *x509.Certificate, requestKey crypto.PublicKey, issuer *x509.Certificate, issuerKey crypto.PrivateKey) (*x509.Certificate, error) {
	derBytes, err := x509.CreateCertificate(rand.Reader, template, issuer, requestKey, issuerKey)
	if err != nil {
		return nil, err
	}
	certs, err := x509.ParseCertificates(derBytes)
	if err != nil {
		return nil, err
	}
	if len(certs) != 1 {
		return nil, errors.New("expected a single certificate")
	}
	return certs[0], nil
}

func ipAddressesDNSNames(hosts []string) ([]net.IP, []string) {
	var ips []net.IP
	var dns []string
	for _, host := range hosts {
		if ip := net.ParseIP(host); ip != nil {
			ips = append(ips, ip)
		} else {
			dns = append(dns, host)
		}
	}

	// Include IP addresses as DNS subjectAltNames in the cert as well, for the sake of Python, Windows (< 10), and unnamed other libraries
	// Ensure these technically invalid DNS subjectAltNames occur after the valid ones, to avoid triggering cert errors in Firefox
	// See https://bugzilla.mozilla.org/show_bug.cgi?id=1148766
	for _, ip := range ips {
		dns = append(dns, ip.String())
	}

	return ips, dns
}

// randomSerialNumber returns a random int64 serial number based on
// time.Now. It is defined separately from the generator interface so
// that the caller doesn't have to worry about an input template or
// error - these are unnecessary when creating a random serial.
func randomSerialNumber() int64 {
	r := mathrand.New(mathrand.NewSource(time.Now().UTC().UnixNano()))
	return r.Int63()
}

func newKeyPairWithHash() (crypto.PublicKey, crypto.PrivateKey, []byte, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, nil, err
	}

	publicKey := &privateKey.PublicKey
	var publicKeyHash []byte
	hash := sha1.New()
	hash.Write(publicKey.N.Bytes())
	publicKeyHash = hash.Sum(nil)

	return publicKey, privateKey, publicKeyHash, err
}
