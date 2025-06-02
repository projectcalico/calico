package cryptoutils

import (
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"io"
	"time"
)

const (
	DefaultCertificateLifetime = 10 * 365 * 24 * time.Hour
)

type CA interface {
	CreateTLSCertificate(name string, opts ...CertificateOption) (*tls.Certificate, error)
	MustCreateTLSCertificate(name string, opts ...CertificateOption) *tls.Certificate
	Certificate() *x509.Certificate
	MustAddToCertPool(pool *x509.CertPool) *x509.CertPool
	AddToCertPool(pool *x509.CertPool) error
}

type certificateAuthority struct {
	cert *x509.Certificate
	key  crypto.PrivateKey
}

func NewCA(name string, opts ...CertificateOption) (CA, error) {
	cert, privateKey, err := CreateSelfSignedCertificate(name, append(
		opts,
		WithIsCA(),
		WithKeyUsages(x509.KeyUsageKeyEncipherment, x509.KeyUsageDigitalSignature, x509.KeyUsageCertSign),
	)...)

	if err != nil {
		return nil, err
	}

	return &certificateAuthority{
		cert: cert,
		key:  privateKey,
	}, nil
}

func MustGetNewCA(name string, opts ...CertificateOption) CA {
	ca, err := NewCA(name, opts...)
	if err != nil {
		panic(err)
	}

	return ca
}

func (ca *certificateAuthority) CreateTLSCertificate(name string, opts ...CertificateOption) (*tls.Certificate, error) {
	cert, privateKey, err := CreateSelfSignedCertificate(name, append(
		opts,
		WithCA(ca),
	)...)
	if err != nil {
		return nil, err
	}

	certPem, err := encodeCertificates(cert)
	if err != nil {
		return nil, err
	}

	keyPem, err := encodeKey(privateKey)
	if err != nil {
		return nil, err
	}

	tlsCert, err := tls.X509KeyPair(certPem, keyPem)
	if err != nil {
		return nil, err
	}

	return &tlsCert, nil
}

func (ca *certificateAuthority) MustCreateTLSCertificate(name string, opts ...CertificateOption) *tls.Certificate {
	tlsCert, err := ca.CreateTLSCertificate(name, opts...)
	if err != nil {
		panic(err)
	}

	return tlsCert
}

func (ca *certificateAuthority) Certificate() *x509.Certificate {
	return ca.cert
}

func (ca *certificateAuthority) AddToCertPool(pool *x509.CertPool) error {
	pool.AddCert(ca.cert)

	return nil
}

func (ca *certificateAuthority) MustAddToCertPool(pool *x509.CertPool) *x509.CertPool {
	pool.AddCert(ca.cert)
	return pool
}

func (ca *certificateAuthority) WriteCertificates(w io.Writer) error {
	byts, err := encodeCertificates(ca.cert)
	if err != nil {
		return err
	}
	if _, err := w.Write(byts); err != nil {
		return err
	}
	return nil
}
