package cryptoutils

import (
	"crypto/x509"
)

type CertificateOption func(*certificateTemplate) error

func WithDNSNames(dnsNames ...string) CertificateOption {
	return func(c *certificateTemplate) error {
		c.DNSNames = dnsNames
		return nil
	}
}

func WithKeyUsages(usages ...x509.KeyUsage) CertificateOption {
	return func(c *certificateTemplate) error {
		for _, usage := range usages {
			c.KeyUsage |= usage
		}
		return nil
	}
}

func WithExtKeyUsages(keyUsages ...x509.ExtKeyUsage) CertificateOption {
	return func(c *certificateTemplate) error {
		c.ExtKeyUsage = keyUsages
		return nil
	}
}

func WithIsCA() CertificateOption {
	return func(c *certificateTemplate) error {
		c.IsCA = true
		return nil
	}
}

func WithCA(ca *certificateAuthority) CertificateOption {
	return func(c *certificateTemplate) error {
		c.ca = ca
		return nil
	}
}
