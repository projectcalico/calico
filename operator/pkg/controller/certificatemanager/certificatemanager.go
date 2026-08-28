// Copyright (c) 2025-2026 Tigera, Inc. All rights reserved.

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

package certificatemanager

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"strings"
	"time"

	"github.com/go-logr/logr"
	"github.com/openshift/library-go/pkg/crypto"
	corev1 "k8s.io/api/core/v1"
	kerrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/sets"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	operatorv1 "github.com/projectcalico/calico/operator/api/v1"
	"github.com/projectcalico/calico/operator/pkg/controller/status"
	"github.com/projectcalico/calico/operator/pkg/controller/utils/imageset"
	rmeta "github.com/projectcalico/calico/operator/pkg/render/common/meta"
	"github.com/projectcalico/calico/operator/pkg/tls"
	"github.com/projectcalico/calico/operator/pkg/tls/certificatemanagement"
	"github.com/projectcalico/calico/operator/pkg/tls/certkeyusage"
)

const (
	// OperatorCSRSignerName when this value is set as a signer on a CSR, the CSR controller will handle
	// the request.
	OperatorCSRSignerName = "tigera.io/operator-signer"
	// GRACE_PERIOD is when we start rolling out a new certificate, during which the current cert is still valid (30d).
	gracePeriod = 30 * 24 * time.Hour
)

var log = logf.Log.WithName("tls")

func ErrInvalidCertDNSNames(secretName, secretNamespace string) error {
	log.V(1).Info("Certificate has wrong DNS names", "namespace", secretNamespace, "name", secretName)
	return fmt.Errorf("certificate %s/%s has the wrong DNS names", secretNamespace, secretName)
}

func errNoPrivateKeyPEM(secretName, secretNamespace string) error {
	return fmt.Errorf("key pair %s/%s is missing a private key", secretNamespace, secretName)
}

func errNoCertificatePEM(secretName, secretNamespace string) error {
	return fmt.Errorf("certificate PEM is missing for %s/%s ", secretNamespace, secretName)
}

type certificateManager struct {
	*x509.Certificate
	*crypto.CA
	keyPair *certificatemanagement.KeyPair
	log     logr.Logger

	// caSecretName is the secret holding the CA this instance signs with.
	caSecretName string

	// Controls whether this instance of the certificate manager is allowed to
	// create new CAs. Most instances should simply read the existing CA and use it to sign
	// certificates.
	allowCACreation bool
}

// CertificateManager can sign new certificates and has methods to retrieve existing KeyPairs and Certificates. If a user
// brings their own secrets, CertificateManager will preserve and return them.
type CertificateManager interface {
	// GetKeyPair returns an existing KeyPair. In normal operation, if the KeyPair is not found, nil is returned.
	// However, when certificate management is enabled keypairs are not written to the cluster. In this case, the keypair returned by this function
	// is an implementation of KeyPairInterface using the provided dnsNames.
	GetKeyPair(cli client.Client, secretName, secretNamespace string, dnsNames []string) (certificatemanagement.KeyPairInterface, error)
	// GetOrCreateKeyPair returns a KeyPair. If one exists, some checks are performed. Otherwise, a new KeyPair is created.
	GetOrCreateKeyPair(cli client.Client, secretName, secretNamespace string, dnsNames []string) (certificatemanagement.KeyPairInterface, error)
	// CreateCSRKeyPair returns a KeyPair that relies on issuing Certificate Signing Requests to the kubernetes api to be
	// signed by OperatorCSRSignerName. This means that pkg/controller/csr/csr_controller.go will end up signing the CSR
	// using the private key of the certificate manager.
	CreateCSRKeyPair(secretName, secretNamespace string, dnsNames []string) certificatemanagement.KeyPairInterface
	// GetCertificate returns a Certificate. If the certificate is not found, nil is returned.
	GetCertificate(cli client.Client, secretName, secretNamespace string) (certificatemanagement.CertificateInterface, error)
	// CreateTrustedBundle creates a TrustedBundle, which provides standardized methods for mounting a bundle of certificates to trust.
	// It will include:
	// - A bundle with Calico's root certificates + any user supplied certificates in /etc/pki/tls/certs/tigera-ca-bundle.crt.
	CreateTrustedBundle(certificates ...certificatemanagement.CertificateInterface) certificatemanagement.TrustedBundle
	CreateNamedTrustedBundleFromSecrets(name string, cli client.Client, namespace string, systemRoot bool, secrets ...string) (certificatemanagement.TrustedBundle, error)
	// CreateTrustedBundleWithSystemRootCertificates creates a TrustedBundle, which provides standardized methods for mounting a bundle of certificates to trust.
	// It will include:
	// - A bundle with Calico's root certificates + any user supplied certificates in /etc/pki/tls/certs/tigera-ca-bundle.crt.
	// - A system root certificate bundle in /etc/pki/tls/certs/ca-bundle.crt.
	CreateTrustedBundleWithSystemRootCertificates(certificates ...certificatemanagement.CertificateInterface) (certificatemanagement.TrustedBundle, error)
	// AddToStatusManager lets the status manager monitor pending CSRs if the certificate management is enabled.
	AddToStatusManager(manager status.StatusManager, namespace string)
	// KeyPair Returns the CA KeyPairInterface, so it can be rendered in the operator namespace.
	KeyPair() certificatemanagement.KeyPairInterface
	// LoadTrustedBundle loads an existing trusted bundle to pass to render.
	LoadTrustedBundle(context.Context, client.Client, string) (certificatemanagement.TrustedBundleRO, error)
	LoadNamedTrustedBundle(context.Context, client.Client, string, string) (certificatemanagement.TrustedBundleRO, error)
	// SignCertificate signs a certificate using the certificate manager's private key. The function is assuming that the
	// public key of the requestor is already set in the certificate template.
	SignCertificate(certificate *x509.Certificate) ([]byte, error)
	// CACertCommonName returns the CommonName from the CA certificate's Subject field.
	CACertCommonName() string
}

type Option func(cm *certificateManager) error

func AllowCACreation() Option {
	return func(cm *certificateManager) error {
		cm.allowCACreation = true
		return nil
	}
}

func WithLogger(log logr.Logger) Option {
	return func(cm *certificateManager) error {
		cm.log = log
		return nil
	}
}

// WithCASecretName overrides the secret the CA is read from. Callers that manage more
// than one CA in a cluster use this to keep them apart.
func WithCASecretName(name string) Option {
	return func(cm *certificateManager) error {
		cm.caSecretName = name
		return nil
	}
}

// Create creates a signer of new certificates and has methods to retrieve existing KeyPairs and Certificates. If a user
// brings their own secrets, CertificateManager will preserve and return them.
func Create(cli client.Client, installation *operatorv1.InstallationSpec, clusterDomain, ns string, opts ...Option) (CertificateManager, error) {
	var (
		cryptoCA *crypto.CA
		csrImage string
		// The private key is of type any, as this is the interface used in the x509 package for all private key types.
		privateKey                    any
		privateKeyPEM, certificatePEM []byte
		certificateManagement         *operatorv1.CertificateManagement
		err                           error
	)

	// Create a certificatemanager instance and apply any user-provided options to
	// initialize it.
	cm := &certificateManager{log: log, caSecretName: certificatemanagement.CASecretName}
	for _, opt := range opts {
		if err := opt(cm); err != nil {
			return nil, err
		}
	}
	cm.log.V(2).Info("Creating CertificateManager in namespace", "ns", ns)

	var certificateManagementEnabled bool
	if installation != nil {
		imageSet, err := imageset.GetImageSet(context.Background(), cli, installation.Variant)
		if err != nil {
			return nil, err
		}
		// We instantiate csrImage regardless of whether certificate management is enabled; it may still be used.
		csrImage, err = certificatemanagement.ResolveCSRInitImage(installation, imageSet)
		if err != nil {
			return nil, err
		}

		if installation.CertificateManagement != nil {
			// Configured to use certificate management. Get the CACert from
			// the installation spec.
			certificateManagement = installation.CertificateManagement
			certificatePEM = certificateManagement.CACert
			certificateManagementEnabled = true
		}
	}

	if !certificateManagementEnabled {
		// Using operator-managed certificates. Check to see if we have already provisioned a CA.
		cm.log.V(2).Info("Looking for an existing CA", "secret", fmt.Sprintf("%s/%s", ns, cm.caSecretName))
		caSecret := &corev1.Secret{}
		k := types.NamespacedName{Name: cm.caSecretName, Namespace: ns}
		if err = cli.Get(context.Background(), k, caSecret); err != nil && !kerrors.IsNotFound(err) {
			return nil, err
		} else if kerrors.IsNotFound(err) {
			cm.log.V(2).Info("No existing CA secret")
		}

		if len(caSecret.Data) == 0 ||
			len(caSecret.Data[corev1.TLSPrivateKeyKey]) == 0 ||
			len(caSecret.Data[corev1.TLSCertKey]) == 0 {

			if !cm.allowCACreation {
				// Most controllers should NOT allow CA creation. For single-tenant, this is handled at cluster startup by the secret controller.
				// For multi-tenant clusters, each tenant has its own CA that is created by the tenant controller.
				return nil, fmt.Errorf("CA secret %s/%s does not exist yet and is not allowed for this call", ns, cm.caSecretName)
			}
			// No existing CA data - we need to generate a new one.
			cm.log.Info("Generating a new CA", "namespace", ns)
			cryptoCA, err = tls.MakeCA(rmeta.TigeraOperatorCAIssuerPrefix)
			if err != nil {
				return nil, err
			}
			keyContent, crtContent := &bytes.Buffer{}, &bytes.Buffer{}
			if err := cryptoCA.Config.WriteCertConfig(crtContent, keyContent); err != nil {
				return nil, err
			}
			privateKey, privateKeyPEM, certificatePEM = cryptoCA.Config.Key, keyContent.Bytes(), crtContent.Bytes()
		} else {
			// Found an existing CA - use that.
			cm.log.V(2).Info("Found an existing CA secret")
			privateKeyPEM, certificatePEM = caSecret.Data[corev1.TLSPrivateKeyKey], caSecret.Data[corev1.TLSCertKey]
			privateKeyDER, _ := pem.Decode(privateKeyPEM)
			if privateKeyDER == nil {
				return nil, fmt.Errorf("cannot parse private tls.key PEM from the CA bundle")
			}
			// Parse in order of likelihood of format. If the tigera-ca-private secret is not replaced with a custom one,
			// the certificate is PKCS1 formatted. (The x509 package also uses parsing as the way to identifying the type.)
			if privateKey, err = x509.ParsePKCS1PrivateKey(privateKeyDER.Bytes); err != nil {
				if privateKey, err = x509.ParsePKCS8PrivateKey(privateKeyDER.Bytes); err != nil {
					if privateKey, err = x509.ParseECPrivateKey(privateKeyDER.Bytes); err != nil {
						return nil, fmt.Errorf("cannot parse private key from the CA bundle")
					}
				}
			}
			cryptoCA, err = crypto.GetCAFromBytes(certificatePEM, privateKeyPEM)
			if err != nil {
				return nil, err
			}
		}
	}

	// At this point, we've located an existing CA or generated a new one. Build a certificateManager
	// instance based on it.
	x509Cert, err := certificatemanagement.ParseCertificate(certificatePEM)
	if err != nil {
		return nil, err
	}

	// Fill in remaining fields.
	cm.CA = cryptoCA
	cm.Certificate = x509Cert
	cm.keyPair = &certificatemanagement.KeyPair{
		Name:                  cm.caSecretName,
		Namespace:             ns,
		PrivateKey:            privateKey,
		PrivateKeyPEM:         privateKeyPEM,
		CertificatePEM:        certificatePEM,
		CSRImage:              csrImage,
		ClusterDomain:         clusterDomain,
		CertificateManagement: certificateManagement,
	}

	cm.log.V(2).Info("Created CertificateManager", "ns", ns, "authority", cm.AuthorityKeyId)
	return cm, nil
}

func (cm *certificateManager) KeyPair() certificatemanagement.KeyPairInterface {
	return cm.keyPair
}

// AddToStatusManager lets the status manager monitor pending CSRs if the certificate management is enabled.
func (cm *certificateManager) AddToStatusManager(statusManager status.StatusManager, namespace string) {
	if cm.CertificateManagement() != nil {
		statusManager.AddCertificateSigningRequests(namespace, map[string]string{"k8s-app": namespace})
	} else {
		statusManager.RemoveCertificateSigningRequests(namespace)
	}
}

func (cm *certificateManager) CreateCSRKeyPair(secretName, namespace string, dnsNames []string) certificatemanagement.KeyPairInterface {
	return &certificatemanagement.KeyPair{
		Name: secretName,
		CertificateManagement: &operatorv1.CertificateManagement{
			CACert:     cm.keyPair.CertificatePEM,
			SignerName: OperatorCSRSignerName,
		},
		DNSNames:       dnsNames,
		CSRImage:       cm.keyPair.CSRImage,
		Namespace:      namespace,
		CertificatePEM: cm.keyPair.CertificatePEM,
	}
}

// GetOrCreateKeyPair returns a KeyPair. If one exists, some checks are performed. Otherwise, a new KeyPair is created.
func (cm *certificateManager) GetOrCreateKeyPair(cli client.Client, secretName, secretNamespace string, dnsNames []string) (certificatemanagement.KeyPairInterface, error) {
	keyPair, x509Cert, err := cm.getKeyPair(cli, secretName, secretNamespace, false, dnsNames)
	if keyPair != nil && keyPair.UseCertificateManagement() {
		return certificateManagementKeyPair(cm, secretName, secretNamespace, dnsNames), nil
	}
	if err != nil && !kerrors.IsNotFound(err) {
		return nil, err
	} else if keyPair != nil {
		err = HasExpectedDNSNames(secretName, secretNamespace, x509Cert, dnsNames)
		if err == nil {
			return keyPair, nil
		} else if keyPair.BYO() {
			cm.log.V(3).Info("secret %s has invalid DNS names, the expected names are: %v", secretName, dnsNames)
			return keyPair, nil
		}
	} else {
		cm.log.V(1).Info("Keypair wasn't found, create a new one", "namespace", secretNamespace, "name", secretName)
	}

	// If we reach here, it means we need to create a new KeyPair.
	tlsCfg, err := cm.MakeServerCertForDuration(sets.New[string](dnsNames...), tls.DefaultCertificateDuration, tls.SetServerAuth, tls.SetClientAuth)
	if err != nil {
		return nil, fmt.Errorf("unable to create signed cert pair: %s", err)
	}
	keyContent, crtContent := &bytes.Buffer{}, &bytes.Buffer{}
	if err := tlsCfg.WriteCertConfig(crtContent, keyContent); err != nil {
		return nil, err
	}

	return &certificatemanagement.KeyPair{
		Issuer:         cm.keyPair,
		Name:           secretName,
		Namespace:      secretNamespace,
		PrivateKeyPEM:  keyContent.Bytes(),
		CertificatePEM: crtContent.Bytes(),
		DNSNames:       dnsNames,
	}, nil
}

// SignCertificate signs a certificate using the certificate manager's private key. The function is assuming that the
// public key of the requestor is already set in the certificate template.
func (cm *certificateManager) SignCertificate(certificateTemplate *x509.Certificate) ([]byte, error) {
	derBytes, err := x509.CreateCertificate(rand.Reader, certificateTemplate, cm.Certificate, certificateTemplate.PublicKey, cm.keyPair.PrivateKey)
	if err != nil {
		return nil, err
	}
	pemBytes := bytes.NewBuffer([]byte{})
	err = pem.Encode(pemBytes, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	if err != nil {
		log.Error(err, "error encoding certificate PEM")
		return nil, err
	}
	return pemBytes.Bytes(), nil
}

// CertExtKeyUsageError This type will be returned for errors that do not have the correct Ext Key usage types
// for a specific secert certificate.
type CertExtKeyUsageError struct {
	msg string
}

func (cue *CertExtKeyUsageError) Error() string {
	return cue.msg
}

var _ error = &CertExtKeyUsageError{}

// Returns true if the error is a CertExtKeyUsageError
func IsCertExtKeyUsageError(err error) bool {
	_, ok := err.(*CertExtKeyUsageError)
	return ok
}

func extKeyUsageToString(requiredExtKeyUsages []x509.ExtKeyUsage) string {
	out := ""
	for i, x := range requiredExtKeyUsages {
		if i != 0 {
			out = out + ", "
		}
		switch x {
		case x509.ExtKeyUsageServerAuth:
			out = out + "ExtKeyUsageServerAuth"
		case x509.ExtKeyUsageClientAuth:
			out = out + "ExtKeyUsageClientAuth"
		default:
			out = out + "unknown"
		}

	}
	return out
}

func newCertExtKeyUsageError(name, ns string, requiredExtKeyUsages []x509.ExtKeyUsage) error {
	return &CertExtKeyUsageError{
		fmt.Sprintf(
			"secret %s/%s must specify ext key usages: %+v",
			ns, name, extKeyUsageToString(requiredExtKeyUsages)),
	}
}

// getKeyPair is an internal convenience method to retrieve a keypair or a certificate.
func (cm *certificateManager) getKeyPair(cli client.Client, secretName, secretNamespace string, readCertOnly bool, dnsNames []string) (certificatemanagement.KeyPairInterface, *x509.Certificate, error) {
	cm.log.V(2).Info("Querying secret for keypair", "namespace", secretNamespace, "name", secretName)
	secret := &corev1.Secret{}
	err := cli.Get(context.Background(), types.NamespacedName{
		Name:      secretName,
		Namespace: secretNamespace,
	}, secret)
	if err != nil {
		if kerrors.IsNotFound(err) {
			cm.log.V(2).Info("KeyPair not found", "namespace", secretNamespace, "name", secretName)
			if cm.keyPair.CertificateManagement != nil {
				// When certificate management is enabled, we expect that in most cases no secret will be present.
				return certificateManagementKeyPair(cm, secretName, secretNamespace, dnsNames), nil, nil
			}
			return nil, nil, nil
		}
		return nil, nil, err
	}
	keyPEM, certPEM := certificatemanagement.GetKeyCertPEM(secret)
	if !readCertOnly {
		if len(keyPEM) == 0 {
			return nil, nil, errNoPrivateKeyPEM(secretName, secretNamespace)
		}
	}
	if len(certPEM) == 0 {
		return nil, nil, errNoCertificatePEM(secretName, secretNamespace)
	}
	x509Cert, err := certificatemanagement.ParseCertificate(certPEM)
	if err != nil {
		return nil, nil, err
	}

	// Get specific usages to check for certs that are utilized for mTLS with Linseed
	requiredKeyUsages := certkeyusage.GetCertKeyUsage(secretName)
	invalidKeyUsage := !HasRequiredKeyUsage(x509Cert, requiredKeyUsages)
	timeInvalid := x509Cert.NotAfter.Before(time.Now()) || x509Cert.NotBefore.After(time.Now())
	if timeInvalid || invalidKeyUsage {
		if !readCertOnly && strings.HasPrefix(x509Cert.Issuer.CommonName, rmeta.TigeraOperatorCAIssuerPrefix) {
			if cm.keyPair.CertificateManagement != nil {
				// When certificate management is enabled, we can simply return a certificate management key pair;
				// the old secret will be deleted automatically.
				return certificateManagementKeyPair(cm, secretName, secretNamespace, dnsNames), nil, nil
			}

			if invalidKeyUsage {
				cm.log.Info(fmt.Sprintf("secret %s/%s must specify ext key usages: %+v", secretNamespace, secretName, requiredKeyUsages))
			}
			// We return nil, so a new secret will be created for expired (legacy) operator signed secrets.
			cm.log.Info("KeyPair is an expired legacy operator cert, make a new one", "name", secretName)
			return nil, nil, nil
		}

		if timeInvalid {
			if readCertOnly {
				cm.log.Info("secret %s/%s is not valid at this date, so we return nil and continue as though it does not exist", secretNamespace, secretName)
				return nil, nil, nil
			}
			return nil, nil, fmt.Errorf("secret %s/%s is not valid at this date for a certificate not created by the operator, user action required", secretNamespace, secretName)
		}
		return nil, nil, newCertExtKeyUsageError(secretName, secretNamespace, requiredKeyUsages)
	}

	if !readCertOnly && x509Cert.NotAfter.Before(time.Now().Add(gracePeriod)) {
		// The certificate is not valid one month from now. Let's start the rotation process, so there will be plenty of time
		// to roll out the changes without disruption. All components that need to trust this certificate are already
		// trusting the issuer, so there will be no disruption.
		if !strings.HasPrefix(x509Cert.Issuer.CommonName, rmeta.TigeraOperatorCAIssuerPrefix) {
			cm.log.V(2).Info("Warning: this certificate will soon expire and is not managed by the operator, user action required!", "name", secretName)
		} else {
			if cm.keyPair.CertificateManagement != nil {
				// When certificate management is enabled, we can simply return a certificate management key pair;
				// the old secret will be deleted automatically.
				return certificateManagementKeyPair(cm, secretName, secretNamespace, dnsNames), nil, nil
			}
			cm.log.Info("rotating the certificate because it is expiring soon", "name", secretName)
			// By returning nil, the controller will issue a new certificate.
			return nil, nil, nil
		}
	}

	var issuer certificatemanagement.KeyPairInterface
	if strings.HasPrefix(x509Cert.Issuer.CommonName, rmeta.TigeraOperatorCAIssuerPrefix) {
		if cm.keyPair.CertificateManagement != nil {
			return certificateManagementKeyPair(cm, secretName, secretNamespace, dnsNames), nil, nil
		}
		if string(x509Cert.AuthorityKeyId) == string(cm.AuthorityKeyId) {
			issuer = cm.keyPair
		} else {
			if !readCertOnly {
				// We want to return nothing, so a new secret will be created to overwrite this one.
				cm.log.Info("KeyPair's authority key id doesn't match, will create a new one", "name", secretName)
				return nil, nil, nil
			}
			// We treat the certificate as a BYO secret, because this may be a certificate created by a management cluster
			// and used inside a managed cluster. If it is not, it should get updated automatically when readCertOnly=false.
			issuer = nil
		}
	}
	return &certificatemanagement.KeyPair{
		Issuer:         issuer,
		Name:           secretName,
		Namespace:      secretNamespace,
		PrivateKeyPEM:  keyPEM,
		CertificatePEM: certPEM,
		OriginalSecret: secret,
	}, x509Cert, nil
}

// HasRequiredKeyUsage returns true if the given certificate is valid
// for use as both a server certificate, as well as a client certificate for mTLS connections.
func HasRequiredKeyUsage(cert *x509.Certificate, required []x509.ExtKeyUsage) bool {
	for _, ku := range required {
		found := false
		for _, certKU := range cert.ExtKeyUsage {
			if certKU == ku {
				found = true
				break
			}
		}

		if !found {
			return false
		}
	}
	return true
}

// GetCertificate returns a Certificate. If the certificate is not found or outdated, a k8s.io NotFound error is returned.
func (cm *certificateManager) GetCertificate(cli client.Client, secretName, secretNamespace string) (certificatemanagement.CertificateInterface, error) {
	keyPair, _, err := cm.getKeyPair(cli, secretName, secretNamespace, true, nil)
	return keyPair, err
}

// GetKeyPair returns an existing KeyPair. If the KeyPair is not found, nil is returned.
func (cm *certificateManager) GetKeyPair(cli client.Client, secretName, secretNamespace string, dnsNames []string) (certificatemanagement.KeyPairInterface, error) {
	keyPair, _, err := cm.getKeyPair(cli, secretName, secretNamespace, false, dnsNames)
	return keyPair, err
}

// CACertCommonName returns the CommonName from the CA certificate's Subject field.
func (cm *certificateManager) CACertCommonName() string {
	if cm.Certificate != nil {
		return cm.Subject.CommonName
	}
	return ""
}

// CertificateManagement returns the CertificateManagement object or nil if it is not configured.
func (cm *certificateManager) CertificateManagement() *operatorv1.CertificateManagement {
	return cm.keyPair.CertificateManagement
}

// certificateManagementKeyPair returns a KeyPair for to be used when certificate management is used to provide a key pair to a pod.
func certificateManagementKeyPair(ca *certificateManager, secretName, ns string, dnsNames []string) *certificatemanagement.KeyPair {
	return &certificatemanagement.KeyPair{
		Name:                  secretName,
		CertificateManagement: ca.CertificateManagement(),
		DNSNames:              dnsNames,
		CSRImage:              ca.keyPair.CSRImage,
		Namespace:             ns,
		CertificatePEM:        ca.CertificateManagement().CACert,
	}
}

func HasExpectedDNSNames(secretName, secretNamespace string, cert *x509.Certificate, expectedDNSNames []string) error {
	dnsNames := sets.New[string](cert.DNSNames...)
	if dnsNames.HasAll(expectedDNSNames...) {
		return nil
	}
	return ErrInvalidCertDNSNames(secretName, secretNamespace)
}

// CreateNamedTrustedBundleFromSecrets creates a TrustedBundle, which provides standardized methods for mounting a bundle of certificates to trust.
// It will include:
// - A bundle with Calico's root certificates + any user supplied certificates in /etc/pki/tls/certs/tigera-ca-bundle.crt.
func (cm *certificateManager) CreateNamedTrustedBundleFromSecrets(prefix string, cli client.Client, namespace string, includeSystem bool, secretsToTrust ...string) (certificatemanagement.TrustedBundle, error) {
	trustedBundle := certificatemanagement.CreateNamedTrustedBundle(prefix, cm.keyPair, includeSystem)
	for _, secretName := range secretsToTrust {
		secret, err := cm.GetCertificate(cli, secretName, namespace)
		if err != nil {
			return nil, fmt.Errorf("failed to retrieve secret %s: %w", secretName, err)
		}
		trustedBundle.AddCertificates(secret)
	}
	return trustedBundle, nil
}

// CreateTrustedBundle creates a TrustedBundle, which provides standardized methods for mounting a bundle of certificates to trust.
// It will include:
// - A bundle with Calico's root certificates + any user supplied certificates in /etc/pki/tls/certs/tigera-ca-bundle.crt.
func (cm *certificateManager) CreateTrustedBundle(certificates ...certificatemanagement.CertificateInterface) certificatemanagement.TrustedBundle {
	return certificatemanagement.CreateTrustedBundle(cm.keyPair, certificates...)
}

// CreateTrustedBundleWithSystemRootCertificates creates a TrustedBundle, which provides standardized methods for mounting a bundle of certificates to trust.
// It will include:
// - A bundle with Calico's root certificates + any user supplied certificates in /etc/pki/tls/certs/tigera-ca-bundle.crt.
// - A system root certificate bundle in /etc/pki/tls/certs/ca-bundle.crt.
func (cm *certificateManager) CreateTrustedBundleWithSystemRootCertificates(certificates ...certificatemanagement.CertificateInterface) (certificatemanagement.TrustedBundle, error) {
	return certificatemanagement.CreateTrustedBundleWithSystemRootCertificates(cm.keyPair, certificates...)
}

func (cm *certificateManager) LoadNamedTrustedBundle(ctx context.Context, client client.Client, ns, name string) (certificatemanagement.TrustedBundleRO, error) {
	return cm.loadTrustedBundle(ctx, client, ns, name)
}

func (cm *certificateManager) LoadTrustedBundle(ctx context.Context, client client.Client, ns string) (certificatemanagement.TrustedBundleRO, error) {
	return cm.loadTrustedBundle(ctx, client, ns, certificatemanagement.TrustedCertConfigMapName)
}

func (cm *certificateManager) loadTrustedBundle(ctx context.Context, client client.Client, ns string, name string) (certificatemanagement.TrustedBundleRO, error) {
	// Get the ConfigMap containing the actual certificates.
	obj := &corev1.ConfigMap{}
	k := types.NamespacedName{Name: name, Namespace: ns}
	if err := client.Get(ctx, k, obj); err != nil {
		return nil, err
	}

	// Create a new readOnlyTrustedBundle based on the given configuration.
	includeSystemCerts := len(obj.Data[certificatemanagement.RHELRootCertificateBundleName]) > 0
	a, err := newReadOnlyTrustedBundle(cm, name, includeSystemCerts)
	if err != nil {
		return nil, err
	}

	// Augment it with annotations from the actual ConfigMap so that we inherit the hash annotations used to
	// detect changes to the ConfigMap's contents.
	for key, val := range obj.Annotations {
		if strings.Contains(key, "hash.operator.tigera.io/") {
			a.annotations[key] = val
		}
	}
	return a, nil
}

// newReadOnlyTrustedBundle creates a new readOnlyTrustedBundle for the ConfigMap of the given
// name. TrustedBundleRO lets one controller create a bundle and another mount it without being
// able to modify it.
func newReadOnlyTrustedBundle(cm CertificateManager, name string, includeSystemCerts bool) (*readOnlyTrustedBundle, error) {
	bundle, err := certificatemanagement.CreateTrustedBundleWithName(name, includeSystemCerts, cm.KeyPair())
	if err != nil {
		return nil, err
	}
	return &readOnlyTrustedBundle{annotations: map[string]string{}, bundle: bundle}, nil
}

// readOnlyTrustedBundle implements the TrustedBundleRO interface. It allows for annotations to be provided that will be added to
// any resources which depend on the bundle. Otherwise, it is a lightweight wrapper around a TrustedBundle that does not allow
// modification of the bundle and simply exposes methods for mounting bundle that has already been created in the cluster.
type readOnlyTrustedBundle struct {
	annotations map[string]string
	bundle      certificatemanagement.TrustedBundle
}

func (a *readOnlyTrustedBundle) MountPath() string {
	return a.bundle.MountPath()
}

func (a *readOnlyTrustedBundle) VolumeMounts(osType rmeta.OSType) []corev1.VolumeMount {
	return a.bundle.VolumeMounts(osType)
}

func (a *readOnlyTrustedBundle) Volume() corev1.Volume {
	return a.bundle.Volume()
}

func (a *readOnlyTrustedBundle) HashAnnotations() map[string]string {
	return a.annotations
}
