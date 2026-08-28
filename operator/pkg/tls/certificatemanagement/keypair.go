// Copyright (c) 2022-2026 Tigera, Inc. All rights reserved.

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

package certificatemanagement

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"regexp"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	operatorv1 "github.com/tigera/operator/api/v1"
	rmeta "github.com/tigera/operator/pkg/render/common/meta"
)

var ErrInvalidCertNoPEMData = errors.New("cert has no PEM data")

type KeyPair struct {
	CSRImage string

	Name      string
	Namespace string
	// Golang's x509 package uses the 'any' type for all private and public keys. See x509.CreateCertificate() for more.
	PrivateKey     any
	PrivateKeyPEM  []byte
	CertificatePEM []byte
	ClusterDomain  string
	*operatorv1.CertificateManagement
	DNSNames []string
	Issuer   KeyPairInterface

	// OriginalSecret maintains a copy of the secret that the KeyPair was created from.
	OriginalSecret *corev1.Secret
}

func (k *KeyPair) GetCertificatePEM() []byte {
	return k.CertificatePEM
}

func (k *KeyPair) GetName() string {
	return k.Name
}

func (k *KeyPair) GetNamespace() string {
	return k.Namespace
}

// UseCertificateManagement is true if this secret is not BYO and certificate management is used to provide the a pair to a pod.
func (k *KeyPair) UseCertificateManagement() bool {
	return k.CertificateManagement != nil
}

// BYO returns true if this KeyPair was provided by the user. If BYO is true, UseCertificateManagement is false.
func (k *KeyPair) BYO() bool {
	return !k.UseCertificateManagement() && k.Issuer == nil
}

func (k *KeyPair) Secret(namespace string) *corev1.Secret {
	var data map[string][]byte
	if k.OriginalSecret == nil {
		data = make(map[string][]byte)
	} else {
		// Preserve original fields, such as uri-san, common-name or legacy names for tls.key and tls.crt.
		// This is necessary for example to support rolling calico-node updates of larger clusters from older versions.
		data = k.OriginalSecret.Data
	}
	data[corev1.TLSPrivateKeyKey] = k.PrivateKeyPEM
	data[corev1.TLSCertKey] = k.CertificatePEM

	labels, annotations := tlsSecretMetadata(k.CertificatePEM)
	if v := k.HashAnnotationValue(); v != "" {
		annotations[k.HashAnnotationKey()] = v
	}

	return &corev1.Secret{
		TypeMeta: metav1.TypeMeta{Kind: "Secret", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:        k.GetName(),
			Namespace:   namespace,
			Labels:      labels,
			Annotations: annotations,
		},
		Data: data,
	}
}

func (k *KeyPair) HashAnnotationKey() string {
	if k.GetNamespace() == "" {
		return fmt.Sprintf("hash.operator.tigera.io/%s", k.GetName())
	}
	return fmt.Sprintf("%s.hash.operator.tigera.io/%s", k.GetNamespace(), k.GetName())
}

func (k *KeyPair) HashAnnotationValue() string {
	if k.CertificateManagement != nil {
		return ""
	}
	return rmeta.AnnotationHash(rmeta.AnnotationHash(k.CertificatePEM))
}

// Warnings returns a warning string if this is a BYO certificate expiring within 30 days.
func (k *KeyPair) Warnings() string {
	if !k.BYO() {
		return ""
	}
	cert, err := ParseCertificate(k.CertificatePEM)
	if err != nil {
		return ""
	}
	remaining := time.Until(cert.NotAfter)
	if remaining <= 30*24*time.Hour {
		return fmt.Sprintf("Warning: user provided certificate %q expires in %d days", k.Name, int(remaining.Hours()/24))
	}
	return ""
}

func (k *KeyPair) Volume() corev1.Volume {
	volumeSource := CertificateVolumeSource(k.CertificateManagement, k.GetName())
	return corev1.Volume{
		Name:         k.GetName(),
		VolumeSource: volumeSource,
	}
}

func (k *KeyPair) VolumeMountCertificateFilePath() string {
	return fmt.Sprintf("/%s/%s", k.GetName(), corev1.TLSCertKey)
}

func (k *KeyPair) VolumeMountKeyFilePath() string {
	return fmt.Sprintf("/%s/%s", k.GetName(), corev1.TLSPrivateKeyKey)
}

func (k *KeyPair) VolumeMount(osType rmeta.OSType) corev1.VolumeMount {
	var mountPath string
	if osType == rmeta.OSTypeWindows {
		mountPath = fmt.Sprintf("c:/%s", k.GetName())
	} else {
		mountPath = fmt.Sprintf("/%s", k.GetName())
	}
	return corev1.VolumeMount{
		Name:      k.GetName(),
		MountPath: mountPath,
		ReadOnly:  true,
	}
}

// InitContainer contains an init container for making a CSR. is only applicable when certificate management is enabled.
func (k *KeyPair) InitContainer(namespace string, securityContext *corev1.SecurityContext) corev1.Container {
	initContainer := CreateCSRInitContainer(
		k.CertificateManagement,
		k.Name,
		k.CSRImage,
		k.GetName(),
		k.DNSNames[0],
		corev1.TLSPrivateKeyKey,
		corev1.TLSCertKey,
		k.DNSNames,
		namespace,
		securityContext,
	)
	initContainer.Name = fmt.Sprintf("%s-%s", k.GetName(), initContainer.Name)
	return initContainer
}

// tlsSecretMetadata parses certPEM and returns labels and annotations that surface
// certificate metadata on the owning Secret. On parse failure it returns empty maps.
func tlsSecretMetadata(certPEM []byte) (labels map[string]string, annotations map[string]string) {
	labels = map[string]string{}
	annotations = map[string]string{}

	cert, err := ParseCertificate(certPEM)
	if err != nil {
		return labels, annotations
	}

	// --- labels ---
	labels[SignerLabel] = signerLabelValue(cert.Issuer.CommonName)

	// --- annotations ---
	issuerCN := cert.Issuer.CommonName
	annotations[IssuerAnnotation] = issuerCN
	annotations[SignerLabel] = issuerCN
	annotations[ExpiryAnnotation] = cert.NotAfter.UTC().Format(ExpiryFormat)

	if len(cert.DNSNames) > 0 {
		annotations["certificates.operator.tigera.io/dns-names"] = strings.Join(cert.DNSNames, ",")
	}
	if len(cert.IPAddresses) > 0 {
		annotations["certificates.operator.tigera.io/ip-sans"] = strings.Join(ipStrings(cert.IPAddresses), ",")
	}

	return labels, annotations
}

// labelUnsafe matches any character that is not alphanumeric, '-', '_', or '.'.
var labelUnsafe = regexp.MustCompile(`[^A-Za-z0-9_.\-]`)

// signerLabelValue returns a Kubernetes-label-safe signer identifier from the
// issuer CN. It replaces invalid characters with '-', trims leading/trailing
// non-alphanumeric characters, and truncates to 63 chars to satisfy the label
// value constraints.
func signerLabelValue(cn string) string {
	// Replace any character not in [A-Za-z0-9_.-] with '-'.
	v := labelUnsafe.ReplaceAllString(cn, "-")

	// Trim leading/trailing characters that are not alphanumeric.
	v = strings.TrimLeft(v, "-_.")
	v = strings.TrimRight(v, "-_.")

	// Truncate to 63 characters, then trim any trailing non-alphanumeric
	// chars that truncation may have exposed.
	if len(v) > 63 {
		v = v[:63]
		v = strings.TrimRight(v, "-_.")
	}

	if v == "" {
		return "unknown"
	}
	return v
}

// ipStrings converts a slice of net.IP to their string representations.
func ipStrings(ips []net.IP) []string {
	out := make([]string, len(ips))
	for i, ip := range ips {
		out[i] = ip.String()
	}
	return out
}

func ParseCertificate(certBytes []byte) (*x509.Certificate, error) {
	pemBlock, _ := pem.Decode(certBytes)
	if pemBlock == nil {
		return nil, ErrInvalidCertNoPEMData
	}
	cert, err := x509.ParseCertificate(pemBlock.Bytes)
	if err != nil {
		return nil, err
	}
	return cert, nil
}

func (k *KeyPair) GetIssuer() CertificateInterface {
	return k.Issuer
}

func GetKeyCertPEM(secret *corev1.Secret) ([]byte, []byte) {
	const (
		legacySecretCertName  = "cert" // Formerly known as certificatemanagement.ManagerSecretCertName
		legacySecretKeyName   = "key"  // Formerly known as certificatemanagement.ManagerSecretKeyName
		legacySecretKeyName2  = "apiserver.key"
		legacySecretCertName2 = "apiserver.crt"
		legacySecretKeyName3  = "key.key"             // Formerly used for Felix and Typha.
		legacySecretCertName3 = "cert.crt"            // Formerly used for Felix and Typha.
		legacySecretKeyName4  = "managed-cluster.key" // Used for tunnel secrets
		legacySecretCertName4 = "managed-cluster.crt"
		legacySecretKeyName5  = "management-cluster.key"
		legacySecretCertName5 = "management-cluster.crt"
	)
	data := secret.Data
	// Check the recognised key/cert field-name pairs in a fixed priority order, standard
	// tls.crt/tls.key first, then the legacy names. Iterating a map here would be a bug: Go
	// randomizes map iteration order, so a secret that contains more than one recognised pair
	// (e.g. the standard tls.crt/tls.key alongside a legacy cert/key that is intentionally kept
	// during a certificate-rotation overlap) would return a non-deterministic cert. That flips
	// the KeyPair's hash annotation between reconciles, which in turn triggers spurious rolling
	// restarts of consumers such as Voltron/tigera-manager (dropping managed-cluster tunnels).
	for _, pair := range []struct{ keyField, certField string }{
		{corev1.TLSPrivateKeyKey, corev1.TLSCertKey},
		{legacySecretKeyName, legacySecretCertName},
		{legacySecretKeyName2, legacySecretCertName2},
		{legacySecretKeyName3, legacySecretCertName3},
		{legacySecretKeyName4, legacySecretCertName4},
		{legacySecretKeyName5, legacySecretCertName5},
	} {
		key, cert := data[pair.keyField], data[pair.certField]
		if len(cert) > 0 {
			return key, cert
		}
	}
	return nil, nil
}

// WarningReporter is a minimal interface for reporting certificate warnings to a status manager.
type WarningReporter interface {
	SetWarning(key string, msg string)
	ClearWarning(key string)
}

// CheckKeyPairWarnings checks each keypair for BYO certificate expiry warnings and reports them
// to the status manager. For nil keypairs or keypairs without warnings, the warning is cleared.
func CheckKeyPairWarnings(keyPairs map[string]KeyPairInterface, status WarningReporter) {
	for key, kp := range keyPairs {
		if kp != nil {
			if w := kp.Warnings(); w != "" {
				status.SetWarning(key, w)
				continue
			}
		}
		status.ClearWarning(key)
	}
}

// NewKeyPair returns a KeyPair, which wraps a Secret object that contains a private key and a certificate. Whether certificate
// management is configured or not, KeyPair returns the right InitContainer, Volumemount or Volume (when applicable).
func NewKeyPair(secret *corev1.Secret, dnsNames []string, clusterDomain string) KeyPairInterface {
	key, cert := GetKeyCertPEM(secret)
	return &KeyPair{
		Name:           secret.Name,
		PrivateKeyPEM:  key,
		CertificatePEM: cert,
		DNSNames:       dnsNames,
		ClusterDomain:  clusterDomain,
	}
}
