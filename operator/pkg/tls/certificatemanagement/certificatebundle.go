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
	"bytes"
	"fmt"
	"os"
	"path"
	"sort"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	rmeta "github.com/tigera/operator/pkg/render/common/meta"
)

const (
	// RHELRootCertificateBundleName is the name of the system CA bundle as present in UBI/RHEL systems.
	RHELRootCertificateBundleName = "ca-bundle.crt"
	// SSLCertFile is the symbolic link to the system CA bundle used by libssl SSL_CERT_FILE.
	SSLCertFile = "cert.pem"

	sslCertDir = "certs"
)

type trustedBundle struct {
	// name is the name of the bundle. This is used to name the configmap and thus also used in the volume mount.
	name string
	// systemCertificates is a bundle of certificates loaded from the host systems root location.
	systemCertificates []byte

	// This is the CA that signs new certificates that are being created.
	ca CertificateInterface

	// certificates is a map of key: hash, value: certificate.
	certificates []CertificateInterface
}

// CreateTrustedBundle creates a TrustedBundle, which provides standardized methods for mounting a bundle of certificates to trust.
// It will include:
// - A bundle with Calico's root certificates + any user supplied certificates in /etc/pki/tls/certs/tigera-ca-bundle.crt.
func CreateTrustedBundle(ca CertificateInterface, certificates ...CertificateInterface) TrustedBundle {
	bundle, err := createTrustedBundle(false, TrustedCertConfigMapName, ca, certificates...)
	if err != nil {
		panic(err) // This should never happen.
	}
	return bundle
}

// CreateNamedTrustedBundle creates a TrustedBundle, which provides standardized methods for mounting a bundle of certificates to trust.
// It will include:
// - A bundle with Calico's root certificates + any user supplied certificates in /etc/pki/tls/certs/tigera-ca-bundle.crt.
func CreateNamedTrustedBundle(prefix string, ca CertificateInterface, includeSystem bool, certificates ...CertificateInterface) TrustedBundle {
	name := TrustedBundleName(prefix, includeSystem)
	bundle, err := createTrustedBundle(includeSystem, name, ca, certificates...)
	if err != nil {
		panic(err) // This should never happen.
	}
	return bundle
}

// CreateTrustedBundleWithSystemRootCertificates creates a TrustedBundle, which provides standardized methods for mounting a bundle of certificates to trust.
// It will include:
// - A bundle with Calico's root certificates + any user supplied certificates in /etc/pki/tls/certs/tigera-ca-bundle.crt.
// - A system root certificate bundle in /etc/pki/tls/certs/ca-bundle.crt.
func CreateTrustedBundleWithSystemRootCertificates(ca CertificateInterface, certificates ...CertificateInterface) (TrustedBundle, error) {
	return createTrustedBundle(true, TrustedCertConfigMapName, ca, certificates...)
}

// CreateTrustedBundleWithName creates a TrustedBundle backed by a ConfigMap of the given name.
// Callers that need more than one bundle in a single namespace use this to keep them apart.
func CreateTrustedBundleWithName(name string, includeSystem bool, ca CertificateInterface, certificates ...CertificateInterface) (TrustedBundle, error) {
	return createTrustedBundle(includeSystem, name, ca, certificates...)
}

// createTrustedBundle creates a TrustedBundle, which provides standardized methods for mounting a bundle of certificates to trust.
func createTrustedBundle(includeSystemBundle bool, name string, ca CertificateInterface, certificates ...CertificateInterface) (TrustedBundle, error) {
	var systemCertificates []byte
	var err error
	if includeSystemBundle {
		systemCertificates, err = getSystemCertificates()
		if err != nil {
			return nil, err
		}
	}

	bundle := &trustedBundle{
		name:               name,
		ca:                 ca,
		systemCertificates: systemCertificates,
		certificates:       []CertificateInterface{},
	}
	if ca != nil {
		bundle.certificates = append(bundle.certificates, ca)
	}
	bundle.AddCertificates(certificates...)

	return bundle, err
}

// AddCertificates Adds the certificates to the bundle.
func (t *trustedBundle) AddCertificates(certificates ...CertificateInterface) {
	for _, cert := range certificates {
		if cert != nil {
			// Only if a certificate was not signed by our operator, we should add it to the bundle.
			if cert.GetIssuer() != nil && t.ca != nil &&
				string(cert.GetIssuer().GetCertificatePEM()) == string(t.ca.GetCertificatePEM()) {
				continue
			}
			t.certificates = append(t.certificates, cert)
		}
	}
}

func (t *trustedBundle) MountPath() string {
	return TrustedCertBundleMountPath
}

func (t *trustedBundle) HashAnnotations() map[string]string {
	annotations := make(map[string]string)
	for _, cert := range t.certificates {
		annotations[fmt.Sprintf("%s.hash.operator.tigera.io/%s", cert.GetNamespace(), cert.GetName())] = rmeta.AnnotationHash(cert.GetCertificatePEM())
	}
	if len(t.systemCertificates) > 0 {
		annotations["hash.operator.tigera.io/system"] = rmeta.AnnotationHash(t.systemCertificates)
	}
	return annotations
}

func (t *trustedBundle) VolumeMounts(osType rmeta.OSType) []corev1.VolumeMount {
	var mountPath string
	if osType == rmeta.OSTypeWindows {
		mountPath = TrustedCertVolumeMountPathWindows
	} else {
		mountPath = TrustedCertVolumeMountPath
	}

	// golang stdlib reads this path
	mounts := []corev1.VolumeMount{
		{
			Name:      t.name,
			MountPath: path.Join(mountPath, sslCertDir),
			ReadOnly:  true,
		},
	}
	if len(t.systemCertificates) > 0 && osType != rmeta.OSTypeWindows {
		// apps linking libssl need this file (SSL_CERT_FILE)
		mounts = append(mounts,
			corev1.VolumeMount{
				Name:      t.name,
				MountPath: path.Join(mountPath, SSLCertFile),
				SubPath:   RHELRootCertificateBundleName,
				ReadOnly:  true,
			},
		)
	}
	return mounts
}

func (t *trustedBundle) Volume() corev1.Volume {
	return corev1.Volume{
		Name: t.name,
		VolumeSource: corev1.VolumeSource{
			ConfigMap: &corev1.ConfigMapVolumeSource{
				LocalObjectReference: corev1.LocalObjectReference{Name: t.name},
			},
		},
	}
}

func (t *trustedBundle) ConfigMap(namespace string) *corev1.ConfigMap {
	pemBuf := bytes.Buffer{}

	// Sort the certificates so that we get a consistent ordering.
	// This reduces the number of changes we see in the configmap.
	var certs []CertificateInterface
	certs = append(certs, t.certificates...)
	sort.Slice(certs, func(i, j int) bool {
		return certs[i].GetName() < certs[j].GetName()
	})
	for _, cert := range certs {
		fmt.Fprintf(&pemBuf, "# certificate name: %s/%s\n%s\n\n", cert.GetNamespace(), cert.GetName(), string(cert.GetCertificatePEM()))
	}

	pemStr := pemBuf.String()
	return &corev1.ConfigMap{
		TypeMeta: metav1.TypeMeta{Kind: "ConfigMap", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      t.name,
			Namespace: namespace,

			// Include the hash annotations on the configmap, so that downstrream controllers
			// can easily acquire them without loading all of the certificates.
			Annotations: t.HashAnnotations(),
		},
		Data: map[string]string{
			RHELRootCertificateBundleName:     string(t.systemCertificates),
			TrustedCertConfigMapKeyName:       pemStr,
			LegacyTrustedCertConfigMapKeyName: pemStr, // This is for backwards compatibility for pods that use the old default.
		},
	}
}

// NewCertificate creates a new certificate.
func NewCertificate(name, ns string, pem []byte, issuer CertificateInterface) CertificateInterface {
	return &certificate{name: name, namespace: ns, pem: pem, issuer: issuer}
}

type certificate struct {
	name      string
	namespace string
	issuer    CertificateInterface
	pem       []byte
}

func (c *certificate) GetCertificatePEM() []byte {
	return c.pem
}

func (c *certificate) GetName() string {
	return c.name
}

func (c *certificate) GetNamespace() string {
	return c.namespace
}

func (c *certificate) GetIssuer() CertificateInterface {
	return c.issuer
}

// certFiles is copied from the x509 package, but re-ordered, since in practice this should run containerized
// and stop at the first entry. More at: https://go.dev/src/crypto/x509/root_linux.go for the source.
//
// Possible certificate files; stop after finding one.
var certFiles = []string{
	"/etc/pki/tls/certs/ca-bundle.crt",                  // Fedora/RHEL 6
	"/etc/ssl/certs/ca-certificates.crt",                // Debian/Ubuntu/Gentoo etc.
	"/etc/ssl/ca-bundle.pem",                            // OpenSUSE
	"/etc/pki/tls/cacert.pem",                           // OpenELEC
	"/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem", // CentOS/RHEL 7
	"/etc/ssl/cert.pem",                                 // Alpine Linux
}

// getSystemCertificates returns the certificate that are installed in the operator's base image.
// The code of this function is loosely based on x509's loadSystemRoots() func:
// https://go.dev/src/crypto/x509/root_unix.go
func getSystemCertificates() ([]byte, error) {
	for _, filename := range certFiles {
		data, err := os.ReadFile(filename)
		if err != nil {
			if !os.IsNotExist(err) {
				return nil, fmt.Errorf(fmt.Sprintf("error occurred when loading system root certificate with name %s", filename), err)
			}
		} else {
			return data, nil
		}
	}
	return nil, nil
}

func TrustedBundleName(prefix string, includeSystem bool) string {
	if includeSystem {
		return prefix + TrustedCertConfigMapSuffixPublic
	}
	return prefix + TrustedCertConfigMapSuffix
}
