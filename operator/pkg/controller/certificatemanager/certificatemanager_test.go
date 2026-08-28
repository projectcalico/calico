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

// This renderer is responsible for all resources related to a Guardian Deployment in a
// multicluster setup.

package certificatemanager_test

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/pem"
	"runtime"
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"k8s.io/apimachinery/pkg/util/sets"

	"github.com/openshift/library-go/pkg/crypto"

	operatorv1 "github.com/projectcalico/calico/operator/api/v1"
	"github.com/projectcalico/calico/operator/pkg/apis"
	"github.com/projectcalico/calico/operator/pkg/common"
	"github.com/projectcalico/calico/operator/pkg/components"
	"github.com/projectcalico/calico/operator/pkg/controller/certificatemanager"
	"github.com/projectcalico/calico/operator/pkg/controller/utils/imageset"
	ctrlrfake "github.com/projectcalico/calico/operator/pkg/ctrlruntime/client/fake"
	rmeta "github.com/projectcalico/calico/operator/pkg/render/common/meta"
	"github.com/projectcalico/calico/operator/pkg/render/common/secret"
	"github.com/projectcalico/calico/operator/pkg/tls"
	"github.com/projectcalico/calico/operator/pkg/tls/certificatemanagement"
	"github.com/projectcalico/calico/operator/pkg/tls/certkeyusage"
	"github.com/projectcalico/calico/operator/test"

	apps "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8sruntime "k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	appSecretName       = "my-app-tls"
	appSecretName2      = "my-app-tls-2"
	legacySecretName    = "legacy-secret"
	appNs               = "my-app"
	legacyKeyFieldName  = "key"
	legacyCertFieldName = "cert"

	certValidity = 365 * 24 * time.Hour
)

var (
	// Configure certs to match legacy operator-generated cert extensions - i.e., only valid for use as a server certificate.
	legacyOpts = []crypto.CertificateExtensionFunc{tls.SetServerAuth}
	modernOpts = []crypto.CertificateExtensionFunc{tls.SetServerAuth, tls.SetClientAuth}

	legacySecret             *corev1.Secret
	expiredLegacySecret      *corev1.Secret
	byoSecret                *corev1.Secret
	expiredBYOSecret         *corev1.Secret
	legacyBYOSecret          *corev1.Secret
	legacyWithClientKeyUsage *corev1.Secret
)

// Precompute expensive operations once.
var _ = BeforeSuite(func() {
	var err error

	certkeyusage.SetCertKeyUsage(legacySecretName, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth})
	// Create a legacy secret (how certs were before v1.24) with non-standardized legacy key and cert name, and no CA.
	// Use a secret
	legacySecret, err = secret.CreateTLSSecret(nil, legacySecretName, appNs, legacyKeyFieldName, legacyCertFieldName, certValidity, legacyOpts, legacySecretName)
	Expect(err).NotTo(HaveOccurred())

	// This is a special case, which may or may not exist in the wild. It's a legacy-style certificate signed by tigera-operator but also with client usage.
	legacyWithClientKeyUsage, err = secret.CreateTLSSecret(nil, legacySecretName, appNs, legacyKeyFieldName, legacyCertFieldName, certValidity, modernOpts, appSecretName)
	Expect(err).NotTo(HaveOccurred())

	// Create a byo secret with non-standardized legacy key and cert name (like our docs for felix/typha).
	cryptoCA, err := tls.MakeCA("byo-ca")
	Expect(err).NotTo(HaveOccurred())
	byoSecret, err = secret.CreateTLSSecret(cryptoCA, appSecretName, appNs, "key.key", "cert.crt", certValidity, modernOpts, appSecretName)
	Expect(err).NotTo(HaveOccurred())
	legacyBYOSecret, err = secret.CreateTLSSecret(cryptoCA, legacySecretName, appNs, "key.key", "cert.crt", certValidity, legacyOpts, legacySecretName)
	Expect(err).NotTo(HaveOccurred())
	expiredBYOSecret, err = secret.CreateTLSSecret(cryptoCA, appSecretName, appNs, "key.key", "cert.crt", -time.Hour, modernOpts, appSecretName)
	Expect(err).NotTo(HaveOccurred())

	// Create a CA in the manner of older operator versions.
	legacyCryptoCA, err := tls.MakeCA(rmeta.TigeraOperatorCAIssuerPrefix + "@some-hash")
	Expect(err).NotTo(HaveOccurred())
	expiredLegacySecret, err = secret.CreateTLSSecret(legacyCryptoCA, appSecretName, appNs, legacyKeyFieldName, legacyCertFieldName, -time.Hour, legacyOpts, appSecretName)
	Expect(err).NotTo(HaveOccurred())
})

var _ = Describe("Test CertificateManagement suite", func() {
	var (
		cli                client.Client
		scheme             *k8sruntime.Scheme
		installation       *operatorv1.InstallationSpec
		cm                 *operatorv1.CertificateManagement
		clusterDomain      = "cluster.local"
		appDNSNames        = []string{appSecretName}
		ctx                = context.TODO()
		certificateManager certificatemanager.CertificateManager
		expiredSecret      *corev1.Secret
	)

	BeforeEach(func() {
		for _, secret := range []*corev1.Secret{legacySecret, byoSecret, legacyWithClientKeyUsage, legacyBYOSecret, expiredBYOSecret, expiredLegacySecret} {
			// Clean up secret state.
			secret.ResourceVersion = ""
		}
		// Create a Kubernetes client.
		scheme = k8sruntime.NewScheme()
		err := apis.AddToScheme(scheme, false)
		Expect(err).NotTo(HaveOccurred())

		Expect(corev1.SchemeBuilder.AddToScheme(scheme)).ShouldNot(HaveOccurred())
		Expect(apps.SchemeBuilder.AddToScheme(scheme)).ShouldNot(HaveOccurred())
		Expect(batchv1.SchemeBuilder.AddToScheme(scheme)).ShouldNot(HaveOccurred())

		cli = ctrlrfake.DefaultFakeClientBuilder(scheme).Build()

		installation = &operatorv1.InstallationSpec{}
		certificateManager, err = certificatemanager.Create(cli, installation, clusterDomain, common.OperatorNamespace(), certificatemanager.AllowCACreation())
		Expect(err).NotTo(HaveOccurred())
		keyPair, err := certificateManager.GetOrCreateKeyPair(cli, "temp", appNs, appDNSNames)
		Expect(err).NotTo(HaveOccurred())
		cm = &operatorv1.CertificateManagement{CACert: keyPair.GetCertificatePEM()}

		ca, err := crypto.GetCAFromBytes(certificateManager.KeyPair().GetCertificatePEM(), certificateManager.KeyPair().Secret("").Data[corev1.TLSPrivateKeyKey])
		Expect(err).NotTo(HaveOccurred())
		expiredSecret, err = secret.CreateTLSSecret(ca, appSecretName, appNs, legacyKeyFieldName, legacyCertFieldName, -time.Hour, legacyOpts, appSecretName)
		Expect(err).NotTo(HaveOccurred())
	})

	Describe("test CertificateManager interface", func() {
		It("should create a CA if it does not exist yet or reconstruct it from secret", func() {
			By("constructing a new CA and storing it")
			Expect(cli.Create(ctx, certificateManager.KeyPair().Secret(common.OperatorNamespace()))).NotTo(HaveOccurred())

			By("constructing a key pair signed by the CA and storing it in a secret")
			keyPair, err := certificateManager.GetOrCreateKeyPair(cli, appSecretName, appNs, appDNSNames)
			Expect(err).NotTo(HaveOccurred())
			Expect(keyPair).NotTo(BeNil())
			Expect(keyPair.GetIssuer().GetCertificatePEM()).To(Equal(certificateManager.KeyPair().GetCertificatePEM()))

			By("reconstructing certificateManager2 from the secret that was stored")
			certificateManager2, err := certificatemanager.Create(cli, installation, clusterDomain, common.OperatorNamespace())
			Expect(err).NotTo(HaveOccurred())
			Expect(certificateManager2).NotTo(BeNil())
			Expect(keyPair.GetIssuer().GetCertificatePEM()).To(Equal(certificateManager2.KeyPair().GetCertificatePEM())) // Proves that certificateManager & certificateManager2 are identical

			By("deleting the tigera-ca-secret")
			Expect(cli.Delete(ctx, certificateManager.KeyPair().Secret(common.OperatorNamespace()))).NotTo(HaveOccurred())

			By("constructing a brand new CA and storing it")
			certificateManager3, err := certificatemanager.Create(cli, installation, clusterDomain, common.OperatorNamespace(), certificatemanager.AllowCACreation())
			Expect(err).NotTo(HaveOccurred())
			Expect(certificateManager3).NotTo(BeNil())
			Expect(keyPair.GetIssuer().GetCertificatePEM()).NotTo(Equal(certificateManager3.KeyPair().GetCertificatePEM())) // Proves that certificateManager & certificateManager3 are different

			By("Constructing a certificateManager with Certificate management enabled and verifying differences")
			installation.CertificateManagement = cm
			certificateManager4, err := certificatemanager.Create(cli, installation, clusterDomain, common.OperatorNamespace())
			Expect(err).NotTo(HaveOccurred())
			Expect(keyPair.GetIssuer()).NotTo(Equal(certificateManager4.KeyPair()))
			Expect(keyPair.UseCertificateManagement()).To(BeFalse())
			keyPair2, err := certificateManager4.GetOrCreateKeyPair(cli, appSecretName, appNs, appDNSNames)
			Expect(err).NotTo(HaveOccurred())
			Expect(keyPair2.GetIssuer()).NotTo(Equal(certificateManager4.KeyPair())) // We expect the customer to bring an issuer to the cluster
			Expect(keyPair2.UseCertificateManagement()).To(BeTrue())
		})

		It("should now allow creation of a CA unless specified", func() {
			// Create a certificate manager in a namespace without allowing CA creation. It should fail.
			_, err := certificatemanager.Create(cli, installation, clusterDomain, "test-namespace")
			Expect(err).To(HaveOccurred())
		})

		It("should create a KeyPair if it does not exist yet or reconstruct it from secret", func() {
			By("creating a key pair and storing the secret")
			keyPair, err := certificateManager.GetOrCreateKeyPair(cli, appSecretName, appNs, appDNSNames)
			Expect(err).NotTo(HaveOccurred())
			Expect(cli.Create(ctx, keyPair.Secret(appNs))).NotTo(HaveOccurred())

			By("fetching the key pair again and verify the two are identical")
			keyPair2, err := certificateManager.GetOrCreateKeyPair(cli, appSecretName, appNs, appDNSNames)
			Expect(err).NotTo(HaveOccurred())
			Expect(keyPair.HashAnnotationValue()).ToNot(BeNil())
			Expect(keyPair2.HashAnnotationValue()).To(Equal(keyPair.HashAnnotationValue()))
		})

		It("should replace a KeyPair if it was created by an older ca", func() {
			By("creating a key pair and storing the secret")
			keyPair, err := certificateManager.GetOrCreateKeyPair(cli, appSecretName, appNs, appDNSNames)
			Expect(err).NotTo(HaveOccurred())
			Expect(cli.Create(ctx, keyPair.Secret(appNs))).NotTo(HaveOccurred())

			By("fetching the key pair again with a newer ca")
			certificateManager2, err := certificatemanager.Create(cli, installation, clusterDomain, common.OperatorNamespace(), certificatemanager.AllowCACreation())
			Expect(err).NotTo(HaveOccurred())
			Expect(certificateManager2).NotTo(BeNil())
			keyPair2, err := certificateManager2.GetOrCreateKeyPair(cli, appSecretName, appNs, appDNSNames)
			Expect(err).NotTo(HaveOccurred())
			Expect(keyPair.HashAnnotationValue()).ToNot(BeNil())
			Expect(keyPair2.HashAnnotationValue()).NotTo(Equal(keyPair.HashAnnotationValue()))
		})

		It("should be able to fetch a key pair if it exists", func() {
			By("verifying that it returns nil if the key pair does not exist")
			key, err := certificateManager.GetKeyPair(cli, appSecretName, appNs, nil)
			Expect(key).To(BeNil())
			Expect(err).NotTo(HaveOccurred())

			By("creating a key pair and storing the secret")
			keyPair, err := certificateManager.GetOrCreateKeyPair(cli, appSecretName, appNs, appDNSNames)
			Expect(err).NotTo(HaveOccurred())
			Expect(cli.Create(ctx, keyPair.Secret(appNs))).NotTo(HaveOccurred())

			By("verifying that it returns the key pair")
			keyPair2, err := certificateManager.GetKeyPair(cli, appSecretName, appNs, nil)
			Expect(err).NotTo(HaveOccurred())
			Expect(keyPair2).NotTo(BeNil())
		})

		It("should be able to fetch a certificate if it exists", func() {
			By("verifying that it returns nil if the certificate does not exist")
			crt, err := certificateManager.GetCertificate(cli, appSecretName, appNs)
			Expect(crt).To(BeNil())
			Expect(err).NotTo(HaveOccurred())

			By("creating a key pair and storing the secret")
			keyPair, err := certificateManager.GetOrCreateKeyPair(cli, appSecretName, appNs, appDNSNames)
			Expect(err).NotTo(HaveOccurred())
			Expect(cli.Create(ctx, keyPair.Secret(appNs))).NotTo(HaveOccurred())

			By("verifying that it returns the certificate")
			certificate, err := certificateManager.GetCertificate(cli, appSecretName, appNs)
			Expect(err).NotTo(HaveOccurred())
			Expect(certificate).NotTo(BeNil())
		})

		Describe("check ExtKeyUsage", func() {
			It("should update certificates that are only valid for server use", func() {
				x509Cert, err := x509FromSecret(legacySecret)
				Expect(err).NotTo(HaveOccurred())

				// Should not be considered valid.
				valid := certificatemanager.HasRequiredKeyUsage(x509Cert, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth})
				Expect(valid).NotTo(BeTrue())

				// Should create a new secret.
				secret := legacySecret
				Expect(cli.Create(ctx, secret)).NotTo(HaveOccurred())

				_, err = certificateManager.GetCertificate(cli, secret.Name, secret.Namespace)
				Expect(err).To(HaveOccurred())
				// Error from GetCertificate with secret that only has server usage should
				// be a cert error.
				Expect(certificatemanager.IsCertExtKeyUsageError(err)).To(BeTrue())
				Expect(err.Error()).To(ContainSubstring("ExtKeyUsageServerAuth"))
				Expect(err.Error()).To(ContainSubstring("ExtKeyUsageClientAuth"))
				kp, err := certificateManager.GetKeyPair(cli, secret.Name, secret.Namespace, nil)
				Expect(err).NotTo(HaveOccurred())
				Expect(kp).To(BeNil())
				kp, err = certificateManager.GetOrCreateKeyPair(cli, secret.Name, secret.Namespace, []string{appSecretName})
				Expect(err).NotTo(HaveOccurred())
				Expect(kp.GetCertificatePEM()).NotTo(Equal(secret.Data[corev1.TLSCertKey]))
			})

			It("should consider a client+server certificate valid", func() {
				// GetOrCreateKeyPair creates a keypair that is configured to act as both a client and server certificate.
				kp, err := certificateManager.GetOrCreateKeyPair(cli, "secret", "default", []string{"localhost"})
				Expect(err).NotTo(HaveOccurred())

				// Get the x509 cert and make sure it is recognized as valid.
				certPEM := kp.GetCertificatePEM()
				x509Cert, err := certificatemanagement.ParseCertificate(certPEM)
				Expect(err).NotTo(HaveOccurred())
				valid := certificatemanager.HasRequiredKeyUsage(x509Cert, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth})
				Expect(valid).To(BeTrue())
			})
		})

		Describe("test certificate expiry", func() {
			It("should create a new secret when it has expired", func() {
				secret := expiredSecret
				Expect(cli.Create(ctx, secret)).NotTo(HaveOccurred())
				kp, err := certificateManager.GetOrCreateKeyPair(cli, secret.Name, secret.Namespace, []string{appSecretName})
				Expect(err).NotTo(HaveOccurred())
				Expect(kp.GetCertificatePEM()).NotTo(Equal(secret.Data[corev1.TLSCertKey]))
			})

			It("should create a new secret when a legacy operator secret has expired", func() {
				secret := expiredLegacySecret
				Expect(cli.Create(ctx, secret)).NotTo(HaveOccurred())
				kp, err := certificateManager.GetOrCreateKeyPair(cli, secret.Name, secret.Namespace, []string{appSecretName})
				Expect(err).NotTo(HaveOccurred())
				Expect(kp.GetCertificatePEM()).NotTo(Equal(secret.Data[corev1.TLSCertKey]))
			})

			It("should return an error on creating, but return nil on fetching expired byo certificates", func() {
				secret := expiredBYOSecret
				Expect(cli.Create(ctx, secret)).NotTo(HaveOccurred())
				_, err := certificateManager.GetOrCreateKeyPair(cli, secret.Name, secret.Namespace, []string{appSecretName})
				Expect(err).To(HaveOccurred())
				certificate, err := certificateManager.GetCertificate(cli, secret.Name, secret.Namespace)
				Expect(err).NotTo(HaveOccurred())
				Expect(certificate).To(BeNil())
			})

			It("should return an error on legacy byo secrets without client key usage", func() {
				secret := legacyBYOSecret
				Expect(cli.Create(ctx, secret)).NotTo(HaveOccurred())
				_, err := certificateManager.GetOrCreateKeyPair(cli, secret.Name, secret.Namespace, []string{appSecretName})
				Expect(err).To(HaveOccurred())
			})

			It("should ignore the expired secret when certificate management is enabled", func() {
				secret := expiredSecret
				Expect(cli.Create(ctx, secret)).NotTo(HaveOccurred())
				installation.CertificateManagement = cm
				certificateManagerCM, err := certificatemanager.Create(cli, installation, clusterDomain, common.OperatorNamespace(), certificatemanager.AllowCACreation())
				Expect(err).NotTo(HaveOccurred())
				_, err = certificateManagerCM.GetOrCreateKeyPair(cli, secret.Name, secret.Namespace, []string{appSecretName})
				Expect(err).NotTo(HaveOccurred())
			})

			It("should return an error on byo expired secrets when certificate management is enabled", func() {
				secret := expiredBYOSecret
				Expect(cli.Create(ctx, secret)).NotTo(HaveOccurred())
				installation.CertificateManagement = cm
				certificateManagerCM, err := certificatemanager.Create(cli, installation, clusterDomain, common.OperatorNamespace(), certificatemanager.AllowCACreation())
				Expect(err).NotTo(HaveOccurred())
				_, err = certificateManagerCM.GetOrCreateKeyPair(cli, secret.Name, secret.Namespace, []string{appSecretName})
				Expect(err).To(HaveOccurred())
			})

			It("should replace certificates that are in grace period to avoid them from expiry", func() {
				caSecret := certificateManager.KeyPair().Secret("")
				privateKeyPEM, certificatePEM := caSecret.Data[corev1.TLSPrivateKeyKey], caSecret.Data[corev1.TLSCertKey]
				privateKeyDER, _ := pem.Decode(privateKeyPEM)
				Expect(privateKeyDER).NotTo(BeNil())
				cryptoCA, err := crypto.GetCAFromBytes(certificatePEM, privateKeyPEM)
				Expect(err).NotTo(HaveOccurred())
				By("creating a certificate that expires within an hour, which is within the grace period for certificates.")
				tlsCfg, err := cryptoCA.MakeServerCertForDuration(sets.New[string](appSecretName), time.Hour, tls.SetServerAuth, tls.SetClientAuth)
				Expect(err).NotTo(HaveOccurred())
				keyContent, crtContent := &bytes.Buffer{}, &bytes.Buffer{}
				err = tlsCfg.WriteCertConfig(crtContent, keyContent)
				Expect(err).NotTo(HaveOccurred())

				keyPair := &certificatemanagement.KeyPair{
					Issuer:         certificateManager.KeyPair(),
					Name:           appSecretName,
					Namespace:      appSecretName,
					PrivateKeyPEM:  keyContent.Bytes(),
					CertificatePEM: crtContent.Bytes(),
					DNSNames:       []string{appSecretName},
				}
				Expect(cli.Create(ctx, keyPair.Secret(appSecretName).DeepCopy())).NotTo(HaveOccurred())

				By("fetching the secret, we can double check that our cert was indeed created successfully")
				fetchedCert, err := certificateManager.GetCertificate(cli, appSecretName, appSecretName)
				Expect(err).NotTo(HaveOccurred())
				Expect(fetchedCert.GetCertificatePEM()).To(Equal(keyPair.CertificatePEM))

				By("fetching the secret, we force the certificate manager to dispose of the old one and create a new one that won't expire in quite some time.")
				fetchedKeyPair, err := certificateManager.GetOrCreateKeyPair(cli, appSecretName, appSecretName, []string{appSecretName})
				Expect(err).NotTo(HaveOccurred())
				certificate, err := certificatemanagement.ParseCertificate(crtContent.Bytes())
				Expect(err).NotTo(HaveOccurred())
				fetchedCertificate, err := certificatemanagement.ParseCertificate(fetchedKeyPair.GetCertificatePEM())
				Expect(err).NotTo(HaveOccurred())
				Expect(certificate.NotAfter).NotTo(Equal(fetchedCertificate.NotAfter))
			})
		})
	})

	Describe("test KeyPair interface", func() {
		It("should not be possible to modify its internal secret", func() {
			By("creating a key pair")
			keyPair, err := certificateManager.GetOrCreateKeyPair(cli, appSecretName, appNs, appDNSNames)
			Expect(err).NotTo(HaveOccurred())

			By("verifying that the secret() method creates a copy, and does not modify its internal data")
			secret1 := keyPair.Secret("test")
			secret1.Name = "test"
			secret2 := keyPair.Secret("test")
			Expect(secret2.Name).NotTo(Equal(secret1.Name))
		})

		It("render the right spec for certificateManager issued key pairs", func() {
			By("creating a key pair signed by certificateManager")
			keyPair, err := certificateManager.GetOrCreateKeyPair(cli, appSecretName, appNs, appDNSNames)
			Expect(err).NotTo(HaveOccurred())
			Expect(keyPair.UseCertificateManagement()).To(BeFalse())
			Expect(keyPair.BYO()).To(BeFalse())
			Expect(keyPair.GetIssuer().GetCertificatePEM()).To(Equal(certificateManager.KeyPair().GetCertificatePEM()))

			By("verifying the volume is correct")
			volume := keyPair.Volume()
			Expect(volume.Secret).NotTo(BeNil())
			Expect(volume.Name).To(Equal(appSecretName))
			Expect(volume.VolumeSource.Secret.SecretName).To(Equal(appSecretName))

			By("verifying the volume mount is correct")
			mount := keyPair.VolumeMount(rmeta.OSTypeLinux)
			Expect(mount.MountPath).To(Equal("/" + appSecretName))
			Expect(mount.Name).To(Equal(appSecretName))

			By("verifying the annotations")
			Expect(keyPair.HashAnnotationKey()).To(Equal("my-app.hash.operator.tigera.io/my-app-tls"))
			Expect(len(keyPair.HashAnnotationValue())).NotTo(BeNil())
		})

		It("should add cert metadata labels and annotations to the secret", func() {
			By("creating a key pair signed by certificateManager")
			keyPair, err := certificateManager.GetOrCreateKeyPair(cli, appSecretName, appNs, appDNSNames)
			Expect(err).NotTo(HaveOccurred())
			secret := keyPair.Secret(appNs)

			By("verifying the signer label is set")
			Expect(secret.Labels).To(HaveKey("certificates.operator.tigera.io/signer"))
			signerLabel := secret.Labels["certificates.operator.tigera.io/signer"]
			Expect(signerLabel).To(ContainSubstring("tigera-operator-signer"))

			By("verifying cert metadata annotations are present and correct")
			Expect(secret.Annotations).To(HaveKey("certificates.operator.tigera.io/issuer"))
			Expect(secret.Annotations).To(HaveKey("certificates.operator.tigera.io/signer"))
			Expect(secret.Annotations).To(HaveKey("certificates.operator.tigera.io/expiry"))
			Expect(secret.Annotations["certificates.operator.tigera.io/issuer"]).To(ContainSubstring("tigera-operator-signer"))
			Expect(secret.Annotations["certificates.operator.tigera.io/signer"]).To(Equal(secret.Annotations["certificates.operator.tigera.io/issuer"]))
			Expect(secret.Annotations["certificates.operator.tigera.io/expiry"]).To(MatchRegexp(`^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$`))

			By("verifying DNS names annotation contains expected names")
			Expect(secret.Annotations).To(HaveKey("certificates.operator.tigera.io/dns-names"))
			Expect(secret.Annotations["certificates.operator.tigera.io/dns-names"]).To(ContainSubstring(appSecretName))

			By("verifying the hash annotation is on the secret")
			Expect(secret.Annotations).To(HaveKey(keyPair.HashAnnotationKey()))
			Expect(secret.Annotations[keyPair.HashAnnotationKey()]).To(Equal(keyPair.HashAnnotationValue()))
		})

		It("should add cert metadata for BYO secrets", func() {
			By("creating a BYO secret and fetching it via certificateManager")
			Expect(cli.Create(ctx, byoSecret)).NotTo(HaveOccurred())
			keyPair, err := certificateManager.GetOrCreateKeyPair(cli, appSecretName, appNs, appDNSNames)
			Expect(err).NotTo(HaveOccurred())
			Expect(keyPair.BYO()).To(BeTrue())
			secret := keyPair.Secret(appNs)

			By("verifying the signer label reflects the BYO CA")
			Expect(secret.Labels).To(HaveKey("certificates.operator.tigera.io/signer"))
			Expect(secret.Labels["certificates.operator.tigera.io/signer"]).To(ContainSubstring("byo-ca"))

			By("verifying cert metadata annotations reflect the BYO certificate")
			Expect(secret.Annotations).To(HaveKey("certificates.operator.tigera.io/issuer"))
			Expect(secret.Annotations["certificates.operator.tigera.io/issuer"]).To(ContainSubstring("byo-ca"))
			Expect(secret.Annotations).To(HaveKey("certificates.operator.tigera.io/expiry"))
		})

		It("renders the right spec for certificate management", func() {
			By("creating a key pair w/ certificate management")
			installation.CertificateManagement = cm
			certificateManager, err := certificatemanager.Create(cli, installation, clusterDomain, common.OperatorNamespace(), certificatemanager.AllowCACreation())
			Expect(err).NotTo(HaveOccurred())
			keyPair, err := certificateManager.GetOrCreateKeyPair(cli, appSecretName, appNs, appDNSNames)
			Expect(err).NotTo(HaveOccurred())
			Expect(keyPair.UseCertificateManagement()).To(BeTrue())
			Expect(keyPair.BYO()).To(BeFalse())
			Expect(keyPair.GetIssuer()).NotTo(Equal(certificateManager.KeyPair()))

			By("verifying the volume is correct")
			volume := keyPair.Volume()
			Expect(volume.EmptyDir).NotTo(BeNil())
			Expect(volume.Name).To(Equal(appSecretName))
			Expect(volume.VolumeSource.EmptyDir).NotTo(BeNil())

			By("verifying the volume mount is correct")
			mount := keyPair.VolumeMount(rmeta.OSTypeLinux)
			Expect(mount.MountPath).To(Equal("/" + appSecretName))
			Expect(mount.Name).To(Equal(appSecretName))

			By("verifying the annotations")
			Expect(keyPair.HashAnnotationKey()).To(Equal("my-app.hash.operator.tigera.io/my-app-tls"))
			Expect(keyPair.HashAnnotationValue()).To(Equal(""))

			By("verifying the init container")
			initContainer := keyPair.InitContainer(appNs, nil)
			imageSet, err := imageset.GetImageSet(context.Background(), cli, installation.Variant)
			Expect(err).NotTo(HaveOccurred())
			expectedImage, err := components.GetReference(
				components.ComponentCalico,
				installation.Registry,
				installation.ImagePath,
				installation.ImagePrefix,
				imageSet,
			)
			Expect(err).NotTo(HaveOccurred())
			Expect(initContainer.Image).To(Equal(expectedImage))
			Expect(initContainer.Env).To(ContainElement(corev1.EnvVar{Name: "COMMON_NAME", Value: appSecretName}))
		})

		It("renders the right spec for BYO certs", func() {
			By("creating a BYO corev1.Secret and then create a KeyPair using the certificateManager")
			Expect(cli.Create(ctx, byoSecret)).NotTo(HaveOccurred())
			keyPair, err := certificateManager.GetOrCreateKeyPair(cli, appSecretName, appNs, appDNSNames)
			Expect(err).NotTo(HaveOccurred())
			Expect(keyPair.UseCertificateManagement()).To(BeFalse())
			Expect(keyPair.BYO()).To(BeTrue())
			Expect(keyPair.GetIssuer()).NotTo(Equal(certificateManager.KeyPair()))

			By("verifying the volume is correct")
			volume := keyPair.Volume()
			Expect(volume.Secret).NotTo(BeNil())
			Expect(volume.Name).To(Equal(appSecretName))
			Expect(volume.VolumeSource.Secret.SecretName).To(Equal(appSecretName))

			By("verifying the volume mount is correct")
			mount := keyPair.VolumeMount(rmeta.OSTypeLinux)
			Expect(mount.MountPath).To(Equal("/" + appSecretName))
			Expect(mount.Name).To(Equal(appSecretName))

			By("verifying the annotations")
			Expect(keyPair.HashAnnotationKey()).To(Equal("my-app.hash.operator.tigera.io/my-app-tls"))
			Expect(len(keyPair.HashAnnotationValue())).NotTo(BeNil())

			By("verifying that the non-standard secret fields have been standardized")
			Expect(keyPair.Secret(appNs).Data[corev1.TLSPrivateKeyKey]).NotTo(BeNil())
			Expect(keyPair.Secret(appNs).Data[corev1.TLSCertKey]).NotTo(BeNil())
		})

		It("handles missing DNS names as expected", func() {
			missingDNSNames := append(appDNSNames, "missing-name")
			By("verifying it does replace a secret when dns names are missing")
			keyPair, err := certificateManager.GetOrCreateKeyPair(cli, appSecretName, appNs, appDNSNames)
			Expect(err).NotTo(HaveOccurred())
			Expect(cli.Create(ctx, keyPair.Secret(appNs))).NotTo(HaveOccurred())
			Expect(err).NotTo(HaveOccurred())
			test.VerifyCertSANs(keyPair.GetCertificatePEM(), appDNSNames...)
			keyPair, err = certificateManager.GetOrCreateKeyPair(cli, appSecretName, appNs, missingDNSNames)
			Expect(err).NotTo(HaveOccurred())
			test.VerifyCertSANs(keyPair.GetCertificatePEM(), missingDNSNames...)

			By("verifying it does replace a legacy secret when dns names are missing")
			Expect(cli.Create(ctx, legacyWithClientKeyUsage)).NotTo(HaveOccurred())
			keyPair, err = certificateManager.GetOrCreateKeyPair(cli, legacySecretName, appNs, appDNSNames)
			Expect(err).NotTo(HaveOccurred())
			test.VerifyCertSANs(keyPair.GetCertificatePEM(), appDNSNames...)
			keyPair, err = certificateManager.GetOrCreateKeyPair(cli, legacySecretName, appNs, missingDNSNames)
			Expect(err).NotTo(HaveOccurred())
			test.VerifyCertSANs(keyPair.GetCertificatePEM(), missingDNSNames...)

			By("verifying it does not replace a BYO secret, nor throw an error")
			Expect(cli.Update(ctx, byoSecret)).NotTo(HaveOccurred())
			keyPair, err = certificateManager.GetOrCreateKeyPair(cli, appSecretName, appNs, missingDNSNames)
			Expect(err).NotTo(HaveOccurred())
			Expect(keyPair.UseCertificateManagement()).To(BeFalse())
			Expect(keyPair.BYO()).To(BeTrue())
			Expect(keyPair.GetIssuer()).NotTo(Equal(certificateManager.KeyPair()))
		})

		It("renders the right spec for legacy certs (<= v1.24)", func() {
			By("creating a legacy secret and then create a KeyPair using the certificateManager")
			Expect(cli.Create(ctx, legacySecret)).NotTo(HaveOccurred())
			keyPair, err := certificateManager.GetOrCreateKeyPair(cli, appSecretName, appNs, appDNSNames)
			Expect(err).NotTo(HaveOccurred())

			// Legacy certs don't specify a usage key of client, and so they will be reissued
			// using the new tigera-operator CA certificate. As such, we expect them to match
			// the new issuer.
			Expect(keyPair.UseCertificateManagement()).To(BeFalse())
			Expect(keyPair.BYO()).NotTo(BeTrue())
			Expect(keyPair.GetIssuer().GetCertificatePEM()).To(Equal(certificateManager.KeyPair().GetCertificatePEM()))

			By("verifying the volume is correct")
			volume := keyPair.Volume()
			Expect(volume.Secret).NotTo(BeNil())
			Expect(volume.Name).To(Equal(appSecretName))
			Expect(volume.VolumeSource.Secret.SecretName).To(Equal(appSecretName))

			By("verifying the volume mount is correct")
			mount := keyPair.VolumeMount(rmeta.OSTypeLinux)
			Expect(mount.MountPath).To(Equal("/" + appSecretName))
			Expect(mount.Name).To(Equal(appSecretName))

			By("verifying the annotations")
			Expect(keyPair.HashAnnotationKey()).To(Equal("my-app.hash.operator.tigera.io/my-app-tls"))
			Expect(len(keyPair.HashAnnotationValue())).NotTo(BeNil())

			By("verifying that the non-standard secret fields have been standardized")
			Expect(keyPair.Secret(appNs).Data[corev1.TLSPrivateKeyKey]).NotTo(BeNil())
			Expect(keyPair.Secret(appNs).Data[corev1.TLSCertKey]).NotTo(BeNil())
		})

		It("should default the CA secret name", func() {
			cm, err := certificatemanager.Create(cli, installation, clusterDomain, common.OperatorNamespace(), certificatemanager.AllowCACreation())
			Expect(err).NotTo(HaveOccurred())
			Expect(cm.KeyPair().GetName()).To(Equal(certificatemanagement.CASecretName))
		})

		It("should read the CA from the secret name it is given", func() {
			cm, err := certificatemanager.Create(cli, installation, clusterDomain, common.OperatorNamespace(), certificatemanager.AllowCACreation(), certificatemanager.WithCASecretName("my-own-ca"))
			Expect(err).NotTo(HaveOccurred())
			Expect(cm.KeyPair().GetName()).To(Equal("my-own-ca"))
		})
	})

	Describe("test TrustedBundle interface", func() {
		It("should add a pem block for each certificate", func() {
			By("creating five secrets in the datastore", func() {
				keyPair, err := certificateManager.GetOrCreateKeyPair(cli, appSecretName, appNs, appDNSNames)
				Expect(err).NotTo(HaveOccurred())
				Expect(cli.Create(ctx, keyPair.Secret(common.OperatorNamespace()))).NotTo(HaveOccurred())

				keyPair2, err := certificateManager.GetOrCreateKeyPair(cli, appSecretName2, appNs, appDNSNames)
				Expect(err).NotTo(HaveOccurred())
				Expect(cli.Create(ctx, keyPair2.Secret(common.OperatorNamespace()))).NotTo(HaveOccurred())

				byoSecret.Name, byoSecret.Namespace = "byo-secret", common.OperatorNamespace()
				Expect(cli.Create(ctx, byoSecret)).NotTo(HaveOccurred())

				legacySecret.Name, legacySecret.Namespace = "legacy-secret", common.OperatorNamespace()
				Expect(cli.Create(ctx, legacySecret)).NotTo(HaveOccurred())

				legacyWithClientKeyUsage.Name, legacyWithClientKeyUsage.Namespace = "legacy-secret-wcku", common.OperatorNamespace()
				Expect(cli.Create(ctx, legacyWithClientKeyUsage)).NotTo(HaveOccurred())
			})

			By("querying and validating the five certificates")
			cert, err := certificateManager.GetCertificate(cli, appSecretName, common.OperatorNamespace())
			Expect(err).NotTo(HaveOccurred())

			cert2, err := certificateManager.GetCertificate(cli, appSecretName2, common.OperatorNamespace())
			Expect(err).NotTo(HaveOccurred())

			byo, err := certificateManager.GetCertificate(cli, byoSecret.Name, common.OperatorNamespace())
			Expect(err).NotTo(HaveOccurred())

			lwcku, err := certificateManager.GetCertificate(cli, legacyWithClientKeyUsage.Name, common.OperatorNamespace())
			Expect(err).NotTo(HaveOccurred())

			kp, err := certificateManager.GetOrCreateKeyPair(cli, legacySecret.Name, common.OperatorNamespace(), []string{appSecretName})
			Expect(err).NotTo(HaveOccurred())
			Expect(cli.Update(ctx, kp.Secret(common.OperatorNamespace()))).NotTo(HaveOccurred())

			legacy, err := certificateManager.GetCertificate(cli, legacySecret.Name, common.OperatorNamespace())
			Expect(err).NotTo(HaveOccurred())

			Expect(cert.GetIssuer().GetCertificatePEM()).To(Equal(certificateManager.KeyPair().GetCertificatePEM()))
			Expect(cert2.GetIssuer().GetCertificatePEM()).To(Equal(certificateManager.KeyPair().GetCertificatePEM()))
			Expect(byo.GetIssuer()).NotTo(Equal(certificateManager.KeyPair()))
			Expect(lwcku.GetIssuer()).NotTo(Equal(certificateManager.KeyPair()))

			// The legacy certificate will have been reissued, and so will match the operator CA.
			Expect(legacy.GetIssuer().GetCertificatePEM()).To(Equal(certificateManager.KeyPair().GetCertificatePEM()))

			By("creating and validating a trusted certificate bundle")
			trustedBundle := certificateManager.CreateTrustedBundle(cert, cert2, byo, legacy, lwcku)
			Expect(trustedBundle.Volume()).To(Equal(corev1.Volume{
				Name: "tigera-ca-bundle",
				VolumeSource: corev1.VolumeSource{
					ConfigMap: &corev1.ConfigMapVolumeSource{
						LocalObjectReference: corev1.LocalObjectReference{Name: "tigera-ca-bundle"},
					},
				},
			}))
			Expect(trustedBundle.VolumeMounts(rmeta.OSTypeLinux)).To(Equal([]corev1.VolumeMount{
				{
					Name:      "tigera-ca-bundle",
					MountPath: "/etc/pki/tls/certs",
					ReadOnly:  true,
				},
			}))
			Expect(trustedBundle.MountPath()).To(Equal(certificatemanagement.TrustedCertBundleMountPath))
			configMap := trustedBundle.ConfigMap(appNs)
			Expect(configMap.Name).To(Equal("tigera-ca-bundle"))
			Expect(configMap.Namespace).To(Equal(appNs))
			Expect(configMap.Annotations).To(HaveKey("tigera-operator.hash.operator.tigera.io/tigera-ca-private"))
			Expect(configMap.Annotations).To(HaveKey("tigera-operator.hash.operator.tigera.io/legacy-secret-wcku"))
			Expect(configMap.Annotations).To(HaveKey("tigera-operator.hash.operator.tigera.io/byo-secret"))
			Expect(configMap.TypeMeta).To(Equal(metav1.TypeMeta{Kind: "ConfigMap", APIVersion: "v1"}))

			By("counting the number of pem blocks in the configmap")
			bundle := configMap.Data[certificatemanagement.TrustedCertConfigMapKeyName]
			numBlocks := strings.Count(bundle, "certificate name:")

			// While we have the ca + 4 certs, we expect 3 cert blocks (+ 2):
			// - the certificateManager: this covers for all certs signed by the tigera root ca
			// - the byo block (+ its ca block)
			// - the legacy cert that already has ExtKeyUsageClient configured.
			Expect(numBlocks).To(Equal(3))
			Expect(trustedBundle.HashAnnotations()).To(HaveKey("tigera-operator.hash.operator.tigera.io/tigera-ca-private"))
			Expect(trustedBundle.HashAnnotations()).To(HaveKey("tigera-operator.hash.operator.tigera.io/byo-secret"))
			Expect(trustedBundle.HashAnnotations()).To(HaveKey("tigera-operator.hash.operator.tigera.io/legacy-secret-wcku"))
		})

		It("should load the system certificates into the bundle", func() {
			if runtime.GOOS != "linux" {
				Skip("Skip for users that run this test outside of a container on incompatible systems.")
			}
			trustedBundle, err := certificateManager.CreateTrustedBundleWithSystemRootCertificates()
			Expect(err).NotTo(HaveOccurred())
			configMap := trustedBundle.ConfigMap(appNs)
			Expect(configMap.Name).To(Equal("tigera-ca-bundle"))
			Expect(configMap.Namespace).To(Equal(appNs))
			Expect(configMap.Annotations).To(HaveKey("tigera-operator.hash.operator.tigera.io/tigera-ca-private"))
			Expect(configMap.Annotations).To(HaveKey("hash.operator.tigera.io/system"))
			Expect(configMap.TypeMeta).To(Equal(metav1.TypeMeta{Kind: "ConfigMap", APIVersion: "v1"}))

			By("counting the number of pem blocks in the configmap")
			bundle := configMap.Data[certificatemanagement.RHELRootCertificateBundleName]
			numBlocks := strings.Count(bundle, "-----BEGIN CERTIFICATE-----")
			Expect(numBlocks > 1).To(BeTrue()) // We expect tens of them most likely.
		})

		It("should create a hash for both secrets even if the same pem is used twice", func() {
			By("creating 2 secrets with identical pem in the datastore", func() {
				byoSecretCopy := byoSecret.DeepCopyObject().(*corev1.Secret)

				byoSecret.Name, byoSecret.Namespace = "byo-secret", common.OperatorNamespace()
				Expect(cli.Create(ctx, byoSecret)).NotTo(HaveOccurred())

				byoSecretCopy.Name, byoSecretCopy.Namespace = "byo-secret-copy", common.OperatorNamespace()
				Expect(cli.Create(ctx, byoSecretCopy)).NotTo(HaveOccurred())
			})

			var trustedBundle certificatemanagement.TrustedBundle
			By("creating the bundle from the certificates", func() {
				byo, err := certificateManager.GetCertificate(cli, "byo-secret", common.OperatorNamespace())
				Expect(err).NotTo(HaveOccurred())
				byoCopy, err := certificateManager.GetCertificate(cli, "byo-secret-copy", common.OperatorNamespace())
				Expect(err).NotTo(HaveOccurred())
				Expect(byo.GetIssuer()).NotTo(Equal(certificateManager.KeyPair()))
				Expect(byoCopy.GetIssuer()).NotTo(Equal(certificateManager.KeyPair()))
				trustedBundle = certificateManager.CreateTrustedBundle(byo, byoCopy)
			})

			By("verifying the hash annotations and pem blocks of the bundle", func() {
				bundle := trustedBundle.ConfigMap("").Data[certificatemanagement.TrustedCertConfigMapKeyName]
				numBlocks := strings.Count(bundle, "certificate name:")
				Expect(numBlocks).To(Equal(3))
				Expect(trustedBundle.HashAnnotations()).To(HaveKey("tigera-operator.hash.operator.tigera.io/tigera-ca-private"))
				Expect(trustedBundle.HashAnnotations()).To(HaveKey("tigera-operator.hash.operator.tigera.io/byo-secret-copy"))
				Expect(trustedBundle.HashAnnotations()).To(HaveKey("tigera-operator.hash.operator.tigera.io/byo-secret"))
			})
		})
	})
})

func x509FromSecret(secret *corev1.Secret) (*x509.Certificate, error) {
	_, certPEM := certificatemanagement.GetKeyCertPEM(secret)
	x509Cert, err := certificatemanagement.ParseCertificate(certPEM)
	if err != nil {
		return nil, err
	}
	return x509Cert, nil
}
