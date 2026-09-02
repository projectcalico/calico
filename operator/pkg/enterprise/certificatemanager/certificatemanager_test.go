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

package certificatemanager_test

import (
	"runtime"
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8sruntime "k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	operatorv1 "github.com/projectcalico/calico/operator/api/v1"
	"github.com/projectcalico/calico/operator/pkg/apis"
	"github.com/projectcalico/calico/operator/pkg/common"
	"github.com/projectcalico/calico/operator/pkg/controller/certificatemanager"
	ctrlrfake "github.com/projectcalico/calico/operator/pkg/ctrlruntime/client/fake"
	entcertificatemanager "github.com/projectcalico/calico/operator/pkg/enterprise/certificatemanager"
	rmeta "github.com/projectcalico/calico/operator/pkg/render/common/meta"
	"github.com/projectcalico/calico/operator/pkg/tls/certificatemanagement"
)

const (
	appNs         = "my-app"
	clusterDomain = "cluster.local"
)

var _ = Describe("Enterprise certificate manager", func() {
	var (
		cli          client.Client
		installation *operatorv1.InstallationSpec
	)

	BeforeEach(func() {
		scheme := k8sruntime.NewScheme()
		Expect(apis.AddToScheme(scheme, false)).NotTo(HaveOccurred())
		Expect(corev1.SchemeBuilder.AddToScheme(scheme)).NotTo(HaveOccurred())
		cli = ctrlrfake.DefaultFakeClientBuilder(scheme).Build()
		installation = &operatorv1.InstallationSpec{}
	})

	create := func(tenant *operatorv1.Tenant) certificatemanager.CertificateManager {
		cm, err := entcertificatemanager.Create(cli, installation, clusterDomain, common.OperatorNamespace(), tenant, certificatemanager.AllowCACreation())
		Expect(err).NotTo(HaveOccurred())
		return cm
	}

	It("should render correct CA secret name for zero-tenant configuration", func() {
		Expect(create(nil).KeyPair().GetName()).To(Equal(certificatemanagement.CASecretName))
	})

	It("should render correct CA secret name for single-tenant configuration", func() {
		tenant := &operatorv1.Tenant{ObjectMeta: metav1.ObjectMeta{Name: "single-tenant", Namespace: ""}}
		Expect(create(tenant).KeyPair().GetName()).To(Equal(certificatemanagement.CASecretName))
	})

	It("should render correct CA secret name for multi-tenant configuration", func() {
		tenant := &operatorv1.Tenant{ObjectMeta: metav1.ObjectMeta{Name: "multi-tenant", Namespace: "tenant-namespace-a"}}
		Expect(create(tenant).KeyPair().GetName()).To(Equal(certificatemanagement.TenantCASecretName))
	})

	It("should load the system certificates into a multi-tenant bundle", func() {
		if runtime.GOOS != "linux" {
			Skip("Skip for users that run this test outside of a container on incompatible systems.")
		}
		trustedBundle, err := entcertificatemanager.CreateTenantBundleWithSystemRootCertificates(create(nil))
		Expect(err).NotTo(HaveOccurred())

		configMap := trustedBundle.ConfigMap(appNs)
		Expect(configMap.Name).To(Equal("tigera-ca-bundle-system-certs"))
		Expect(configMap.Namespace).To(Equal(appNs))
		Expect(configMap.Annotations).To(HaveKey("tigera-operator.hash.operator.tigera.io/tigera-ca-private"))
		Expect(configMap.Annotations).To(HaveKey("hash.operator.tigera.io/system"))
		Expect(configMap.TypeMeta).To(Equal(metav1.TypeMeta{Kind: "ConfigMap", APIVersion: "v1"}))

		By("counting the number of pem blocks in the configmap")
		bundle := configMap.Data[certificatemanagement.RHELRootCertificateBundleName]
		Expect(strings.Count(bundle, "-----BEGIN CERTIFICATE-----") > 1).To(BeTrue())

		By("verifying the volume is correct")
		volume := trustedBundle.Volume()
		Expect(volume.ConfigMap).NotTo(BeNil())
		Expect(volume.Name).To(Equal("tigera-ca-bundle-system-certs"))
		Expect(volume.VolumeSource.ConfigMap.Name).To(Equal("tigera-ca-bundle-system-certs"))

		By("verifying the volume mount is correct")
		Expect(trustedBundle.VolumeMounts(rmeta.OSTypeLinux)).To(Equal([]corev1.VolumeMount{
			{
				Name:      "tigera-ca-bundle-system-certs",
				MountPath: "/etc/pki/tls/certs",
				ReadOnly:  true,
			},
			{
				Name:      "tigera-ca-bundle-system-certs",
				MountPath: "/etc/pki/tls/cert.pem",
				SubPath:   "ca-bundle.crt",
				ReadOnly:  true,
			},
		}))
	})
})
