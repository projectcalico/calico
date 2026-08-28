// Copyright (c) 2024-2026 Tigera, Inc. All rights reserved.

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

package utils_test

import (
	"context"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	operatorv1 "github.com/projectcalico/calico/operator/api/v1"
	"github.com/projectcalico/calico/operator/pkg/apis"
	"github.com/projectcalico/calico/operator/pkg/common"
	"github.com/projectcalico/calico/operator/pkg/controller/certificatemanager"
	ctrlrfake "github.com/projectcalico/calico/operator/pkg/ctrlruntime/client/fake"
	"github.com/projectcalico/calico/operator/pkg/enterprise/utils"
)

var _ = Describe("LDAP secrets tests", func() {
	var (
		cli         client.Client
		ctx         context.Context
		validCert   []byte
		invalidCert = []byte("----fakecert-----")
	)

	BeforeEach(func() {
		scheme := runtime.NewScheme()
		Expect(apis.AddToScheme(scheme, false)).NotTo(HaveOccurred())
		Expect(corev1.SchemeBuilder.AddToScheme(scheme)).ShouldNot(HaveOccurred())
		Expect(operatorv1.SchemeBuilder.AddToScheme(scheme)).ShouldNot(HaveOccurred())

		cli = ctrlrfake.DefaultFakeClientBuilder(scheme).Build()

		ctx = context.Background()
		certificateManager, err := certificatemanager.Create(cli, &operatorv1.InstallationSpec{}, ".cluster.local", common.OperatorNamespace(), certificatemanager.AllowCACreation())
		Expect(err).NotTo(HaveOccurred())
		keyPair, err := certificateManager.GetOrCreateKeyPair(cli, "temp", "temp", []string{"temp"})
		Expect(err).NotTo(HaveOccurred())
		validCert = keyPair.GetCertificatePEM()
	})

	DescribeTable("test ldap validation", func(bindDN, bindPW string, rootCA *[]byte, expectErr bool) {
		err := cli.Create(ctx, &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "tigera-ldap-credentials",
				Namespace: common.OperatorNamespace(),
			},
			Data: map[string][]byte{
				"bindDN": []byte(bindDN),
				"bindPW": []byte(bindPW),
				"rootCA": validCert,
			},
		})
		Expect(err).NotTo(HaveOccurred())

		_, err = utils.GetIDPSecret(ctx, cli, &operatorv1.Authentication{Spec: operatorv1.AuthenticationSpec{LDAP: &operatorv1.AuthenticationLDAP{}}})
		if expectErr {
			Expect(err).To(HaveOccurred())
		} else {
			Expect(err).NotTo(HaveOccurred())
		}
	},
		Entry("valid bind ca, dn and pw", `CN=example,OU=finance,DC=com`, "tigera-secure", &validCert, false),
		Entry("valid escape of quotes escaped dn", `CN=example,OU=\"finance\",DC=com`, "tigera-secure", &validCert, false),
		Entry("valid escaped quotes in dn", `CN=example,OU=\"finance department\",DC=com`, "tigera-secure", &validCert, false),
		Entry("valid space in dn", `CN=example,OU=finance department,DC=com`, "tigera-secure", &validCert, false),
		Entry("valid escaped backslash in pw with proper escape", `CN=example,OU=finance,DC=com`, "tige\\ra-secure", &validCert, false),
		Entry("invalid unescaped quotes in dn", `CN=example,OU="finance",DC=com`, "tigera-secure", &validCert, true),
		Entry("invalid backslash in pw", `CN=example,OU=finance",DC=com`, "tige\ra-secure", &validCert, true),
		Entry("invalid rootCA", `CN=example,OU=finance",DC=com`, "tige\ra-secure", &invalidCert, true),
	)
})
