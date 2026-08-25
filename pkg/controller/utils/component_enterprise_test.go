// Copyright (c) 2026 Tigera, Inc. All rights reserved.

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

	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	"k8s.io/utils/ptr"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/apis"
	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/controller/certificatemanager"
	"github.com/tigera/operator/pkg/controller/k8sapi"
	"github.com/tigera/operator/pkg/controller/utils"
	ctrlrfake "github.com/tigera/operator/pkg/ctrlruntime/client/fake"
	"github.com/tigera/operator/pkg/dns"
	"github.com/tigera/operator/pkg/enterprise"
	eoptions "github.com/tigera/operator/pkg/enterprise/options"
	"github.com/tigera/operator/pkg/render"
)

// A real typha component goes through the handler with the enterprise modifier
// attached, so this fails if dispatch or the modifier stops matching render.
var _ = Describe("enterprise typha modifier integration", func() {
	// Both spellings have to reach the modifier: an Installation asking for the
	// deprecated TigeraSecureEnterprise otherwise renders Typha without the
	// Enterprise-only permissions, and Typha never becomes ready.
	DescribeTable("applies the enterprise typha modifier to real render output",
		func(variant operatorv1.ProductVariant) {
			scheme := runtime.NewScheme()
			Expect(apis.AddToScheme(scheme, false)).NotTo(HaveOccurred())
			cli := ctrlrfake.DefaultFakeClientBuilder(scheme).Build()

			certManager, err := certificatemanager.Create(cli, nil, "", common.OperatorNamespace(), certificatemanager.AllowCACreation())
			Expect(err).NotTo(HaveOccurred())
			nodeKeyPair, err := certManager.GetOrCreateKeyPair(cli, render.NodeTLSSecretName, common.OperatorNamespace(), []string{render.FelixCommonName})
			Expect(err).NotTo(HaveOccurred())
			typhaKeyPair, err := certManager.GetOrCreateKeyPair(cli, render.TyphaTLSSecretName, common.OperatorNamespace(), []string{render.TyphaCommonName})
			Expect(err).NotTo(HaveOccurred())

			instance := &operatorv1.InstallationSpec{
				Variant: variant,
				CNI:     &operatorv1.CNISpec{Type: operatorv1.PluginCalico},
			}
			typhaCfg := &render.TyphaConfiguration{
				K8sServiceEp:       k8sapi.ServiceEndpoint{},
				Installation:       instance,
				ClusterDomain:      dns.DefaultClusterDomain,
				FelixConfiguration: &v3.FelixConfiguration{Spec: v3.FelixConfigurationSpec{HealthPort: ptr.To(9099)}},
				TLS: &render.TyphaNodeTLS{
					TrustedBundle:   certManager.CreateTrustedBundle(),
					TyphaSecret:     typhaKeyPair,
					TyphaCommonName: render.TyphaCommonName,
					NodeSecret:      nodeKeyPair,
					NodeCommonName:  render.FelixCommonName,
				},
			}

			ext := enterprise.New(variant, eoptions.Options{}).Installation()
			renderInputs := render.Inputs{Installation: instance}
			handler := utils.NewComponentHandler(logf.Log, cli, scheme, nil, utils.WithModifier(func(c render.Component) render.Component {
				return ext.Modify(c, renderInputs)
			}))
			Expect(handler.CreateOrUpdateOrDelete(context.Background(), render.Typha(typhaCfg), nil)).NotTo(HaveOccurred())

			role := &rbacv1.ClusterRole{}
			Expect(cli.Get(context.Background(), client.ObjectKey{Name: "calico-typha"}, role)).NotTo(HaveOccurred())
			Expect(role.Rules).To(ContainElement(HaveField("Resources", ContainElement("licensekeys"))))
		},
		Entry("CalicoEnterprise", operatorv1.CalicoEnterprise),
		//nolint:staticcheck // SA1019: the deprecated spelling is what this covers
		Entry("TigeraSecureEnterprise", operatorv1.TigeraSecureEnterprise),
	)
})
