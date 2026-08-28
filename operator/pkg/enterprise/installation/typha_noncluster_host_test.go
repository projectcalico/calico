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

package installation_test

import (
	"context"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/stretchr/testify/mock"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"

	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/controller"
	"github.com/tigera/operator/pkg/controller/k8sapi"
	"github.com/tigera/operator/pkg/controller/status"
	"github.com/tigera/operator/pkg/controller/utils"
	"github.com/tigera/operator/pkg/dns"
	"github.com/tigera/operator/pkg/enterprise"
	eoptions "github.com/tigera/operator/pkg/enterprise/options"
	"github.com/tigera/operator/pkg/extensions"
	"github.com/tigera/operator/pkg/extensions/extensionstest"
	"github.com/tigera/operator/pkg/render"
	"github.com/tigera/operator/pkg/render/kubecontrollers"
)

var _ = Describe("non-cluster host typha", func() {
	const nchDeploymentName = common.TyphaDeploymentName + render.TyphaNonClusterHostSuffix

	var (
		nchExt     extensions.Extensions
		nchCtx     context.Context
		cancel     context.CancelFunc
		mockStatus *status.MockStatus
	)

	BeforeEach(func() {
		// The extension owns the autoscaler goroutine, so each spec gets its own.
		nchExt = enterprise.New(operatorv1.CalicoEnterprise, eoptions.Options{})
		nchCtx, cancel = context.WithCancel(context.Background())
		mockStatus = &status.MockStatus{}
		mockStatus.On("SetDegraded", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return()
	})

	AfterEach(func() {
		cancel()
	})

	nchControllerInputs := func(objs ...client.Object) controller.Inputs {
		ci := newControllerInputs(operatorv1.CalicoEnterprise, objs...)
		ci.Status = mockStatus
		ci.ShutdownContext = nchCtx
		ci.RenderInputs.FelixConfiguration = &v3.FelixConfiguration{
			Spec: v3.FelixConfigurationSpec{HealthPort: ptr.To(9099)},
		}
		ci.RenderInputs.Installation.CNI = &operatorv1.CNISpec{Type: operatorv1.PluginCalico}
		return ci
	}

	nonClusterHost := func() client.Object {
		return &operatorv1.NonClusterHost{ObjectMeta: metav1.ObjectMeta{Name: utils.DefaultEnterpriseInstanceKey.Name}}
	}

	typhaNodeTLSFor := func(ci controller.Inputs) *render.TyphaNodeTLS {
		node, err := ci.CertificateManager.GetOrCreateKeyPair(ci.Client, render.NodeTLSSecretName, common.OperatorNamespace(), []string{render.FelixCommonName})
		Expect(err).NotTo(HaveOccurred())
		typha, err := ci.CertificateManager.GetOrCreateKeyPair(ci.Client, render.TyphaTLSSecretName, common.OperatorNamespace(), []string{render.TyphaCommonName})
		Expect(err).NotTo(HaveOccurred())

		return &render.TyphaNodeTLS{
			TrustedBundle:   ci.CertificateManager.CreateTrustedBundle(node, typha),
			TyphaSecret:     typha,
			TyphaCommonName: render.TyphaCommonName,
			NodeSecret:      node,
			NodeCommonName:  render.FelixCommonName,
		}
	}

	// renderTypha renders the real typha component and runs the extension over it,
	// exactly as the installation controller does.
	renderTypha := func(ci controller.Inputs) []client.Object {
		cfg := &render.TyphaConfiguration{
			K8sServiceEp:       k8sapi.Endpoint,
			Installation:       ci.RenderInputs.Installation,
			TLS:                typhaNodeTLSFor(ci),
			ClusterDomain:      dns.DefaultClusterDomain,
			FelixConfiguration: ci.RenderInputs.FelixConfiguration,
		}
		component := render.Typha(cfg)
		Expect(component.ResolveImages(nil)).NotTo(HaveOccurred())
		created, del := component.Objects()

		stub := extensionstest.TyphaStub{
			StubComponent: extensionstest.StubComponent{Create: created, Delete: del},
			Cfg:           cfg,
		}
		out, _ := nchExt.Installation().Modify(stub, ci.RenderInputs).Objects()
		return out
	}

	nchDeployment := func(objs []client.Object) *appsv1.Deployment {
		dep, ok := extensions.FindObject[*appsv1.Deployment](objs, nchDeploymentName)
		Expect(ok).To(BeTrue())
		return dep
	}

	It("renders a second Typha deployment and service for non-cluster hosts", func() {
		ci, _, err := nchExt.Installation().ExtendInputs(nchCtx, nchControllerInputs(nonClusterHost()))
		Expect(err).NotTo(HaveOccurred())
		objs := renderTypha(ci)

		svc, ok := extensions.FindObject[*corev1.Service](objs, render.TyphaServiceName+render.TyphaNonClusterHostSuffix)
		Expect(ok).To(BeTrue())
		Expect(svc.Spec.Selector).To(HaveKeyWithValue(render.AppLabelName, nchDeploymentName))

		d := nchDeployment(objs)
		Expect(d.Spec.Template.Spec.Affinity).To(BeNil())
		Expect(d.Spec.Template.Spec.HostNetwork).To(BeFalse())
		Expect(d.Spec.Template.Spec.Containers).To(HaveLen(1))
		Expect(d.Spec.Template.Spec.Containers[0].Env).To(ContainElements(
			corev1.EnvVar{Name: "TYPHA_CLIENTCN", Value: render.FelixCommonName + render.TyphaNonClusterHostSuffix},
			corev1.EnvVar{Name: "TYPHA_HEALTHHOST", Value: "0.0.0.0"},
			corev1.EnvVar{Name: "TYPHA_SERVERCERTFILE", Value: "/typha-certs-noncluster-host/tls.crt"},
			corev1.EnvVar{Name: "TYPHA_SERVERKEYFILE", Value: "/typha-certs-noncluster-host/tls.key"},
		))
		Expect(d.Spec.Template.Spec.Containers[0].LivenessProbe.HTTPGet.Host).To(BeEmpty())
		Expect(d.Spec.Template.Spec.Containers[0].ReadinessProbe.HTTPGet.Host).To(BeEmpty())
	})

	It("serves the non-cluster-host Typha with its own keypair", func() {
		ci, managed, err := nchExt.Installation().ExtendInputs(nchCtx, nchControllerInputs(nonClusterHost()))
		Expect(err).NotTo(HaveOccurred())

		names := []string{}
		for _, kp := range managed {
			names = append(names, kp.GetName())
		}
		Expect(names).To(ContainElement(render.TyphaTLSSecretNameNonClusterHost))

		d := nchDeployment(renderTypha(ci))
		Expect(d.Spec.Template.Spec.Volumes).To(ContainElement(HaveField("Name", render.TyphaTLSSecretNameNonClusterHost)))
		Expect(d.Spec.Template.Spec.Volumes).NotTo(ContainElement(HaveField("Name", render.TyphaTLSSecretName)))
	})

	It("puts the non-cluster-host Typha on the pod network endpoint", func() {
		k8sapi.Endpoint = k8sapi.ServiceEndpoint{Host: "proxy.local", Port: "6444"}
		k8sapi.PodNetworkEndpoint = k8sapi.ServiceEndpoint{Host: "10.96.0.1", Port: "443"}
		defer func() {
			k8sapi.Endpoint = k8sapi.ServiceEndpoint{}
			k8sapi.PodNetworkEndpoint = k8sapi.ServiceEndpoint{}
		}()

		ci, _, err := nchExt.Installation().ExtendInputs(nchCtx, nchControllerInputs(nonClusterHost()))
		Expect(err).NotTo(HaveOccurred())

		Expect(nchDeployment(renderTypha(ci)).Spec.Template.Spec.Containers[0].Env).To(ContainElements(
			corev1.EnvVar{Name: "KUBERNETES_SERVICE_HOST", Value: "10.96.0.1"},
			corev1.EnvVar{Name: "KUBERNETES_SERVICE_PORT", Value: "443"},
		))
	})

	It("renders nothing extra without a NonClusterHost resource", func() {
		ci, _, err := nchExt.Installation().ExtendInputs(nchCtx, nchControllerInputs())
		Expect(err).NotTo(HaveOccurred())

		_, ok := extensions.FindObject[*appsv1.Deployment](renderTypha(ci), nchDeploymentName)
		Expect(ok).To(BeFalse())
	})

	It("renders the non-cluster-host policy with the other component policies", func() {
		ci := nchControllerInputs(nonClusterHost())
		eci, _, err := nchExt.Installation().ExtendInputs(nchCtx, ci)
		Expect(err).NotTo(HaveOccurred())

		comp := kubecontrollers.NewCalicoKubeControllersPolicy(&kubecontrollers.KubeControllersConfiguration{
			Installation:      ci.RenderInputs.Installation,
			ClusterDomain:     ci.RenderInputs.ClusterDomain,
			TrustedBundle:     ci.RenderInputs.TrustedBundle,
			MetricsPort:       9094,
			Namespace:         common.CalicoNamespace,
			BindingNamespaces: []string{common.CalicoNamespace},
		}, nil)
		create, del := comp.Objects()
		stub := extensionstest.KubeControllersPolicyStub{
			StubComponent: extensionstest.StubComponent{Create: create, Delete: del},
		}
		objs, deleted := nchExt.Installation().Modify(stub, eci.RenderInputs).Objects()

		policy, ok := extensions.FindObject[*v3.NetworkPolicy](objs, render.TyphaNonClusterHostNetworkPolicyName)
		Expect(ok).To(BeTrue())
		Expect(policy.Namespace).To(Equal(common.CalicoNamespace))
		Expect(policy.Spec.Ingress).To(HaveLen(1))

		// The policy moved out of the allow-tigera tier, so the old object is deleted.
		Expect(deleted).To(ContainElement(HaveField("GetName()", "allow-tigera.typha-noncluster-host-access")))
	})
})
