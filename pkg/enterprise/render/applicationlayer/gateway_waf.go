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

package applicationlayer

import (
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/tigera/operator/pkg/common"
)

const (
	// WAFWebhookServerTLSSecretName is the serving-cert Secret for the in-process
	// WAF admission webhook, issued for the WAFWebhookServiceName DNS name and
	// mounted into calico-kube-controllers.
	WAFWebhookServerTLSSecretName = "calico-kube-controllers-waf-webhook-tls"

	// WAFWebhookServiceName fronts the WAF SecLang validating admission webhook.
	// The webhook is served in-process by the calico-kube-controllers Pod (see
	// tigera/calico-private kube-controllers applicationlayer manager), so this
	// Service selects the kube-controllers Pod rather than a dedicated
	// Deployment. The webhook serving certificate is issued for this Service's
	// DNS name and mounted into kube-controllers (see pkg/render/kubecontrollers).
	WAFWebhookServiceName = "tigera-waf-webhook"

	// WAFWebhookContainerPort is the in-process webhook server port on the
	// calico-kube-controllers Pod (controller-runtime webhook server). Must match
	// the port the kube-controllers applicationlayer manager listens on. Shared
	// with pkg/render/kubecontrollers (container port + NetworkPolicy ingress).
	WAFWebhookContainerPort = int32(9443)

	// wafWebhookPath is the admission path the kube-controllers webhook server
	// registers. Must match WAFWebhookPath in the calico-private applicationlayer
	// manager.
	wafWebhookPath = "/validate-waf"

	// wafWebhookConfigName / wafWebhookName name the ValidatingWebhookConfiguration
	// and its single webhook entry.
	wafWebhookConfigName = "tigera-waf.applicationlayer.projectcalico.org"
	wafWebhookName       = "waf.applicationlayer.projectcalico.org"
)

// WAFAdmissionWebhookComponents returns the objects required to expose the WAF
// SecLang validating admission webhook: a Service fronting the
// calico-kube-controllers Pod and the ValidatingWebhookConfiguration that points
// at it. The webhook itself runs in-process inside calico-kube-controllers — no
// separate Deployment, ServiceAccount, or ClusterRole; it reuses the
// kube-controllers ServiceAccount and ClusterRole (RBAC is rendered in
// pkg/render/kubecontrollers). The caller passes caBundle — the PEM of the CA
// that issued the webhook serving cert (the operator CA), so the apiserver can
// verify the in-process webhook endpoint.
//
// The caller is responsible for invoking this only when the gateway-addons
// license feature is present and the GatewayAPI WAF extension is enabled.
func WAFAdmissionWebhookComponents(caBundle []byte) []client.Object {
	return []client.Object{
		wafWebhookService(),
		wafValidatingWebhookConfiguration(caBundle),
	}
}

// wafWebhookService fronts the in-process webhook on the calico-kube-controllers
// Pod. The selector matches the kube-controllers Pod label (k8s-app), and the
// service port (443) forwards to the in-process webhook container port.
func wafWebhookService() *corev1.Service {
	return &corev1.Service{
		TypeMeta: metav1.TypeMeta{Kind: "Service", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      WAFWebhookServiceName,
			Namespace: common.CalicoNamespace,
			Labels:    map[string]string{"k8s-app": common.KubeControllersDeploymentName},
		},
		Spec: corev1.ServiceSpec{
			Selector: map[string]string{"k8s-app": common.KubeControllersDeploymentName},
			Ports: []corev1.ServicePort{
				{
					Name:       "https",
					Port:       443,
					Protocol:   corev1.ProtocolTCP,
					TargetPort: intstr.FromInt32(WAFWebhookContainerPort),
				},
			},
			Type: corev1.ServiceTypeClusterIP,
		},
	}
}

// wafValidatingWebhookConfiguration rejects unsafe AO-supplied SecLang at
// admission. It intercepts CREATE/UPDATE on WAFPlugin and WAFPolicy (the
// resources that carry AO SecLang) and fails closed: FailurePolicy=Fail so an
// unavailable webhook blocks the (infrequent) WAF resource writes rather than
// admitting unvalidated directives. The in-cluster reconciler backstop is
// status-only, so the webhook is the hard admission gate.
func wafValidatingWebhookConfiguration(caBundle []byte) *admissionregistrationv1.ValidatingWebhookConfiguration {
	failPolicy := admissionregistrationv1.Fail
	sideEffects := admissionregistrationv1.SideEffectClassNone
	timeoutSeconds := int32(10)

	return &admissionregistrationv1.ValidatingWebhookConfiguration{
		TypeMeta: metav1.TypeMeta{
			Kind:       "ValidatingWebhookConfiguration",
			APIVersion: "admissionregistration.k8s.io/v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:   wafWebhookConfigName,
			Labels: map[string]string{"k8s-app": common.KubeControllersDeploymentName},
		},
		Webhooks: []admissionregistrationv1.ValidatingWebhook{
			{
				Name: wafWebhookName,
				Rules: []admissionregistrationv1.RuleWithOperations{
					{
						Operations: []admissionregistrationv1.OperationType{
							admissionregistrationv1.Create,
							admissionregistrationv1.Update,
						},
						Rule: admissionregistrationv1.Rule{
							APIGroups:   []string{"applicationlayer.projectcalico.org"},
							APIVersions: []string{"v3"},
							Resources:   []string{"wafplugins", "wafpolicies"},
							Scope:       ptr.To(admissionregistrationv1.NamespacedScope),
						},
					},
				},
				ClientConfig: admissionregistrationv1.WebhookClientConfig{
					Service: &admissionregistrationv1.ServiceReference{
						Namespace: common.CalicoNamespace,
						Name:      WAFWebhookServiceName,
						Path:      ptr.To(wafWebhookPath),
					},
					CABundle: caBundle,
				},
				AdmissionReviewVersions: []string{"v1"},
				SideEffects:             &sideEffects,
				TimeoutSeconds:          &timeoutSeconds,
				FailurePolicy:           &failPolicy,
			},
		},
	}
}
