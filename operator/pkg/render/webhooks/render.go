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

package webhooks

import (
	"fmt"

	"sigs.k8s.io/controller-runtime/pkg/client"

	operatorv1 "github.com/projectcalico/calico/operator/api/v1"
	"github.com/projectcalico/calico/operator/pkg/common"
	"github.com/projectcalico/calico/operator/pkg/components"
	"github.com/projectcalico/calico/operator/pkg/render"
	rcomp "github.com/projectcalico/calico/operator/pkg/render/common/components"
	rmeta "github.com/projectcalico/calico/operator/pkg/render/common/meta"
	"github.com/projectcalico/calico/operator/pkg/render/common/networkpolicy"
	"github.com/projectcalico/calico/operator/pkg/render/common/podaffinity"
	"github.com/projectcalico/calico/operator/pkg/render/common/secret"
	"github.com/projectcalico/calico/operator/pkg/render/common/securitycontext"
	"github.com/projectcalico/calico/operator/pkg/tls/certificatemanagement"
	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/utils/ptr"
)

const (
	WebhooksTLSSecretName = "calico-webhooks-tls"

	WebhooksName            = "calico-webhooks"
	WebhooksSecretsRBACName = "calico-webhooks-secrets-access"

	webhooksContainerPort int32 = 6443
)

var WebhooksPolicyName = fmt.Sprintf("%s.%s", networkpolicy.CalicoTierName, WebhooksName)

// Configuration is the public API used to provide information to the render code to
// generate Kubernetes objects for installing calico/webhooks on a cluster.
type Configuration struct {
	PullSecrets  []*corev1.Secret
	KeyPair      certificatemanagement.KeyPairInterface
	Installation *operatorv1.InstallationSpec
	APIServer    *operatorv1.APIServerSpec
	OpenShift    bool
}

// WebhooksComponent is the webhooks component paired with the configuration it rendered
// from, so extensions can layer variant-specific objects onto it.
type WebhooksComponent interface {
	render.Component
	WebhooksConfig() *Configuration
}

func Component(cfg *Configuration) render.Component {
	return &component{cfg: cfg}
}

type component struct {
	// Input configuration from the controller.
	cfg *Configuration

	// Images.
	calicoImage string
}

func (c *component) WebhooksConfig() *Configuration {
	return c.cfg
}

func (c *component) ResolveImages(is *operatorv1.ImageSet) error {

	var err error
	c.calicoImage, err = components.ReferenceFor(components.ImageKeyCalico, c.cfg.Installation, is)
	return err
}

func (c *component) SupportedOSType() rmeta.OSType {
	return rmeta.OSTypeLinux
}

func (c *component) Objects() ([]client.Object, []client.Object) {
	// Create the ServiceAccount for the webhook.
	sa := &corev1.ServiceAccount{
		TypeMeta: metav1.TypeMeta{Kind: "ServiceAccount", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      WebhooksName,
			Namespace: common.CalicoNamespace,
		},
	}

	// Create the Deployment for the webhook with defaults, then apply overrides.
	dep := &appsv1.Deployment{
		TypeMeta: metav1.TypeMeta{Kind: "Deployment", APIVersion: "apps/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      WebhooksName,
			Namespace: common.CalicoNamespace,
		},
		Spec: appsv1.DeploymentSpec{
			Replicas: c.cfg.Installation.ControlPlaneReplicas,
			Strategy: appsv1.DeploymentStrategy{
				// Use RollingUpdate to avoid downtime during rollouts. Since this is a webhook with
				// FailurePolicy=Fail, using Recreate would cause a window where no webhook pod is running,
				// blocking all matching API requests.
				Type: appsv1.RollingUpdateDeploymentStrategyType,
				RollingUpdate: &appsv1.RollingUpdateDeployment{
					MaxSurge:       ptr.To(intstr.FromInt(1)),
					MaxUnavailable: ptr.To(intstr.FromInt(0)),
				},
			},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Name: WebhooksName,
				},
				Spec: corev1.PodSpec{
					HostNetwork:        render.HostNetworkRequired(c.cfg.Installation),
					ServiceAccountName: WebhooksName,
					Tolerations:        c.tolerations(),
					ImagePullSecrets:   secret.GetReferenceList(c.cfg.PullSecrets),
					Containers: []corev1.Container{{
						Name:            WebhooksName,
						Image:           c.calicoImage,
						Command:         []string{components.CalicoBinaryPath, "component", "webhooks"},
						SecurityContext: securitycontext.NewNonRootContext(),
						Args: []string{
							"webhook",
							fmt.Sprintf("--tls-cert-file=%s", c.cfg.KeyPair.VolumeMountCertificateFilePath()),
							fmt.Sprintf("--tls-private-key-file=%s", c.cfg.KeyPair.VolumeMountKeyFilePath()),
						},
						Ports: []corev1.ContainerPort{{
							ContainerPort: webhooksContainerPort,
							Protocol:      corev1.ProtocolTCP,
						}},

						// Keep the pod out of the Service endpoints until the TLS listener is up, so a
						// rollout doesn't reject policy writes against the FailurePolicy=Fail webhook.
						ReadinessProbe: &corev1.Probe{
							ProbeHandler: corev1.ProbeHandler{
								HTTPGet: &corev1.HTTPGetAction{
									Path:   "/readyz",
									Port:   intstr.FromInt32(webhooksContainerPort),
									Scheme: corev1.URISchemeHTTPS,
								},
							},
							PeriodSeconds:  10,
							TimeoutSeconds: 5,
						},
						VolumeMounts: []corev1.VolumeMount{
							c.cfg.KeyPair.VolumeMount(c.SupportedOSType()),
						},
					}},
					Volumes: []corev1.Volume{
						c.cfg.KeyPair.Volume(),
					},
				},
			},
		},
	}

	if c.cfg.Installation.ControlPlaneReplicas != nil && *c.cfg.Installation.ControlPlaneReplicas > 1 {
		dep.Spec.Template.Spec.Affinity = podaffinity.NewPodAntiAffinity(WebhooksName, []string{common.CalicoNamespace})
	}

	if overrides := c.cfg.APIServer.CalicoWebhooksDeployment; overrides != nil {
		rcomp.ApplyDeploymentOverrides(dep, overrides)
	}

	// Set DNSPolicy based on the final HostNetwork value (after overrides).
	if dep.Spec.Template.Spec.HostNetwork {
		dep.Spec.Template.Spec.DNSPolicy = corev1.DNSClusterFirstWithHostNet
	}

	// Read the final container port from the deployment (after overrides) for use in the Service.
	containerPort := dep.Spec.Template.Spec.Containers[0].Ports[0].ContainerPort
	dep.Spec.Template.Spec.Containers[0].ReadinessProbe.HTTPGet.Port = intstr.FromInt32(containerPort)

	// The binary picks its own listen port, so pass the final value rather than let it default.
	dep.Spec.Template.Spec.Containers[0].Args = append(
		dep.Spec.Template.Spec.Containers[0].Args,
		fmt.Sprintf("--port=%d", containerPort),
	)

	// Network policy to allow traffic to/from the webhook pod. Skip if host networking is
	// enabled, since network policy is ineffective for host-networked pods.
	var np *v3.NetworkPolicy
	if !dep.Spec.Template.Spec.HostNetwork {
		egressRules := networkpolicy.AppendDNSEgressRules(nil, c.cfg.OpenShift)
		egressRules = append(egressRules,
			v3.Rule{
				Action:      v3.Allow,
				Protocol:    &networkpolicy.TCPProtocol,
				Destination: networkpolicy.KubeAPIServerEntityRule,
			},
			v3.Rule{
				Action: v3.Pass,
			},
		)

		// TODO: Calico policy can't match "any node" or "any tunnel IP" as a source. Such
		// a selector would let us allow nodes explicitly and drop the fallback allow.
		ingressRules := []v3.Rule{
			// The apiserver source IP usually survives unmodified to the webhook pod, where it
			// matches the endpoints of the default/kubernetes Service.
			{
				Action:   v3.Allow,
				Protocol: &networkpolicy.TCPProtocol,
				Source:   networkpolicy.KubeAPIServerEntityRule,
				Destination: v3.EntityRule{
					Ports: networkpolicy.Ports(uint16(containerPort)),
				},
			},
			// AKS and GKE route the apiserver through konnectivity agents, so the admission call
			// arrives with a pod source IP and would otherwise hit the deny below.
			{
				Action:   v3.Allow,
				Protocol: &networkpolicy.TCPProtocol,
				Source:   networkpolicy.KonnectivityAgentEntityRule,
				Destination: v3.EntityRule{
					Ports: networkpolicy.Ports(uint16(containerPort)),
				},
			},
			// Only workload endpoints carry projectcalico.org/orchestrator, so a user-created
			// NetworkSet can't match this deny. Traffic SNAT'd to a node tunnel address comes
			// from the node, not a pod, and falls through.
			{
				Action: v3.Deny,
				Source: v3.EntityRule{
					NamespaceSelector: "all()",
					Selector:          "has(projectcalico.org/orchestrator)",
				},
			},
			// Catches node-sourced traffic, including a hostnet apiserver SNAT'd through an IPIP
			// or VXLAN overlay, plus cluster-external sources routed to the pod.
			{
				Action:   v3.Allow,
				Protocol: &networkpolicy.TCPProtocol,
				Destination: v3.EntityRule{
					Ports: networkpolicy.Ports(uint16(containerPort)),
				},
			},
		}

		np = &v3.NetworkPolicy{
			TypeMeta: metav1.TypeMeta{Kind: "NetworkPolicy", APIVersion: "projectcalico.org/v3"},
			ObjectMeta: metav1.ObjectMeta{
				Name:      WebhooksPolicyName,
				Namespace: common.CalicoNamespace,
			},
			Spec: v3.NetworkPolicySpec{
				Order:    &networkpolicy.HighPrecedenceOrder,
				Tier:     networkpolicy.CalicoTierName,
				Selector: networkpolicy.KubernetesAppSelector(WebhooksName),
				Types:    []v3.PolicyType{v3.PolicyTypeIngress, v3.PolicyTypeEgress},
				Ingress:  ingressRules,
				Egress:   egressRules,
			},
		}
	}

	// Create the Service for the webhook.
	svc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      WebhooksName,
			Namespace: common.CalicoNamespace,
		},
		Spec: corev1.ServiceSpec{
			Selector: map[string]string{"k8s-app": WebhooksName},
			Ports: []corev1.ServicePort{
				{
					Port:       443,
					Protocol:   corev1.ProtocolTCP,
					TargetPort: intstr.FromInt32(containerPort),
				},
			},
			Type: corev1.ServiceTypeClusterIP,
		},
	}

	// Create the ValidatingWebhookConfiguration to register the webhook with the API server.
	vwc := &admissionregistrationv1.ValidatingWebhookConfiguration{
		ObjectMeta: metav1.ObjectMeta{
			Name: "api.projectcalico.org",
		},
		Webhooks: []admissionregistrationv1.ValidatingWebhook{
			{
				// This first webhook is for CRUD operations on network policies, to ensure that tier-based RBAC is enforced
				Name: "tiered-rbac.api.projectcalico.org",
				Rules: []admissionregistrationv1.RuleWithOperations{
					{
						Operations: []admissionregistrationv1.OperationType{
							admissionregistrationv1.Create,
							admissionregistrationv1.Update,
							admissionregistrationv1.Delete,
						},
						Rule: admissionregistrationv1.Rule{
							APIGroups:   []string{"projectcalico.org"},
							APIVersions: []string{"v3"},
							Resources: []string{
								"networkpolicies",
								"globalnetworkpolicies",
								"stagednetworkpolicies",
								"stagedglobalnetworkpolicies",
							},
							Scope: ptr.To(admissionregistrationv1.AllScopes),
						},
					},
					{
						Operations: []admissionregistrationv1.OperationType{
							admissionregistrationv1.Create,
							admissionregistrationv1.Update,
							admissionregistrationv1.Delete,
							admissionregistrationv1.Connect,
						},
						Rule: admissionregistrationv1.Rule{
							APIGroups:   []string{"projectcalico.org"},
							APIVersions: []string{"v3"},
							Resources:   []string{"networkpolicies", "globalnetworkpolicies", "stagednetworkpolicies", "stagedglobalnetworkpolicies"},
							Scope:       ptr.To(admissionregistrationv1.AllScopes),
						},
					},
				},
				ClientConfig: admissionregistrationv1.WebhookClientConfig{
					Service: &admissionregistrationv1.ServiceReference{
						Namespace: common.CalicoNamespace,
						Name:      WebhooksName,
						Path:      ptr.To("/rbac"),
					},
					CABundle: c.cfg.KeyPair.GetCertificatePEM(),
				},
				AdmissionReviewVersions: []string{"v1"},
				SideEffects:             ptr.To(admissionregistrationv1.SideEffectClassNone),
				TimeoutSeconds:          ptr.To(int32(5)),
				FailurePolicy:           ptr.To(admissionregistrationv1.Fail),
			},
			{
				// This webhook blocks user writes to ClusterInformation, which is a read-only resource managed by
				// Calico system components. This mirrors the write protection provided by the aggregated API server.
				Name: "cluster-info.api.projectcalico.org",
				Rules: []admissionregistrationv1.RuleWithOperations{
					{
						Operations: []admissionregistrationv1.OperationType{
							admissionregistrationv1.Create,
							admissionregistrationv1.Update,
							admissionregistrationv1.Delete,
						},
						Rule: admissionregistrationv1.Rule{
							APIGroups:   []string{"projectcalico.org"},
							APIVersions: []string{"v3"},
							Resources:   []string{"clusterinformations"},
							Scope:       ptr.To(admissionregistrationv1.AllScopes),
						},
					},
				},
				ClientConfig: admissionregistrationv1.WebhookClientConfig{
					Service: &admissionregistrationv1.ServiceReference{
						Namespace: common.CalicoNamespace,
						Name:      WebhooksName,
						Path:      ptr.To("/cluster-info"),
					},
					CABundle: c.cfg.KeyPair.GetCertificatePEM(),
				},
				AdmissionReviewVersions: []string{"v1"},
				SideEffects:             ptr.To(admissionregistrationv1.SideEffectClassNone),
				TimeoutSeconds:          ptr.To(int32(5)),
				FailurePolicy:           ptr.To(admissionregistrationv1.Ignore),
			},
		},
	}

	// Create a ClusterRole and ClusterRoleBinding for the webhook service account.
	rules := []rbacv1.PolicyRule{
		{
			// The webhook needs to be able to create SubjectAccessReviews in order to perform authorization checks for API requests.
			APIGroups: []string{"authorization.k8s.io"},
			Resources: []string{"subjectaccessreviews"},
			Verbs:     []string{"create"},
		},
		{
			// The webhook needs to GET tiers to verify tier existence when validating tiered policies.
			APIGroups: []string{"projectcalico.org"},
			Resources: []string{"tiers"},
			Verbs:     []string{"get"},
		},
	}

	cr := &rbacv1.ClusterRole{
		TypeMeta: metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name: WebhooksName,
		},
		Rules: rules,
	}

	crb := &rbacv1.ClusterRoleBinding{
		TypeMeta: metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name: WebhooksName,
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "ClusterRole",
			Name:     WebhooksName,
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      "ServiceAccount",
				Name:      WebhooksName,
				Namespace: common.CalicoNamespace,
			},
		},
	}

	objs := []client.Object{sa}
	if np != nil {
		objs = append(objs, np)
	}
	objs = append(objs, dep, svc, vwc, cr, crb)

	return objs, nil
}

func (c *component) Ready() bool {
	return true
}

// tolerations creates the tolerations used by the webhooks deployment.
func (c *component) tolerations() []corev1.Toleration {
	if render.HostNetworkRequired(c.cfg.Installation) {
		return rmeta.TolerateBootstrap
	}
	tolerations := append(c.cfg.Installation.ControlPlaneTolerations, rmeta.TolerateControlPlane...)
	if c.cfg.Installation.KubernetesProvider.IsGKE() {
		tolerations = append(tolerations, rmeta.TolerateGKEARM64NoSchedule)
	}
	return tolerations
}
