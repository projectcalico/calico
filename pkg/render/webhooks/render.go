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

	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/components"
	"github.com/tigera/operator/pkg/render"
	rcomp "github.com/tigera/operator/pkg/render/common/components"
	rmeta "github.com/tigera/operator/pkg/render/common/meta"
	"github.com/tigera/operator/pkg/render/common/networkpolicy"
	"github.com/tigera/operator/pkg/render/common/podaffinity"
	"github.com/tigera/operator/pkg/render/common/secret"
	"github.com/tigera/operator/pkg/render/common/securitycontext"
	"github.com/tigera/operator/pkg/tls/certificatemanagement"
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
	reg := c.cfg.Installation.Registry
	path := c.cfg.Installation.ImagePath
	prefix := c.cfg.Installation.ImagePrefix

	var err error
	c.calicoImage, err = components.GetReference(components.CombinedCalicoImage(c.cfg.Installation), reg, path, prefix, is)
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

	// Create the correct security context for the webhook container. By default, it should run as non-root, but in Enterprise
	// we need to run as root to be able to write audit logs to the host filesystem.
	securtyContext := securitycontext.NewNonRootContext()
	if c.cfg.Installation.Variant.IsEnterprise() {
		securtyContext = securitycontext.NewRootContext(c.cfg.Installation.KubernetesProvider.IsOpenShift())
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
						SecurityContext: securtyContext,
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
							{
								Name:      "audit-logs",
								MountPath: "/var/log/calico/audit",
								ReadOnly:  false,
							},
						},
					}},
					Volumes: []corev1.Volume{
						// The volume for the TLS certs.
						c.cfg.KeyPair.Volume(),

						// Host volume for audit logs to be wrriten.
						{
							Name: "audit-logs",
							VolumeSource: corev1.VolumeSource{
								HostPath: &corev1.HostPathVolumeSource{
									Path: "/var/log/calico/audit",
									Type: ptr.To(corev1.HostPathDirectoryOrCreate),
								},
							},
						},
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

		// Rule 1: Allow traffic from the kube-apiserver using serviceSelector.
		// This covers the common case where the apiserver source IP survives unmodified
		// to the webhook pod and matches the kubernetes Service's endpoints.
		//
		// Rule 2: Deny traffic from any Kubernetes workload endpoint. The selector
		// "has(projectcalico.org/orchestrator)" matches only pods — Calico adds this
		// label to every workload endpoint but not to NetworkSets or host endpoints, so
		// a user-created NetworkSet (which could otherwise be picked up by a bare
		// namespaceSelector: all()) does not short-circuit this deny. Traffic that has
		// been SNAT'd to a node tunnel address (e.g. a hostnet apiserver sending through
		// an IPIP/VXLAN overlay) arrives from the node, not from a workload endpoint,
		// and so falls through to Rule 3. This is what makes the policy work for hostnet
		// apiservers whose traffic arrives at the webhook with a tunnel IP source.
		//
		// Rule 3: Fallback allow for everything else on the webhook port. In practice
		// this covers node-sourced traffic (including the SNAT'd hostnet-apiserver case
		// above) and cluster-external sources routed to the pod.
		//
		// TODO: This three-rule structure exists because Calico's policy model has no
		// native way to say "any node" or "any tunnel IP" as a source. If we add a
		// first-class selector for that (e.g. a built-in label on host endpoints, or a
		// Source match for tunnel-sourced traffic), we could collapse these rules into a
		// single explicit allow from {apiserver service endpoints, cluster nodes} and
		// drop the fallback.
		ingressRules := []v3.Rule{
			{
				Action:   v3.Allow,
				Protocol: &networkpolicy.TCPProtocol,
				Source:   networkpolicy.KubeAPIServerEntityRule,
				Destination: v3.EntityRule{
					Ports: networkpolicy.Ports(uint16(containerPort)),
				},
			},
			{
				Action: v3.Deny,
				Source: v3.EntityRule{
					NamespaceSelector: "all()",
					Selector:          "has(projectcalico.org/orchestrator)",
				},
			},
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

	if c.cfg.Installation.Variant.IsEnterprise() {
		// The /audit handler only exists in Enterprise. Registering this webhook on Calico OSS
		// points the API server at an endpoint that isn't served, filling its log with failed
		// webhook calls, so only add it for Enterprise.
		vwc.Webhooks = append(vwc.Webhooks, admissionregistrationv1.ValidatingWebhook{
			Name: "audit-logging.api.projectcalico.org",
			Rules: []admissionregistrationv1.RuleWithOperations{
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
						Resources:   []string{"*"},
						Scope:       ptr.To(admissionregistrationv1.AllScopes),
					},
				},
			},
			ClientConfig: admissionregistrationv1.WebhookClientConfig{
				Service: &admissionregistrationv1.ServiceReference{
					Namespace: common.CalicoNamespace,
					Name:      WebhooksName,
					Path:      ptr.To("/audit"),
				},
				CABundle: c.cfg.KeyPair.GetCertificatePEM(),
			},
			AdmissionReviewVersions: []string{"v1"},
			SideEffects:             ptr.To(admissionregistrationv1.SideEffectClassNone),
			TimeoutSeconds:          ptr.To(int32(5)),
			FailurePolicy:           ptr.To(admissionregistrationv1.Ignore),
			MatchPolicy:             ptr.To(admissionregistrationv1.Exact),
		})
	}

	// Create a MutatingWebhookConfiguration for Enterprise-only mutating webhooks.
	mwc := &admissionregistrationv1.MutatingWebhookConfiguration{
		ObjectMeta: metav1.ObjectMeta{
			Name: "api.projectcalico.org",
		},
		Webhooks: []admissionregistrationv1.MutatingWebhook{
			{
				// This webhook handles authorization, mutation, and validation for UISettings resources.
				// On Create it sets ownerReferences and user fields; on all operations it performs
				// authorization checks against the parent UISettingsGroup.
				Name: "uisettings.api.projectcalico.org",
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
							Resources:   []string{"uisettings"},
							Scope:       ptr.To(admissionregistrationv1.AllScopes),
						},
					},
				},
				ClientConfig: admissionregistrationv1.WebhookClientConfig{
					Service: &admissionregistrationv1.ServiceReference{
						Namespace: common.CalicoNamespace,
						Name:      WebhooksName,
						Path:      ptr.To("/uisettings"),
					},
					CABundle: c.cfg.KeyPair.GetCertificatePEM(),
				},
				AdmissionReviewVersions: []string{"v1"},
				SideEffects:             ptr.To(admissionregistrationv1.SideEffectClassNone),
				TimeoutSeconds:          ptr.To(int32(10)),
				FailurePolicy:           ptr.To(admissionregistrationv1.Fail),
				MatchPolicy:             ptr.To(admissionregistrationv1.Exact),
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

	if c.cfg.Installation.Variant.IsEnterprise() {
		rules = append(rules,
			rbacv1.PolicyRule{
				// The ManagedCluster cleanup controller watches ManagedCluster objects and clears their
				// installation manifest field after creation.
				APIGroups: []string{"projectcalico.org"},
				Resources: []string{"managedclusters"},
				Verbs:     []string{"list", "watch", "update"},
			},
			rbacv1.PolicyRule{
				// The UISettings webhook needs to GET UISettingsGroups to verify group existence
				// and build owner references when creating UISettings.
				APIGroups: []string{"projectcalico.org"},
				Resources: []string{"uisettingsgroups"},
				Verbs:     []string{"get"},
			},
		)
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
	objs = append(objs, dep, svc, vwc)
	if c.cfg.Installation.Variant.IsEnterprise() {
		objs = append(objs, mwc)
	}
	objs = append(objs, cr, crb)

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
