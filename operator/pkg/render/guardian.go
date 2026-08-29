// Copyright (c) 2020-2026 Tigera, Inc. All rights reserved.

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
package render

import (
	"fmt"

	"golang.org/x/net/http/httpproxy"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	netv1 "k8s.io/api/networking/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"sigs.k8s.io/controller-runtime/pkg/client"

	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"

	operatorv1 "github.com/projectcalico/calico/operator/api/v1"
	"github.com/projectcalico/calico/operator/pkg/common"
	"github.com/projectcalico/calico/operator/pkg/components"
	rcomponents "github.com/projectcalico/calico/operator/pkg/render/common/components"
	rmeta "github.com/projectcalico/calico/operator/pkg/render/common/meta"
	"github.com/projectcalico/calico/operator/pkg/render/common/networkpolicy"
	"github.com/projectcalico/calico/operator/pkg/render/common/secret"
	"github.com/projectcalico/calico/operator/pkg/render/common/securitycontext"
	"github.com/projectcalico/calico/operator/pkg/tls/certificatemanagement"
)

// The names of the components related to the Guardian related rendered objects.
const (
	GuardianName                   = "guardian"
	GuardianNamespace              = common.CalicoNamespace
	GuardianServiceAccountName     = GuardianName
	GuardianClusterRoleName        = "calico-guardian"
	GuardianClusterRoleBindingName = "calico-guardian"
	GuardianDeploymentName         = GuardianName

	// GuardianContainerName name is the name of the container running guardian. It's named `tigera-guardian`, instead
	// of `guardian` so that the API for the container overrides don't have to change (`tigera-guardian` is a legacy name).
	GuardianContainerName = "tigera-guardian"
	GuardianServiceName   = "guardian"
	GuardianVolumeName    = "guardian-certs"
	GuardianSecretName    = "tigera-managed-cluster-connection"
	GuardianTargetPort    = 8080
	GuardianPolicyName    = networkpolicy.CalicoComponentPolicyPrefix + "guardian-access"
	GuardianKeyPairSecret = "guardian-key-pair"

	GoldmaneDeploymentName         = "goldmane"
	GuardianSecretsRole            = "calico-guardian-secrets"
	GuardianSecretsRoleBindingName = "calico-guardian-secrets"
)

var (
	GuardianEntityRule                = networkpolicy.CreateEntityRule(GuardianNamespace, GuardianDeploymentName, GuardianTargetPort)
	GuardianSourceEntityRule          = networkpolicy.CreateSourceEntityRule(GuardianNamespace, GuardianDeploymentName)
	GuardianServiceSelectorEntityRule = networkpolicy.CreateServiceSelectorEntityRule(GuardianNamespace, GuardianName)
)

func Guardian(cfg *GuardianConfiguration) Component {
	return &guardianComponent{
		cfg: cfg,
	}
}

// GuardianPolicy renders the OSS guardian network policy. A variant may replace it
// with its own. The error return is always nil, and is kept for callers.
func GuardianPolicy(cfg *GuardianConfiguration) (Component, error) {
	return &guardianPolicyComponent{cfg: cfg}, nil
}

type guardianPolicyComponent struct {
	cfg *GuardianConfiguration
}

func (c *guardianPolicyComponent) ResolveImages(*operatorv1.ImageSet) error { return nil }
func (c *guardianPolicyComponent) SupportedOSType() rmeta.OSType            { return rmeta.OSTypeAny }
func (c *guardianPolicyComponent) Ready() bool                              { return true }
func (c *guardianPolicyComponent) GuardianPolicyConfig() *GuardianConfiguration {
	return c.cfg
}

func (c *guardianPolicyComponent) Objects() ([]client.Object, []client.Object) {
	return []client.Object{ossNetworkPolicy(c.cfg)}, []client.Object{
		// allow-tigera Tier was renamed to calico-system
		networkpolicy.DeprecatedAllowTigeraNetworkPolicyObject("guardian-access", GuardianNamespace),
		networkpolicy.DeprecatedAllowTigeraNetworkPolicyObject("default-deny", GuardianNamespace),
	}
}

// GuardianConfiguration contains all the config information needed to render the component.
type GuardianConfiguration struct {
	URL                         string
	ClusterDomain               string
	PullSecrets                 []*corev1.Secret
	OpenShift                   bool
	Installation                *operatorv1.InstallationSpec
	TunnelSecret                *corev1.Secret
	TrustedCertBundle           certificatemanagement.TrustedBundleRO
	TunnelCAType                operatorv1.CAType
	ManagementClusterConnection *operatorv1.ManagementClusterConnection
	IncludeEgressNetworkPolicy  bool

	// PodProxies represents the resolved proxy configuration for each Guardian pod.
	// If this slice is empty, then resolution has not yet occurred. Pods with no proxy
	// configured are represented with a nil value.
	PodProxies []*httpproxy.Config

	GuardianClientKeyPair certificatemanagement.KeyPairInterface

	// Version stores the version of the cluster, as reported by the ClusterInformation object. It is used to restart
	// guardian when the version changes, which triggers the management cluster to re-check for version skew.
	Version string
}

// GuardianRenderData is the variant-specific Guardian input a controller extension
// computes during reconcile and stashes in Inputs.Extension. The
// clusterconnection controller reads it back to fill GuardianConfiguration without
// depending on the extension: when present it carries the enterprise values
// (the management-cluster version and the license-gated egress policy flag) and
// signals that the controller should not create the OSS Guardian client keypair.
// It lives in render so the controller can read it generically.
type GuardianRenderData struct {
	// Version is the managed cluster version reported by ClusterInformation
	// (CNXVersion for Enterprise, CalicoVersion for the OSS default).
	Version string

	// IncludeEgressNetworkPolicy enables the domain-based egress rules in the
	// Guardian policy, gated on an Enterprise license feature.
	IncludeEgressNetworkPolicy bool
}

// GuardianRenderDataFromInputs returns the GuardianRenderData a controller
// extension stashed in the render inputs, and whether it was present. Absent
// means the OSS path: the controller applies its own defaults.
func GuardianRenderDataFromInputs(ri Inputs) (GuardianRenderData, bool) {
	data, ok := ri.Extension.(GuardianRenderData)
	return data, ok
}

type guardianComponent struct {
	cfg         *GuardianConfiguration
	calicoImage string
}

func (c *guardianComponent) ResolveImages(is *operatorv1.ImageSet) error {
	var err error
	c.calicoImage, err = components.ReferenceFor(components.ImageKeyCalico, c.cfg.Installation, is)
	return err
}

func (c *guardianComponent) GuardianConfig() *GuardianConfiguration {
	return c.cfg
}

func (c *guardianComponent) SupportedOSType() rmeta.OSType {
	return rmeta.OSTypeLinux
}

func (c *guardianComponent) Objects() ([]client.Object, []client.Object) {
	objs := []client.Object{
		c.serviceAccount(),
		c.clusterRole(),
		c.clusterRoleBinding(),
		c.deployment(),
		c.service(),
		secret.CopyToNamespace(GuardianNamespace, c.cfg.TunnelSecret)[0],
	}

	return objs, deprecatedObjects()
}

func (c *guardianComponent) Ready() bool {
	return true
}

func (c *guardianComponent) service() *corev1.Service {
	ports := []corev1.ServicePort{
		{
			Name: "https",
			Port: 443,
			TargetPort: intstr.IntOrString{
				Type:   intstr.Int,
				IntVal: 8080,
			},
			Protocol: corev1.ProtocolTCP,
		},
	}

	return &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      GuardianServiceName,
			Namespace: GuardianNamespace,
		},
		Spec: corev1.ServiceSpec{
			Selector: map[string]string{
				"k8s-app": GuardianName,
			},
			Ports: ports,
		},
	}
}

func (c *guardianComponent) serviceAccount() *corev1.ServiceAccount {
	return &corev1.ServiceAccount{
		TypeMeta:   metav1.TypeMeta{Kind: "ServiceAccount", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{Name: GuardianServiceAccountName, Namespace: GuardianNamespace},
	}
}

func (c *guardianComponent) clusterRole() *rbacv1.ClusterRole {
	policyRules := []rbacv1.PolicyRule{
		{
			APIGroups: []string{""},
			Resources: []string{"namespaces", "services", "pods"},
			Verbs:     []string{"get", "list", "watch"},
		},
		{
			APIGroups: []string{"apps"},
			Resources: []string{"deployments", "replicasets", "statefulsets", "daemonsets"},
			Verbs:     []string{"get", "list", "watch"},
		},
		{
			APIGroups: []string{"networking.k8s.io"},
			Resources: []string{"networkpolicies"},
			Verbs:     []string{"get", "list", "watch"},
		},
		{
			APIGroups: []string{"projectcalico.org"},
			Resources: []string{
				"clusterinformations",
				"tiers",
				"stagednetworkpolicies",
				"tier.stagednetworkpolicies",
				"stagedglobalnetworkpolicies",
				"tier.stagedglobalnetworkpolicies",
				"stagedkubernetesnetworkpolicies",
				"tier.stagedkubernetesnetworkpolicies",
				"networkpolicies",
				"tier.networkpolicies",
				"globalnetworkpolicies",
				"tier.globalnetworkpolicies",
				"globalnetworksets",
				"networksets",
			},
			Verbs: []string{"get", "list", "watch"},
		},
	}

	return &rbacv1.ClusterRole{
		TypeMeta: metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name: GuardianClusterRoleName,
		},
		Rules: policyRules,
	}
}

func (c *guardianComponent) clusterRoleBinding() *rbacv1.ClusterRoleBinding {
	return &rbacv1.ClusterRoleBinding{
		TypeMeta: metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name: GuardianClusterRoleBindingName,
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "ClusterRole",
			Name:     GuardianClusterRoleName,
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      "ServiceAccount",
				Name:      GuardianServiceAccountName,
				Namespace: GuardianNamespace,
			},
		},
	}
}

func (c *guardianComponent) deployment() *appsv1.Deployment {
	var replicas int32 = 1

	tolerations := append(c.cfg.Installation.ControlPlaneTolerations, rmeta.TolerateCriticalAddonsAndControlPlane...)
	if c.cfg.Installation.KubernetesProvider.IsGKE() {
		tolerations = append(tolerations, rmeta.TolerateGKEARM64NoSchedule)
	}

	d := &appsv1.Deployment{
		TypeMeta: metav1.TypeMeta{Kind: "Deployment", APIVersion: "apps/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      GuardianDeploymentName,
			Namespace: GuardianNamespace,
		},
		Spec: appsv1.DeploymentSpec{
			Replicas: &replicas,
			Strategy: appsv1.DeploymentStrategy{
				Type: appsv1.RecreateDeploymentStrategyType,
			},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Name:        GuardianDeploymentName,
					Namespace:   GuardianNamespace,
					Annotations: c.annotations(),
				},
				Spec: corev1.PodSpec{
					NodeSelector:       c.cfg.Installation.ControlPlaneNodeSelector,
					ServiceAccountName: GuardianServiceAccountName,
					Tolerations:        tolerations,
					ImagePullSecrets:   secret.GetReferenceList(c.cfg.PullSecrets),
					Containers:         c.container(),
					Volumes:            c.volumes(),
				},
			},
		},
	}

	if c.cfg.ManagementClusterConnection != nil {
		if overrides := c.cfg.ManagementClusterConnection.Spec.GuardianDeployment; overrides != nil {
			rcomponents.ApplyDeploymentOverrides(d, overrides)
		}
	}
	return d
}

func (c *guardianComponent) volumes() []corev1.Volume {
	volumes := []corev1.Volume{
		c.cfg.TrustedCertBundle.Volume(),
		{
			Name: GuardianVolumeName,
			VolumeSource: corev1.VolumeSource{
				Secret: &corev1.SecretVolumeSource{
					SecretName: GuardianSecretName,
				},
			},
		},
	}
	if c.cfg.GuardianClientKeyPair != nil {
		volumes = append(volumes, c.cfg.GuardianClientKeyPair.Volume())
	}
	return volumes
}

func (c *guardianComponent) container() []corev1.Container {
	envVars := []corev1.EnvVar{
		{Name: "GUARDIAN_PORT", Value: "9443"},
		{Name: "GUARDIAN_LOGLEVEL", Value: "INFO"},
		{Name: "GUARDIAN_VOLTRON_URL", Value: c.cfg.URL},
		{Name: "GUARDIAN_VOLTRON_CA_TYPE", Value: string(c.cfg.TunnelCAType)},
		{Name: "GUARDIAN_CA_FILE", Value: "/etc/pki/tls/certs/tigera-ca-bundle.crt"},
	}
	envVars = append(envVars, c.cfg.Installation.Proxy.EnvVars()...)

	if c.cfg.GuardianClientKeyPair != nil {
		envVars = append(envVars,
			corev1.EnvVar{
				Name:  "GUARDIAN_GOLDMANE_ENDPOINT",
				Value: "https://goldmane.calico-system.svc.cluster.local:7443",
			},
			corev1.EnvVar{
				Name:  "GUARDIAN_GOLDMANE_CLIENT_CERT",
				Value: c.cfg.GuardianClientKeyPair.VolumeMountCertificateFilePath(),
			},
			corev1.EnvVar{
				Name:  "GUARDIAN_GOLDMANE_CLIENT_KEY",
				Value: c.cfg.GuardianClientKeyPair.VolumeMountKeyFilePath(),
			},
		)
	}

	return []corev1.Container{
		{
			Name:         GuardianContainerName,
			Image:        c.calicoImage,
			Command:      []string{components.CalicoBinaryPath, "component", "guardian"},
			Env:          envVars,
			VolumeMounts: c.volumeMounts(),
			LivenessProbe: &corev1.Probe{
				ProbeHandler: corev1.ProbeHandler{
					HTTPGet: &corev1.HTTPGetAction{
						Path: "/liveness",
						Port: intstr.FromInt(9080),
					},
				},
				InitialDelaySeconds: 90,
			},
			ReadinessProbe: &corev1.Probe{
				ProbeHandler: corev1.ProbeHandler{
					HTTPGet: &corev1.HTTPGetAction{
						Path: "/readiness",
						Port: intstr.FromInt(9080),
					},
				},
				InitialDelaySeconds: 10,
			},
			SecurityContext: securitycontext.NewNonRootContext(),
		},
	}
}

func (c *guardianComponent) volumeMounts() []corev1.VolumeMount {
	volumeMounts := append(
		c.cfg.TrustedCertBundle.VolumeMounts(c.SupportedOSType()),
		corev1.VolumeMount{Name: GuardianVolumeName, MountPath: "/certs/", ReadOnly: true},
	)
	if c.cfg.GuardianClientKeyPair != nil {
		volumeMounts = append(volumeMounts, c.cfg.GuardianClientKeyPair.VolumeMount(c.SupportedOSType()))
	}
	return volumeMounts
}

func (c *guardianComponent) annotations() map[string]string {
	annotations := c.cfg.TrustedCertBundle.HashAnnotations()
	annotations["hash.operator.tigera.io/tigera-managed-cluster-connection"] = rmeta.AnnotationHash(c.cfg.TunnelSecret.Data)

	if len(c.cfg.Version) != 0 {
		annotations["hash.operator.tigera.io/version"] = c.cfg.Version
	}
	return annotations
}

func ossNetworkPolicy(cfg *GuardianConfiguration) *v3.NetworkPolicy {
	egressRules := networkpolicy.AppendDNSEgressRules([]v3.Rule{}, cfg.OpenShift)

	// Allow egress to the Kubernetes API server.
	egressRules = append(egressRules, v3.Rule{
		Action:      v3.Allow,
		Protocol:    &networkpolicy.TCPProtocol,
		Destination: networkpolicy.KubeAPIServerEntityRule,
	})

	// Guardian's tunnel destination is the management cluster, whose address is
	// environment-specific and often a hostname. OSS policy can't express a
	// domain-based egress rule, so Pass and let the cluster's default posture
	// govern the tunnel (and the management cluster's queries back to Goldmane).
	egressRules = append(egressRules, v3.Rule{Action: v3.Pass})

	return &v3.NetworkPolicy{
		TypeMeta:   metav1.TypeMeta{Kind: "NetworkPolicy", APIVersion: "projectcalico.org/v3"},
		ObjectMeta: metav1.ObjectMeta{Name: GuardianPolicyName, Namespace: GuardianNamespace},
		Spec: v3.NetworkPolicySpec{
			Order:    &networkpolicy.HighPrecedenceOrder,
			Tier:     networkpolicy.CalicoTierName,
			Selector: networkpolicy.KubernetesAppSelector(GuardianName),
			Types:    []v3.PolicyType{v3.PolicyTypeIngress, v3.PolicyTypeEgress},
			Ingress: []v3.Rule{
				{
					Action:   v3.Allow,
					Protocol: &networkpolicy.TCPProtocol,
					Source: v3.EntityRule{
						Selector: networkpolicy.KubernetesAppSelector(GoldmaneDeploymentName),
					},
					Destination: v3.EntityRule{
						Ports: networkpolicy.Ports(GuardianTargetPort),
					},
				},
			},
			Egress: egressRules,
		},
	}
}

func ProcessPodProxies(podProxies []*httpproxy.Config) []*httpproxy.Config {
	// If pod proxies are empty, then pod proxy resolution has not yet occurred.
	// Assume that a single Guardian pod is running without a proxy.
	if len(podProxies) == 0 {
		return []*httpproxy.Config{nil}
	}

	return podProxies
}

func GuardianService(clusterDomain string) string {
	return fmt.Sprintf("https://%s.%s.svc.%s:%d", GuardianServiceName, GuardianNamespace, clusterDomain, 443)
}

func deprecatedObjects() []client.Object {
	return []client.Object{
		// All the Guardian objects were moved to "calico-system" circa Calico v3.30, and so the legacy tigera-guardian
		// Namespace and everything within it should be removed.
		&corev1.Namespace{
			TypeMeta:   metav1.TypeMeta{Kind: "Namespace", APIVersion: "v1"},
			ObjectMeta: metav1.ObjectMeta{Name: "tigera-guardian"},
		},
		// All the Guardian objects were moved to "calico-system" circa Calico v3.30, and so the legacy `tigera-`
		// prefix is replaced with `calico-` for consistency, which means removing the old global resources.
		&rbacv1.ClusterRole{
			TypeMeta:   metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"},
			ObjectMeta: metav1.ObjectMeta{Name: "tigera-guardian"},
		},
		&rbacv1.ClusterRoleBinding{
			TypeMeta:   metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"},
			ObjectMeta: metav1.ObjectMeta{Name: "tigera-guardian"},
		},

		// Remove manager namespace objects since the guardian identity is responsible for handling manager requests
		&corev1.ServiceAccount{
			TypeMeta:   metav1.TypeMeta{Kind: "ServiceAccount", APIVersion: "v1"},
			ObjectMeta: metav1.ObjectMeta{Name: "tigera-manager", Namespace: "tigera-manager"},
		},
		&corev1.Namespace{
			TypeMeta:   metav1.TypeMeta{Kind: "Namespace", APIVersion: "v1"},
			ObjectMeta: metav1.ObjectMeta{Name: "tigera-manager"},
		},
		&rbacv1.ClusterRole{
			TypeMeta:   metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"},
			ObjectMeta: metav1.ObjectMeta{Name: "tigera-manager-role"},
		},
		&rbacv1.ClusterRoleBinding{
			TypeMeta:   metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"},
			ObjectMeta: metav1.ObjectMeta{Name: "tigera-manager-binding"},
		},

		// Clean up deprecated k8s NetworkPolicy
		&netv1.NetworkPolicy{
			TypeMeta:   metav1.TypeMeta{Kind: "NetworkPolicy", APIVersion: "networking.k8s.io/v1"},
			ObjectMeta: metav1.ObjectMeta{Name: "guardian", Namespace: GuardianNamespace},
		},
	}
}
