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
	"net"
	"net/url"

	"golang.org/x/net/http/httpproxy"

	operatorurl "github.com/tigera/operator/pkg/url"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	netv1 "k8s.io/api/networking/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"sigs.k8s.io/controller-runtime/pkg/client"

	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"

	"github.com/tigera/api/pkg/lib/numorstring"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/components"
	rcomponents "github.com/tigera/operator/pkg/render/common/components"
	rmeta "github.com/tigera/operator/pkg/render/common/meta"
	"github.com/tigera/operator/pkg/render/common/networkpolicy"
	"github.com/tigera/operator/pkg/render/common/secret"
	"github.com/tigera/operator/pkg/render/common/securitycontext"
	"github.com/tigera/operator/pkg/render/common/securitycontextconstraints"
	"github.com/tigera/operator/pkg/tls/certificatemanagement"
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
	return &GuardianComponent{
		cfg: cfg,
	}
}

func GuardianPolicy(cfg *GuardianConfiguration) (Component, error) {
	var policies []client.Object

	guardianAccessPolicy, err := guardianCalicoSystemPolicy(cfg)
	if err != nil {
		return nil, err
	}
	if guardianAccessPolicy != nil {
		policies = []client.Object{
			guardianAccessPolicy,
		}
	}

	return NewPassthrough(
		policies,
		[]client.Object{
			// allow-tigera Tier was renamed to calico-system
			networkpolicy.DeprecatedAllowTigeraNetworkPolicyObject("guardian-access", GuardianNamespace),
			networkpolicy.DeprecatedAllowTigeraNetworkPolicyObject("default-deny", GuardianNamespace),
		},
	), nil
}

// GuardianConfiguration contains all the config information needed to render the component.
type GuardianConfiguration struct {
	URL                         string
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

type GuardianComponent struct {
	cfg         *GuardianConfiguration
	calicoImage string
}

func (c *GuardianComponent) ResolveImages(is *operatorv1.ImageSet) error {
	reg := c.cfg.Installation.Registry
	path := c.cfg.Installation.ImagePath
	prefix := c.cfg.Installation.ImagePrefix
	var err error
	c.calicoImage, err = components.GetReference(components.CombinedCalicoImage(c.cfg.Installation), reg, path, prefix, is)
	return err
}

func (c *GuardianComponent) SupportedOSType() rmeta.OSType {
	return rmeta.OSTypeLinux
}

func (c *GuardianComponent) Objects() ([]client.Object, []client.Object) {
	objs := []client.Object{
		// common RBAC for EE and OSS
		c.serviceAccount(),
		c.clusterRole(),
		c.clusterRoleBinding(),
	}

	if c.cfg.Installation.Variant.IsEnterprise() {
		// Enterprise-specific RBAC and settings
		objs = append(objs,
			c.secretsRole(),
			c.secretRoleBinding(),
			// Install default UI settings for this managed cluster.
			managerClusterWideSettingsGroup(),
			managerUserSpecificSettingsGroup(),
			managerClusterWideTigeraLayer(),
			managerClusterWideDefaultView(),
		)
	}

	objs = append(objs,
		c.deployment(),
		c.service(),
		secret.CopyToNamespace(GuardianNamespace, c.cfg.TunnelSecret)[0],
	)

	return objs, deprecatedObjects()
}

func (c *GuardianComponent) Ready() bool {
	return true
}

func (c *GuardianComponent) service() *corev1.Service {
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

	if c.cfg.Installation.Variant.IsEnterprise() {
		ports = append(ports,
			corev1.ServicePort{
				Name: "elasticsearch",
				Port: 9200,
				TargetPort: intstr.IntOrString{
					Type:   intstr.Int,
					IntVal: 8080,
				},
				Protocol: corev1.ProtocolTCP,
			},
			corev1.ServicePort{
				Name: "kibana",
				Port: 5601,
				TargetPort: intstr.IntOrString{
					Type:   intstr.Int,
					IntVal: 8080,
				},
				Protocol: corev1.ProtocolTCP,
			},
		)
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

func (c *GuardianComponent) serviceAccount() *corev1.ServiceAccount {
	return &corev1.ServiceAccount{
		TypeMeta:   metav1.TypeMeta{Kind: "ServiceAccount", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{Name: GuardianServiceAccountName, Namespace: GuardianNamespace},
	}
}

func (c *GuardianComponent) clusterRole() *rbacv1.ClusterRole {
	var policyRules []rbacv1.PolicyRule
	if c.cfg.Installation.Variant.IsEnterprise() {
		impersonation := c.cfg.ManagementClusterConnection.Spec.Impersonation
		if impersonation != nil {
			if impersonation.Users != nil {
				policyRules = append(policyRules,
					rbacv1.PolicyRule{
						APIGroups:     []string{""},
						Resources:     []string{"users"},
						ResourceNames: impersonation.Users,
						Verbs:         []string{"impersonate"},
					})
			}
			if impersonation.Groups != nil {
				policyRules = append(policyRules,
					rbacv1.PolicyRule{
						APIGroups:     []string{""},
						Resources:     []string{"groups"},
						ResourceNames: impersonation.Groups,
						Verbs:         []string{"impersonate"},
					})
			}
			if impersonation.ServiceAccounts != nil {
				policyRules = append(policyRules,
					rbacv1.PolicyRule{
						APIGroups:     []string{""},
						Resources:     []string{"serviceaccounts"},
						ResourceNames: impersonation.ServiceAccounts,
						Verbs:         []string{"impersonate"},
					})
			}
		}

		policyRules = append(policyRules, rulesForManagementClusterRequests(c.cfg.OpenShift)...)

		if c.cfg.OpenShift {
			policyRules = append(policyRules, rbacv1.PolicyRule{
				APIGroups:     []string{"security.openshift.io"},
				Resources:     []string{"securitycontextconstraints"},
				Verbs:         []string{"use"},
				ResourceNames: []string{securitycontextconstraints.NonRootV2},
			})
		}
	} else {
		policyRules = append(policyRules,
			rbacv1.PolicyRule{
				APIGroups: []string{""},
				Resources: []string{"namespaces", "services", "pods"},
				Verbs:     []string{"get", "list", "watch"},
			},
			rbacv1.PolicyRule{
				APIGroups: []string{"apps"},
				Resources: []string{"deployments", "replicasets", "statefulsets", "daemonsets"},
				Verbs:     []string{"get", "list", "watch"},
			},
			rbacv1.PolicyRule{
				APIGroups: []string{"networking.k8s.io"},
				Resources: []string{"networkpolicies"},
				Verbs:     []string{"get", "list", "watch"},
			},
			rbacv1.PolicyRule{
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
		)
	}

	return &rbacv1.ClusterRole{
		TypeMeta: metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name: GuardianClusterRoleName,
		},
		Rules: policyRules,
	}
}

func (c *GuardianComponent) clusterRoleBinding() *rbacv1.ClusterRoleBinding {
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

// secretRole creates a Role that allows the management cluster to provision secrets to the tigera-operator Namespace.
// This is used to push secrets used by the managed cluster to access / authenticate with the management cluster.
func (c *GuardianComponent) secretsRole() *rbacv1.Role {
	return &rbacv1.Role{
		TypeMeta: metav1.TypeMeta{Kind: "Role", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      GuardianSecretsRole,
			Namespace: common.OperatorNamespace(),
		},
		Rules: []rbacv1.PolicyRule{
			{
				APIGroups: []string{""},
				Resources: []string{"secrets"},
				Verbs:     []string{"create", "delete", "deletecollection", "update"},
			},
		},
	}
}

func (c *GuardianComponent) secretRoleBinding() *rbacv1.RoleBinding {
	return &rbacv1.RoleBinding{
		TypeMeta: metav1.TypeMeta{Kind: "RoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      GuardianSecretsRoleBindingName,
			Namespace: common.OperatorNamespace(),
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "Role",
			Name:     GuardianSecretsRole,
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

func (c *GuardianComponent) deployment() *appsv1.Deployment {
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

func (c *GuardianComponent) volumes() []corev1.Volume {
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

func (c *GuardianComponent) container() []corev1.Container {
	envVars := []corev1.EnvVar{
		{Name: "GUARDIAN_PORT", Value: "9443"},
		{Name: "GUARDIAN_LOGLEVEL", Value: "INFO"},
		{Name: "GUARDIAN_VOLTRON_URL", Value: c.cfg.URL},
		{Name: "GUARDIAN_VOLTRON_CA_TYPE", Value: string(c.cfg.TunnelCAType)},
		{Name: "GUARDIAN_CA_FILE", Value: "/etc/pki/tls/certs/tigera-ca-bundle.crt"},
	}
	envVars = append(envVars, c.cfg.Installation.Proxy.EnvVars()...)

	if c.cfg.Installation.Variant.IsEnterprise() {
		envVars = append(envVars,
			corev1.EnvVar{Name: "GUARDIAN_PACKET_CAPTURE_CA_BUNDLE_PATH", Value: c.cfg.TrustedCertBundle.MountPath()},
			corev1.EnvVar{Name: "GUARDIAN_PROMETHEUS_CA_BUNDLE_PATH", Value: c.cfg.TrustedCertBundle.MountPath()},
			corev1.EnvVar{Name: "GUARDIAN_QUERYSERVER_CA_BUNDLE_PATH", Value: c.cfg.TrustedCertBundle.MountPath()},
		)
	}

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

func (c *GuardianComponent) volumeMounts() []corev1.VolumeMount {
	volumeMounts := append(
		c.cfg.TrustedCertBundle.VolumeMounts(c.SupportedOSType()),
		corev1.VolumeMount{Name: GuardianVolumeName, MountPath: "/certs/", ReadOnly: true},
	)
	if c.cfg.GuardianClientKeyPair != nil {
		volumeMounts = append(volumeMounts, c.cfg.GuardianClientKeyPair.VolumeMount(c.SupportedOSType()))
	}
	return volumeMounts
}

func (c *GuardianComponent) annotations() map[string]string {
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

func guardianCalicoSystemPolicy(cfg *GuardianConfiguration) (*v3.NetworkPolicy, error) {
	if !cfg.Installation.Variant.IsEnterprise() {
		return ossNetworkPolicy(cfg), nil
	}

	egressRules := []v3.Rule{
		{
			Action:      v3.Allow,
			Protocol:    &networkpolicy.TCPProtocol,
			Destination: PacketCaptureEntityRule,
		},
	}
	egressRules = networkpolicy.AppendDNSEgressRules(egressRules, cfg.OpenShift)
	egressRules = append(egressRules, []v3.Rule{
		{
			Action:      v3.Allow,
			Protocol:    &networkpolicy.TCPProtocol,
			Destination: networkpolicy.KubeAPIServerEntityRule,
		},
		{
			Action:      v3.Allow,
			Protocol:    &networkpolicy.TCPProtocol,
			Destination: networkpolicy.PrometheusEntityRule,
		},
		{
			Action:      v3.Allow,
			Protocol:    &networkpolicy.TCPProtocol,
			Destination: TigeraAPIServerEntityRule,
		},
	}...)

	// The loop below creates an egress rule for each unique destination that the Guardian pods connect to. If there are
	// multiple guardian pods and their proxy  settings differ, then there are multiple destinations that must have egress allowed.
	allowedDestinations := map[string]bool{}
	processedPodProxies := ProcessPodProxies(cfg.PodProxies)
	for _, podProxyConfig := range processedPodProxies {
		var proxyURL *url.URL
		var err error
		if podProxyConfig != nil && podProxyConfig.HTTPSProxy != "" {
			targetURL := &url.URL{
				// The scheme should be HTTPS, as we are establishing an mTLS session with the target.
				Scheme: "https",

				// We expect `target` to be of the form host:port.
				Host: cfg.URL,
			}

			proxyURL, err = podProxyConfig.ProxyFunc()(targetURL)
			if err != nil {
				return nil, err
			}
		}

		var tunnelDestinationHostPort string
		if proxyURL != nil {
			proxyHostPort, err := operatorurl.ParseHostPortFromHTTPProxyURL(proxyURL)
			if err != nil {
				return nil, err
			}

			tunnelDestinationHostPort = proxyHostPort
		} else {
			// cfg.URL has host:port form
			tunnelDestinationHostPort = cfg.URL
		}

		// Check if we've already created an egress rule for this destination.
		if allowedDestinations[tunnelDestinationHostPort] {
			continue
		}

		host, port, err := net.SplitHostPort(tunnelDestinationHostPort)
		if err != nil {
			return nil, err
		}
		parsedPort, err := numorstring.PortFromString(port)
		if err != nil {
			return nil, err
		}
		parsedIp := net.ParseIP(host)
		if parsedIp == nil {
			// Domain-based egress rules require the EgressAccessControl license feature.
			if !cfg.IncludeEgressNetworkPolicy {
				continue
			}
			// Assume host is a valid hostname.
			egressRules = append(egressRules, v3.Rule{
				Action:   v3.Allow,
				Protocol: &networkpolicy.TCPProtocol,
				Destination: v3.EntityRule{
					Domains: []string{host},
					Ports:   []numorstring.Port{parsedPort},
				},
			})
			allowedDestinations[tunnelDestinationHostPort] = true

		} else {
			var netSuffix string
			if parsedIp.To4() != nil {
				netSuffix = "/32"
			} else {
				netSuffix = "/128"
			}

			egressRules = append(egressRules, v3.Rule{
				Action:   v3.Allow,
				Protocol: &networkpolicy.TCPProtocol,
				Destination: v3.EntityRule{
					Nets:  []string{parsedIp.String() + netSuffix},
					Ports: []numorstring.Port{parsedPort},
				},
			})
			allowedDestinations[tunnelDestinationHostPort] = true
		}
	}

	egressRules = append(egressRules, v3.Rule{Action: v3.Pass})

	guardianIngressDestinationEntityRule := v3.EntityRule{Ports: networkpolicy.Ports(GuardianTargetPort)}
	var ingressRules []v3.Rule
	if cfg.Installation.Variant.IsEnterprise() {
		ingressRules = append(ingressRules, []v3.Rule{
			{
				Action:      v3.Allow,
				Protocol:    &networkpolicy.TCPProtocol,
				Source:      FluentBitSourceEntityRule,
				Destination: guardianIngressDestinationEntityRule,
			},
			{
				Action:      v3.Allow,
				Protocol:    &networkpolicy.TCPProtocol,
				Source:      IntrusionDetectionSourceEntityRule,
				Destination: guardianIngressDestinationEntityRule,
			},
			{
				Action:      v3.Allow,
				Protocol:    &networkpolicy.TCPProtocol,
				Source:      IntrusionDetectionInstallerSourceEntityRule,
				Destination: guardianIngressDestinationEntityRule,
			},
			{
				Action:      v3.Allow,
				Protocol:    &networkpolicy.TCPProtocol,
				Destination: guardianIngressDestinationEntityRule,
			},
		}...)
	}

	policy := &v3.NetworkPolicy{
		TypeMeta: metav1.TypeMeta{Kind: "NetworkPolicy", APIVersion: "projectcalico.org/v3"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      GuardianPolicyName,
			Namespace: GuardianNamespace,
		},
		Spec: v3.NetworkPolicySpec{
			Order:    &networkpolicy.HighPrecedenceOrder,
			Tier:     networkpolicy.CalicoTierName,
			Selector: networkpolicy.KubernetesAppSelector(GuardianName),
			Types:    []v3.PolicyType{v3.PolicyTypeIngress, v3.PolicyTypeEgress},
			Ingress:  ingressRules,
			Egress:   egressRules,
		},
	}

	return policy, nil
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

// rulesForManagementClusterRequests returns the set of RBAC rules needed by Guardian in order to
// satisfy requests from the management cluster over the tunnel.
func rulesForManagementClusterRequests(isOpenShift bool) []rbacv1.PolicyRule {
	rules := []rbacv1.PolicyRule{
		// Common rules required to handle requests from multiple components in the management cluster.
		{
			// ID uses read-only permissions and kube-controllers uses both read and write verbs.
			APIGroups: []string{""},
			Resources: []string{"configmaps"},
			Verbs:     []string{"create", "delete", "get", "list", "update", "watch"},
		},
		{
			// Allows Linseed to watch namespaces before copying its token.
			// Also enables PolicyRecommendation to watch namespaces,
			// and Manager/kube-controllers to list them.
			APIGroups: []string{""},
			Resources: []string{"namespaces"},
			Verbs:     []string{"get", "list", "watch"},
		},
		{
			// kube-controllers watches Nodes to monitor for deletions.
			// Manager performs a list operation on Nodes.
			APIGroups: []string{""},
			Resources: []string{"nodes"},
			Verbs:     []string{"get", "list", "watch"},
		},
		{
			// kube-controllers watches Pods to verify existence for IPAM garbage collection.
			// Manager performs get operations on Pods.
			APIGroups: []string{""},
			Resources: []string{"pods"},
			Verbs:     []string{"get", "list", "watch"},
		},
		{
			// The Federated Services Controller needs access to the remote kubeconfig secret
			// in order to create a remote syncer.
			APIGroups: []string{""},
			Resources: []string{"secrets"},
			Verbs:     []string{"get", "list", "watch"},
		},
		{
			// Manager uses list; kube-controllers uses 'get', 'list', 'watch', 'update'.
			APIGroups: []string{""},
			Resources: []string{"services"},
			Verbs:     []string{"get", "list", "update", "watch"},
		},
		{
			// Needed by kube-controllers to validate licenses; also used by ID.
			APIGroups: []string{"projectcalico.org", "crd.projectcalico.org"},
			Resources: []string{"licensekeys"},
			Verbs:     []string{"get", "watch"},
		},
		{
			// Manager uses list; PolicyRecommendation & ID uses all verbs.
			APIGroups: []string{"projectcalico.org"},
			Resources: []string{
				"globalnetworksets",
				"networkpolicies",
				"tier.networkpolicies",
				"stagednetworkpolicies",
				"tier.stagednetworkpolicies",
			},
			Verbs: []string{"create", "delete", "get", "list", "patch", "update", "watch"},
		},
		{
			// Manager uses list; PolicyRecommendation uses all verbs.
			APIGroups: []string{"projectcalico.org"},
			Resources: []string{"tiers"},
			Verbs:     []string{"create", "delete", "get", "list", "patch", "update", "watch"},
		},
		// Rules needed by guardian to handle manager authorization reviews.
		{
			APIGroups: []string{"rbac.authorization.k8s.io"},
			Resources: []string{"clusterroles", "clusterrolebindings", "roles", "rolebindings"},
			Verbs:     []string{"list", "get"},
		},
		{
			APIGroups: []string{"projectcalico.org"},
			Resources: []string{"uisettings", "uisettingsgroups"},
			Verbs:     []string{"list", "get"},
		},

		// Rules needed by guardian to handle other manager requests.
		{
			APIGroups: []string{""},
			Resources: []string{"events"},
			Verbs:     []string{"list"},
		},
		{
			APIGroups: []string{""},
			Resources: []string{"serviceaccounts"},
			Verbs:     []string{"list"},
		},
		{
			// Allow query server talk to Prometheus via the manager user.
			APIGroups: []string{""},
			Resources: []string{"services/proxy"},
			ResourceNames: []string{
				"calico-node-prometheus:9090",
				"https:calico-api:8080",
			},
			Verbs: []string{"create", "get"},
		},
		{
			APIGroups: []string{"apps"},
			Resources: []string{"daemonsets", "replicasets", "statefulsets"},
			Verbs:     []string{"list"},
		},
		{
			APIGroups: []string{"authentication.k8s.io"},
			Resources: []string{"tokenreviews"},
			Verbs:     []string{"create"},
		},
		{
			APIGroups: []string{"authorization.k8s.io"},
			Resources: []string{"subjectaccessreviews"},
			Verbs:     []string{"create"},
		},
		{
			APIGroups: []string{"networking.k8s.io"},
			Resources: []string{"networkpolicies"},
			Verbs:     []string{"get", "list"},
		},
		{
			APIGroups: []string{"policy.networking.k8s.io"},
			Resources: []string{
				"clusternetworkpolicies",
				"adminnetworkpolicies",
				"baselineadminnetworkpolicies",
			},
			Verbs: []string{"list"},
		},
		{
			APIGroups: []string{"projectcalico.org"},
			Resources: []string{"alertexceptions"},
			Verbs:     []string{"get", "list", "update"},
		},
		{
			APIGroups:     []string{"projectcalico.org"},
			Resources:     []string{"felixconfigurations"},
			ResourceNames: []string{"default"},
			Verbs:         []string{"get"},
		},
		{
			APIGroups: []string{"projectcalico.org"},
			Resources: []string{
				"globalnetworkpolicies",
				"networksets",
				"stagedglobalnetworkpolicies",
				"stagedkubernetesnetworkpolicies",
				"tier.globalnetworkpolicies",
				"tier.stagedglobalnetworkpolicies",
			},
			Verbs: []string{"list"},
		},
		{
			APIGroups: []string{"projectcalico.org"},
			Resources: []string{"hostendpoints"},
			Verbs:     []string{"list"},
		},

		// Rules needed by guardian to handle policy recommendation requests.
		{
			APIGroups: []string{"projectcalico.org"},
			Resources: []string{
				"policyrecommendationscopes",
				"policyrecommendationscopes/status",
			},
			Verbs: []string{"create", "delete", "get", "list", "patch", "update", "watch"},
		},

		// Rules needed by guardian to handle calico-kube-controller requests.
		{
			// Nodes are watched to monitor for deletions.
			APIGroups: []string{""},
			Resources: []string{"endpoints"},
			Verbs:     []string{"create", "delete", "get", "list", "update", "watch"},
		},
		{
			APIGroups: []string{""},
			Resources: []string{"services/status"},
			Verbs:     []string{"get", "list", "update", "watch"},
		},
		{
			// Needs to manage hostendpoints.
			APIGroups: []string{"projectcalico.org", "crd.projectcalico.org"},
			Resources: []string{"hostendpoints"},
			Verbs:     []string{"create", "delete", "get", "list", "update", "watch"},
		},
		{
			// Needs access to update clusterinformations.
			APIGroups: []string{"projectcalico.org", "crd.projectcalico.org"},
			Resources: []string{"clusterinformations"},
			Verbs:     []string{"create", "get", "list", "update", "watch"},
		},
		{
			// Needs to manipulate kubecontrollersconfiguration, which contains its config.
			// It creates a default if none exists, and updates status as well.
			APIGroups: []string{"projectcalico.org", "crd.projectcalico.org"},
			Resources: []string{"kubecontrollersconfigurations"},
			Verbs:     []string{"create", "get", "list", "update", "watch"},
		},
		{
			APIGroups: []string{"projectcalico.org", "crd.projectcalico.org"},
			Resources: []string{"tiers"},
			Verbs:     []string{"create"},
		},
		{
			APIGroups: []string{"crd.projectcalico.org", "projectcalico.org"},
			Resources: []string{"deeppacketinspections"},
			Verbs:     []string{"get", "list", "watch"},
		},
		{
			APIGroups: []string{"projectcalico.org", "crd.projectcalico.org"},
			Resources: []string{"deeppacketinspections/status"},
			Verbs:     []string{"update"},
		},
		{
			APIGroups: []string{"projectcalico.org", "crd.projectcalico.org"},
			Resources: []string{"packetcaptures"},
			Verbs:     []string{"get", "list", "update"},
		},
		{
			APIGroups: []string{"projectcalico.org", "crd.projectcalico.org"},
			Resources: []string{"remoteclusterconfigurations"},
			Verbs:     []string{"get", "list", "watch"},
		},
		{
			APIGroups: []string{"projectcalico.org"},
			Resources: []string{"licensekeys"},
			Verbs:     []string{"create", "get", "list", "update", "watch"},
		},
		{
			// Grant permissions to access ClusterInformation resources in managed clusters.
			APIGroups: []string{"projectcalico.org"},
			Resources: []string{"clusterinformations"},
			Verbs:     []string{"get", "list", "watch"},
		},
		{
			APIGroups: []string{"usage.tigera.io"},
			Resources: []string{"licenseusagereports"},
			Verbs:     []string{"create", "delete", "get", "list", "update", "watch"},
		},

		// Rules needed by guardian to handle Intrusion detection requests.
		{
			APIGroups: []string{""},
			Resources: []string{"podtemplates"},
			Verbs:     []string{"get"},
		},
		{
			APIGroups: []string{"apps"},
			Resources: []string{"deployments"},
			Verbs:     []string{"get"},
		},
		{
			APIGroups: []string{"projectcalico.org", "crd.projectcalico.org"},
			Resources: []string{"alertexceptions"},
			Verbs:     []string{"get", "list"},
		},
		{
			APIGroups: []string{"projectcalico.org", "crd.projectcalico.org"},
			Resources: []string{"securityeventwebhooks"},
			Verbs:     []string{"get", "list", "update", "watch"},
		},
		{
			APIGroups: []string{"projectcalico.org"},
			Resources: []string{
				"globalalerts",
				"globalalerts/status",
				"globalthreatfeeds",
				"globalthreatfeeds/status",
			},
			Verbs: []string{"create", "delete", "get", "list", "patch", "update", "watch"},
		},
		// Rules needed to fetch the compliance reports
		{
			APIGroups: []string{"projectcalico.org"},
			Resources: []string{"globalreporttypes", "globalreports"},
			Verbs:     []string{"get", "list", "watch"},
		},
	}

	// Rules needed by policy recommendation in openshift.
	if isOpenShift {
		rules = append(rules,
			rbacv1.PolicyRule{
				APIGroups:     []string{"security.openshift.io"},
				Resources:     []string{"securitycontextconstraints"},
				Verbs:         []string{"use"},
				ResourceNames: []string{securitycontextconstraints.HostNetworkV2},
			},
		)
	}

	return rules
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
