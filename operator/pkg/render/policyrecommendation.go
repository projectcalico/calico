// Copyright (c) 2023-2026 Tigera, Inc. All rights reserved.

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

package render

import (
	"crypto/x509"
	"fmt"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apiserver/pkg/authentication/serviceaccount"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"

	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	operatorv1 "github.com/projectcalico/calico/operator/api/v1"
	"github.com/projectcalico/calico/operator/pkg/common"
	"github.com/projectcalico/calico/operator/pkg/components"
	rcomponents "github.com/projectcalico/calico/operator/pkg/render/common/components"
	relasticsearch "github.com/projectcalico/calico/operator/pkg/render/common/elasticsearch"
	rmeta "github.com/projectcalico/calico/operator/pkg/render/common/meta"
	"github.com/projectcalico/calico/operator/pkg/render/common/networkpolicy"
	"github.com/projectcalico/calico/operator/pkg/render/common/secret"
	"github.com/projectcalico/calico/operator/pkg/render/common/securitycontext"
	"github.com/projectcalico/calico/operator/pkg/render/common/securitycontextconstraints"
	"github.com/projectcalico/calico/operator/pkg/tls/certificatemanagement"
	"github.com/projectcalico/calico/operator/pkg/tls/certkeyusage"
)

// The names of the components related to the PolicyRecommendation APIs related rendered objects.
const (
	ElasticsearchPolicyRecommendationUserSecret = "tigera-ee-policy-recommendation-elasticsearch-access"

	PolicyRecommendationName       = "tigera-policy-recommendation"
	PolicyRecommendationNamespace  = common.CalicoNamespace
	PolicyRecommendationPolicyName = networkpolicy.CalicoComponentPolicyPrefix + PolicyRecommendationName

	PolicyRecommendationTLSSecretName                                   = "policy-recommendation-tls"
	PolicyRecommendationMultiTenantManagedClustersAccessRoleBindingName = "tigera-policy-recommendation-managed-cluster-access"
	PolicyRecommendationManagedClustersWatchRoleBindingName             = "tigera-policy-recommendation-managed-cluster-watch"
)

// Register secret/certs that need Server and Client Key usage
func init() {
	certkeyusage.SetCertKeyUsage(PolicyRecommendationTLSSecretName, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth})
}

// PolicyRecommendationConfiguration contains all the config information needed to render the component.
type PolicyRecommendationConfiguration struct {
	ClusterDomain                  string
	Installation                   *operatorv1.InstallationSpec
	ManagedCluster                 bool
	ManagementCluster              bool
	OpenShift                      bool
	PullSecrets                    []*corev1.Secret
	TrustedBundle                  certificatemanagement.TrustedBundleRO
	PolicyRecommendationCertSecret certificatemanagement.KeyPairInterface

	Namespace         string
	BindingNamespaces []string

	// Whether or not to run the rendered components in multi-tenant mode.
	Tenant          *operatorv1.Tenant
	ExternalElastic bool

	PolicyRecommendation *operatorv1.PolicyRecommendation
}

type policyRecommendationComponent struct {
	cfg         *PolicyRecommendationConfiguration
	calicoImage string
}

func PolicyRecommendation(cfg *PolicyRecommendationConfiguration) Component {
	return &policyRecommendationComponent{
		cfg: cfg,
	}
}

func (pr *policyRecommendationComponent) ResolveImages(is *operatorv1.ImageSet) error {
	reg := pr.cfg.Installation.Registry
	path := pr.cfg.Installation.ImagePath
	prefix := pr.cfg.Installation.ImagePrefix

	var err error
	pr.calicoImage, err = components.GetReference(components.ComponentTigeraCalico, reg, path, prefix, is)
	if err != nil {
		return err
	}
	return nil
}

func (pr *policyRecommendationComponent) SupportedOSType() rmeta.OSType {
	return rmeta.OSTypeLinux
}

func (pr *policyRecommendationComponent) Objects() ([]client.Object, []client.Object) {
	var objs []client.Object

	// Guardian has RBAC permissions to handle policy recommendation requests in managed clusters,
	// so clean up the resources left behind in older clusters during upgrade.
	if pr.cfg.ManagedCluster {
		return objs, pr.deprecatedObjects(pr.cfg.ManagedCluster)
	}

	// Management and managed clusters need API access to the resources defined in the policy
	// recommendation cluster role
	objs = []client.Object{
		pr.calicoSystemPolicyForPolicyRecommendation(),
		pr.serviceAccount(),
		pr.clusterRole(),
		pr.clusterRoleBinding(),
		pr.managedClustersWatchRoleBinding(),
		pr.deployment(),
	}
	if pr.cfg.Tenant.MultiTenant() {
		objs = append(objs, pr.multiTenantManagedClustersAccess()...)
	}

	return objs, pr.deprecatedObjects(pr.cfg.ManagedCluster)
}

func (pr *policyRecommendationComponent) Ready() bool {
	return true
}

func (pr *policyRecommendationComponent) clusterRole() client.Object {
	rules := []rbacv1.PolicyRule{
		{
			APIGroups: []string{""},
			Resources: []string{"namespaces"},
			Verbs:     []string{"get", "list", "watch"},
		},
		{
			APIGroups: []string{"projectcalico.org"},
			Resources: []string{
				"tiers",
				"policyrecommendationscopes",
				"policyrecommendationscopes/status",
				"stagednetworkpolicies",
				"tier.stagednetworkpolicies",
				"networkpolicies",
				"tier.networkpolicies",
				"stagedglobalnetworkpolicies",
				"tier.stagedglobalnetworkpolicies",
				"globalnetworkpolicies",
				"tier.globalnetworkpolicies",
				"globalnetworksets",
				"hostendpoints",
			},
			Verbs: []string{"create", "delete", "get", "list", "patch", "update", "watch"},
		},
		{
			// Add read access to Linseed APIs.
			APIGroups: []string{"linseed.tigera.io"},
			Resources: []string{
				"flows",
			},
			Verbs: []string{"get"},
		},
	}

	if !pr.cfg.ManagedCluster {
		rules = append(rules, []rbacv1.PolicyRule{
			{
				APIGroups: []string{"projectcalico.org"},
				Resources: []string{"licensekeys"},
				Verbs:     []string{"get", "list", "watch"},
			},
			{
				APIGroups: []string{"crd.projectcalico.org"},
				Resources: []string{"licensekeys"},
				Verbs:     []string{"get", "list", "watch"},
			},
		}...)
	}

	if pr.cfg.OpenShift {
		rules = append(rules, rbacv1.PolicyRule{
			APIGroups:     []string{"security.openshift.io"},
			Resources:     []string{"securitycontextconstraints"},
			Verbs:         []string{"use"},
			ResourceNames: []string{securitycontextconstraints.HostNetworkV2},
		})
	}

	if pr.cfg.Tenant.MultiTenant() {
		// These rules are used by policy-recommendation in a management cluster serving multiple tenants in order to appear to managed
		// clusters as the expected serviceaccount. They're only needed when there are multiple tenants sharing the same
		// management cluster.
		rules = append(rules, []rbacv1.PolicyRule{
			{
				APIGroups:     []string{""},
				Resources:     []string{"serviceaccounts"},
				Verbs:         []string{"impersonate"},
				ResourceNames: []string{PolicyRecommendationName},
			},
			{
				APIGroups: []string{""},
				Resources: []string{"groups"},
				Verbs:     []string{"impersonate"},
				ResourceNames: []string{
					serviceaccount.AllServiceAccountsGroup,
					"system:authenticated",
					fmt.Sprintf("%s%s", serviceaccount.ServiceAccountGroupPrefix, PolicyRecommendationNamespace),
				},
			},
		}...)
	}

	return &rbacv1.ClusterRole{
		TypeMeta: metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name: PolicyRecommendationName,
		},
		Rules: rules,
	}
}

func (pr *policyRecommendationComponent) clusterRoleBinding() client.Object {
	return rcomponents.ClusterRoleBinding(PolicyRecommendationName, PolicyRecommendationName, PolicyRecommendationName, pr.cfg.BindingNamespaces)
}

func (pr *policyRecommendationComponent) managedClustersWatchRoleBinding() client.Object {
	if pr.cfg.Tenant.MultiTenant() {
		// There are 2 service accounts that require permissions on managedcluster resources; the real service account in
		// the tenant namespace that is used to watch managedcluster resources and the tigera-policy-recommendation:tigera-policy-recommendation
		// service account which is hardcoded into the impersonation headers by voltron and used only for checking whether
		// the request is allowed to access the managed cluster in question
		policyRecRoleBinding := &rbacv1.RoleBinding{
			TypeMeta:   metav1.TypeMeta{Kind: "RoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"},
			ObjectMeta: metav1.ObjectMeta{Name: PolicyRecommendationManagedClustersWatchRoleBindingName, Namespace: pr.cfg.Namespace},
			RoleRef: rbacv1.RoleRef{
				APIGroup: "rbac.authorization.k8s.io",
				Kind:     "ClusterRole",
				Name:     ManagedClustersWatchClusterRoleName,
			},
			Subjects: []rbacv1.Subject{
				{
					Kind:      "ServiceAccount",
					Name:      PolicyRecommendationName,
					Namespace: pr.cfg.Namespace,
				},
				{
					Kind:      "ServiceAccount",
					Name:      "tigera-policy-recommendation",
					Namespace: "tigera-policy-recommendation",
				},
			},
		}
		return policyRecRoleBinding
	}

	return rcomponents.ClusterRoleBinding(PolicyRecommendationManagedClustersWatchRoleBindingName, ManagedClustersWatchClusterRoleName, PolicyRecommendationName, []string{pr.cfg.Namespace})
}

func (pr *policyRecommendationComponent) multiTenantManagedClustersAccess() []client.Object {
	var objects []client.Object

	// In a single tenant setup we want to create a cluster role that binds using service account
	// tigera-policy-recommendation from calico-system namespace. In a multi-tenant setup
	// PolicyRecommendation Controller from the tenant's namespace impersonates service tigera-policy-recommendation
	// from calico-system namespace
	objects = append(objects, &rbacv1.RoleBinding{
		TypeMeta:   metav1.TypeMeta{Kind: "RoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{Name: PolicyRecommendationMultiTenantManagedClustersAccessRoleBindingName, Namespace: pr.cfg.Namespace},
		RoleRef: rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "ClusterRole",
			Name:     MultiTenantManagedClustersAccessClusterRoleName,
		},
		Subjects: []rbacv1.Subject{
			// requests for policy recommendation to managed clusters are done using service account tigera-policy-recommendation
			// from calico-system namespace regardless of tenancy mode (single tenant or multi-tenant)
			{
				Kind:      "ServiceAccount",
				Name:      PolicyRecommendationName,
				Namespace: PolicyRecommendationNamespace,
			},
		},
	})

	return objects
}

// deployment returns the policy recommendation deployments. It assumes that this is defined for
// management and standalone clusters only.
func (pr *policyRecommendationComponent) deployment() *appsv1.Deployment {
	envs := []corev1.EnvVar{
		{
			Name:  "LOG_LEVEL",
			Value: "Info",
		},
		{
			Name:  "MULTI_CLUSTER_FORWARDING_CA",
			Value: pr.cfg.TrustedBundle.MountPath(),
		},
		{
			Name:  "MULTI_CLUSTER_FORWARDING_ENDPOINT",
			Value: ManagerService(pr.cfg.Tenant),
		},
		{
			Name:  "LINSEED_URL",
			Value: relasticsearch.LinseedEndpoint(pr.SupportedOSType(), pr.cfg.ClusterDomain, LinseedNamespace(pr.cfg.Tenant), pr.cfg.ManagedCluster, false),
		},
		{
			Name:  "LINSEED_CA",
			Value: pr.cfg.TrustedBundle.MountPath(),
		},
		{
			Name:  "LINSEED_CLIENT_CERT",
			Value: pr.cfg.PolicyRecommendationCertSecret.VolumeMountCertificateFilePath(),
		},
		{
			Name:  "LINSEED_CLIENT_KEY",
			Value: pr.cfg.PolicyRecommendationCertSecret.VolumeMountKeyFilePath(),
		},
		{
			Name:  "LINSEED_TOKEN",
			Value: GetLinseedTokenPath(false),
		},
	}

	if pr.cfg.Tenant != nil {
		if pr.cfg.ExternalElastic {
			envs = append(envs, corev1.EnvVar{Name: "TENANT_ID", Value: pr.cfg.Tenant.Spec.ID})
		}

		if pr.cfg.Tenant.MultiTenant() {
			envs = append(envs, corev1.EnvVar{Name: "TENANT_NAMESPACE", Value: pr.cfg.Tenant.Namespace})
		}
	}

	if pr.cfg.ManagementCluster {
		envs = append(envs, corev1.EnvVar{Name: "CLUSTER_CONNECTION_TYPE", Value: "management"})
		if pr.cfg.Tenant != nil && pr.cfg.Tenant.ManagedClusterIsCalico() {
			envs = append(envs, corev1.EnvVar{Name: "MANAGED_CLUSTER_TYPE", Value: "calico"})
		}
	} else {
		envs = append(envs, corev1.EnvVar{Name: "CLUSTER_CONNECTION_TYPE", Value: "standalone"})
	}

	volumeMounts := pr.cfg.TrustedBundle.VolumeMounts(pr.SupportedOSType())
	volumeMounts = append(volumeMounts, pr.cfg.PolicyRecommendationCertSecret.VolumeMount(pr.SupportedOSType()))

	controllerContainer := corev1.Container{
		Name:            "policy-recommendation-controller",
		Image:           pr.calicoImage,
		Command:         []string{components.CalicoBinaryPath, "component", "policy-recommendation"},
		Env:             envs,
		SecurityContext: securitycontext.NewNonRootContext(),
		VolumeMounts:    volumeMounts,
	}

	volumes := []corev1.Volume{
		pr.cfg.TrustedBundle.Volume(),
		pr.cfg.PolicyRecommendationCertSecret.Volume(),
	}
	var initContainers []corev1.Container
	if pr.cfg.PolicyRecommendationCertSecret != nil && pr.cfg.PolicyRecommendationCertSecret.UseCertificateManagement() {
		initContainers = append(initContainers, pr.cfg.PolicyRecommendationCertSecret.InitContainer(PolicyRecommendationNamespace, controllerContainer.SecurityContext))
	}

	tolerations := pr.cfg.Installation.ControlPlaneTolerations
	if pr.cfg.Installation.KubernetesProvider.IsGKE() {
		tolerations = append(tolerations, rmeta.TolerateGKEARM64NoSchedule)
	}

	podTemplateSpec := &corev1.PodTemplateSpec{
		ObjectMeta: metav1.ObjectMeta{
			Name:        PolicyRecommendationName,
			Namespace:   pr.cfg.Namespace,
			Annotations: pr.policyRecommendationAnnotations(),
		},
		Spec: corev1.PodSpec{
			Tolerations:        tolerations,
			NodeSelector:       pr.cfg.Installation.ControlPlaneNodeSelector,
			ServiceAccountName: PolicyRecommendationName,
			ImagePullSecrets:   secret.GetReferenceList(pr.cfg.PullSecrets),
			Containers:         []corev1.Container{controllerContainer},
			InitContainers:     initContainers,
			Volumes:            volumes,
		},
	}

	d := &appsv1.Deployment{
		TypeMeta: metav1.TypeMeta{Kind: "Deployment", APIVersion: "apps/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      PolicyRecommendationName,
			Namespace: pr.cfg.Namespace,
		},
		Spec: appsv1.DeploymentSpec{
			Replicas: ptr.To(int32(1)),
			Template: *podTemplateSpec,
		},
	}

	if pr.cfg.PolicyRecommendation != nil {
		if overrides := pr.cfg.PolicyRecommendation.Spec.PolicyRecommendationDeployment; overrides != nil {
			rcomponents.ApplyDeploymentOverrides(d, overrides)
		}
	}

	return d
}

func (pr *policyRecommendationComponent) policyRecommendationAnnotations() map[string]string {
	return pr.cfg.TrustedBundle.HashAnnotations()
}

func (pr *policyRecommendationComponent) serviceAccount() client.Object {
	return &corev1.ServiceAccount{
		TypeMeta:   metav1.TypeMeta{Kind: "ServiceAccount", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{Name: PolicyRecommendationName, Namespace: pr.cfg.Namespace},
	}
}

// calicoSystemPolicyForPolicyRecommendation defines a calico-system policy for policy recommendation.
func (pr *policyRecommendationComponent) calicoSystemPolicyForPolicyRecommendation() *v3.NetworkPolicy {
	egressRules := []v3.Rule{
		{
			Action:      v3.Allow,
			Protocol:    &networkpolicy.TCPProtocol,
			Destination: networkpolicy.KubeAPIServerEntityRule,
		},
		{
			Action:      v3.Allow,
			Protocol:    &networkpolicy.TCPProtocol,
			Destination: networkpolicy.Helper(pr.cfg.Tenant.MultiTenant(), pr.cfg.Namespace).ManagerEntityRule(),
		},
	}

	if !pr.cfg.ManagedCluster {
		egressRules = append(egressRules, v3.Rule{
			Action:      v3.Allow,
			Protocol:    &networkpolicy.TCPProtocol,
			Destination: networkpolicy.Helper(pr.cfg.Tenant.MultiTenant(), pr.cfg.Namespace).LinseedEntityRule(),
		})
	}

	egressRules = networkpolicy.AppendDNSEgressRules(egressRules, pr.cfg.OpenShift)

	return &v3.NetworkPolicy{
		TypeMeta: metav1.TypeMeta{Kind: "NetworkPolicy", APIVersion: "projectcalico.org/v3"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      PolicyRecommendationPolicyName,
			Namespace: pr.cfg.Namespace,
		},
		Spec: v3.NetworkPolicySpec{
			Order:    &networkpolicy.HighPrecedenceOrder,
			Tier:     networkpolicy.CalicoTierName,
			Selector: networkpolicy.KubernetesAppSelector(PolicyRecommendationName),
			Types:    []v3.PolicyType{v3.PolicyTypeEgress},
			Ingress:  []v3.Rule{},
			Egress:   egressRules,
		},
	}
}

func (pr *policyRecommendationComponent) deprecatedObjects(isManagedCluster bool) []client.Object {
	var deprecatedObjs []client.Object
	if isManagedCluster {
		deprecatedObjs = append(deprecatedObjs, []client.Object{
			&corev1.Namespace{
				TypeMeta:   metav1.TypeMeta{Kind: "Namespace", APIVersion: "v1"},
				ObjectMeta: metav1.ObjectMeta{Name: "tigera-policy-recommendation"},
			},
			&rbacv1.ClusterRole{
				TypeMeta:   metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"},
				ObjectMeta: metav1.ObjectMeta{Name: "tigera-policy-recommendation"},
			},
			&rbacv1.ClusterRoleBinding{
				TypeMeta:   metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"},
				ObjectMeta: metav1.ObjectMeta{Name: "tigera-policy-recommendation"},
			},
		}...)
	} else {
		// Clean up the legacy namespace
		deprecatedObjs = append(deprecatedObjs,
			&corev1.Namespace{
				TypeMeta:   metav1.TypeMeta{Kind: "Namespace", APIVersion: "v1"},
				ObjectMeta: metav1.ObjectMeta{Name: "tigera-policy-recommendation"},
			},
			// allow-tigera Tier was renamed to calico-system
			networkpolicy.DeprecatedAllowTigeraNetworkPolicyObject("tigera-policy-recommendation", pr.cfg.Namespace),
		)
	}

	return deprecatedObjs
}
