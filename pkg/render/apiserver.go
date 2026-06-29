// Copyright (c) 2019-2026 Tigera, Inc. All rights reserved.

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
	"fmt"
	"net/url"
	"strings"

	admregv1 "k8s.io/api/admissionregistration/v1"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	netv1 "k8s.io/api/networking/v1"
	policyv1 "k8s.io/api/policy/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	apiregv1 "k8s.io/kube-aggregator/pkg/apis/apiregistration/v1"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"

	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	"github.com/tigera/api/pkg/lib/numorstring"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/components"
	"github.com/tigera/operator/pkg/controller/k8sapi"
	"github.com/tigera/operator/pkg/render/common/authentication"
	rcomp "github.com/tigera/operator/pkg/render/common/components"
	relasticsearch "github.com/tigera/operator/pkg/render/common/elasticsearch"
	rmeta "github.com/tigera/operator/pkg/render/common/meta"
	"github.com/tigera/operator/pkg/render/common/networkpolicy"
	"github.com/tigera/operator/pkg/render/common/podaffinity"
	"github.com/tigera/operator/pkg/render/common/secret"
	"github.com/tigera/operator/pkg/render/common/securitycontext"
	"github.com/tigera/operator/pkg/render/common/securitycontextconstraints"
	"github.com/tigera/operator/pkg/tls/certificatemanagement"
)

type ContainerName string

const (
	APIServerPort       = 5443
	APIServerPortName   = "apiserver"
	APIServerPolicyName = networkpolicy.CalicoComponentPolicyPrefix + "apiserver-access"

	auditLogsVolumeName   = "calico-audit-logs"
	auditPolicyVolumeName = "calico-audit-policy"
)

const (
	APIServerResourceName  = "apiserver"
	APIServerNamespace     = common.CalicoNamespace
	QueryServerPort        = 8080
	QueryServerPortName    = "queryserver"
	QueryserverNamespace   = "calico-system"
	QueryserverServiceName = "calico-api"

	// Use the same API server container name for both OSS and Enterprise.
	APIServerName                                         = "calico-apiserver"
	APIServerContainerName                  ContainerName = "calico-apiserver"
	TigeraAPIServerQueryServerContainerName ContainerName = "tigera-queryserver"

	CalicoAPIServerTLSSecretName = "calico-apiserver-certs"
	APIServerServiceName         = "calico-api"
	APIServerServiceAccountName  = "calico-apiserver"

	APIServerSecretsRBACName                                      = "calico-extension-apiserver-secrets-access"
	APIServerLinseedAccessClusterRoleName                         = "calico-apiserver-linseed-access"
	MultiTenantManagedClustersAccessClusterRoleName               = "calico-managed-cluster-access"
	ManagedClustersWatchClusterRoleName                           = "calico-managed-cluster-watch"
	L7AdmissionControllerContainerName              ContainerName = "calico-l7-admission-controller"
	L7AdmissionControllerPort                                     = 6443
	L7AdmissionControllerPortName                                 = "l7admctrl"
)

var (
	TigeraAPIServerEntityRule = v3.EntityRule{
		Services: &v3.ServiceMatch{
			Namespace: QueryserverNamespace,
			Name:      QueryserverServiceName,
		},
	}

	// allVerbs is a list of all verbs that are supported by the API server, used
	// for tiered policy passthrough.
	allVerbs = []string{
		"get",
		"list",
		"watch",
		"create",
		"update",
		"patch",
		"delete",
		"deletecollection",
	}
)

func APIServer(cfg *APIServerConfiguration) (Component, error) {
	return &apiServerComponent{
		cfg: cfg,
	}, nil
}

func APIServerPolicy(cfg *APIServerConfiguration) Component {
	return NewPassthrough(
		[]client.Object{calicoSystemAPIServerPolicy(cfg)},
		[]client.Object{
			// allow-tigera Tier was renamed to calico-system
			networkpolicy.DeprecatedAllowTigeraNetworkPolicyObject("apiserver-access", APIServerNamespace),
		},
	)
}

// APIServerConfiguration contains all the config information needed to render the component.
type APIServerConfiguration struct {
	K8SServiceEndpoint           k8sapi.ServiceEndpoint
	K8SServiceEndpointPodNetwork k8sapi.ServiceEndpoint
	Installation                 *operatorv1.InstallationSpec
	APIServer                    *operatorv1.APIServerSpec
	ForceHostNetwork             bool
	ApplicationLayer             *operatorv1.ApplicationLayer
	ManagementCluster            *operatorv1.ManagementCluster
	ManagementClusterConnection  *operatorv1.ManagementClusterConnection
	TLSKeyPair                   certificatemanagement.KeyPairInterface
	PullSecrets                  []*corev1.Secret
	OpenShift                    bool
	TrustedBundle                certificatemanagement.TrustedBundle
	MultiTenant                  bool

	// BindingNamespaces are the tenant namespaces whose calico-apiserver ServiceAccount should be granted
	// Linseed access on a multi-tenant management cluster. Each managed cluster's calico-apiserver
	// authenticates to Linseed with a token whose identity is namespace-overridden to its tenant namespace
	// (system:serviceaccount:<tenant-namespace>:calico-apiserver), so a ClusterRoleBinding with one subject
	// per tenant namespace is required. Empty on zero/single-tenant clusters.
	BindingNamespaces []string

	KeyValidatorConfig authentication.KeyValidatorConfig
	KubernetesVersion  *common.VersionInfo
	ClusterDomain      string

	// RBACManagementEnabled gates the RBAC management UI permissions on
	// tigera-network-admin.
	RBACManagementEnabled bool

	// Cloud indicates the API server is being rendered for a Calico Cloud install. It gates
	// cloud-specific RBAC in the tigera-ui-user / tigera-network-admin cluster roles (Calico Cloud
	// exposes only per-user UISettings and grants access to runtime logs). When false the RBAC is
	// exactly the regular Calico/Calico Enterprise RBAC.
	Cloud bool

	// Whether or not we should run the aggregation API server for projectcalico.org/v3 APIs
	// as part of this component.
	RequiresAggregationServer bool

	// When certificate management is enabled, we need a separate init container to create a cert, running
	// with the same permissions as query server.
	QueryServerTLSKeyPairCertificateManagementOnly certificatemanagement.KeyPairInterface
}

type apiServerComponent struct {
	cfg                             *APIServerConfiguration
	calicoImage                     string
	l7AdmissionControllerEnvoyImage string
	dikastesImage                   string
}

func (c *apiServerComponent) ResolveImages(is *operatorv1.ImageSet) error {
	reg := c.cfg.Installation.Registry
	path := c.cfg.Installation.ImagePath
	prefix := c.cfg.Installation.ImagePrefix
	var err error
	errMsgs := []string{}

	enterprise := c.cfg.Installation.Variant.IsEnterprise()
	if enterprise || c.cfg.RequiresAggregationServer {
		c.calicoImage, err = components.GetReference(components.CombinedCalicoImage(c.cfg.Installation), reg, path, prefix, is)
		if err != nil {
			errMsgs = append(errMsgs, err.Error())
		}
	}

	if enterprise && c.cfg.IsSidecarInjectionEnabled() {
		c.l7AdmissionControllerEnvoyImage, err = components.GetReference(components.ComponentEnvoyProxy, reg, path, prefix, is)
		if err != nil {
			errMsgs = append(errMsgs, err.Error())
		}
		c.dikastesImage, err = components.GetReference(components.ComponentDikastes, reg, path, prefix, is)
		if err != nil {
			errMsgs = append(errMsgs, err.Error())
		}
	}

	if len(errMsgs) != 0 {
		return fmt.Errorf("%s", strings.Join(errMsgs, ","))
	}
	return nil
}

func (c *apiServerComponent) SupportedOSType() rmeta.OSType {
	return rmeta.OSTypeLinux
}

func (c *apiServerComponent) Objects() ([]client.Object, []client.Object) {
	// Start with all of the cluster-scoped resources that are used for both Calico and Calico Enterprise.
	// When switching between Calico / Enterprise, these objects are simply updated in-place.
	globalObjects := []client.Object{
		c.calicoCustomResourcesClusterRole(),
		c.calicoCustomResourcesClusterRoleBinding(),
		c.tierGetterClusterRole(),
		c.kubeControllerMgrTierGetterClusterRoleBinding(),
		c.delegateAuthClusterRoleBinding(),
		c.webhookReaderClusterRole(),
		c.webhookReaderClusterRoleBinding(),
	}

	objsToDelete := []client.Object{}

	// Namespaced objects common to both Calico and Calico Enterprise.
	// These objects will be updated when switching between the variants.
	namespacedObjects := []client.Object{}

	// Add in image pull secrets.
	secrets := secret.CopyToNamespace(APIServerNamespace, c.cfg.PullSecrets...)
	namespacedObjects = append(namespacedObjects, secret.ToRuntimeObjects(secrets...)...)

	// The deployment and its supporting objects are needed when running the aggregation API server
	// or when running Enterprise (which always needs the queryserver).
	if c.cfg.RequiresAggregationServer || c.cfg.Installation.Variant.IsEnterprise() {
		namespacedObjects = append(namespacedObjects,
			c.apiServerServiceAccount(),
			c.apiServerDeployment(),
			c.apiServerService(),
			c.apiServerPodDisruptionBudget(),
		)
	} else {
		objsToDelete = append(objsToDelete,
			&corev1.ServiceAccount{TypeMeta: metav1.TypeMeta{Kind: "ServiceAccount", APIVersion: "v1"}, ObjectMeta: metav1.ObjectMeta{Name: APIServerServiceAccountName, Namespace: APIServerNamespace}},
			&appsv1.Deployment{TypeMeta: metav1.TypeMeta{Kind: "Deployment", APIVersion: "apps/v1"}, ObjectMeta: metav1.ObjectMeta{Name: APIServerName, Namespace: APIServerNamespace}},
			&corev1.Service{TypeMeta: metav1.TypeMeta{Kind: "Service", APIVersion: "v1"}, ObjectMeta: metav1.ObjectMeta{Name: APIServerServiceName, Namespace: APIServerNamespace}},
			&policyv1.PodDisruptionBudget{TypeMeta: metav1.TypeMeta{Kind: "PodDisruptionBudget", APIVersion: "policy/v1"}, ObjectMeta: metav1.ObjectMeta{Name: APIServerName, Namespace: APIServerNamespace}},
		)
	}

	// These are objects that only need to exist when we are running an aggregation API server to
	// serve projectcalico.org/v3 APIs. If using CRDs for this API group, we can remove these objects.
	aggregationAPIServerObjects := []client.Object{
		c.calicoPolicyPassthruClusterRole(),
		c.calicoPolicyPassthruClusterRolebinding(),
		c.authClusterRole(),
		c.authClusterRoleBinding(),
		c.authReaderRoleBinding(),
	}

	if c.cfg.Installation.Variant.IsEnterprise() {
		aggregationAPIServerObjects = append(aggregationAPIServerObjects,
			c.uiSettingsGroupGetterClusterRole(),
			c.kubeControllerManagerUISettingsGroupGetterClusterRoleBinding(),
			c.uiSettingsPassthruClusterRole(),
			c.uiSettingsPassthruClusterRolebinding(),
			c.auditPolicyConfigMap(),
		)
	}

	// Add in certificates for API server TLS.
	if !c.cfg.TLSKeyPair.UseCertificateManagement() {
		aggregationAPIServerObjects = append(aggregationAPIServerObjects, c.apiServiceRegistration(c.cfg.TLSKeyPair.GetCertificatePEM()))
	} else {
		aggregationAPIServerObjects = append(aggregationAPIServerObjects, c.apiServiceRegistration(c.cfg.Installation.CertificateManagement.CACert))
	}

	// Global enterprise-only objects.
	globalEnterpriseObjects := []client.Object{
		c.tigeraAPIServerClusterRole(),
		c.tigeraAPIServerClusterRoleBinding(),
	}

	if c.cfg.MultiTenant {
		// On a multi-tenant management cluster, each tenant's calico-apiserver identity needs read access to
		// Linseed. A single least-privilege ClusterRole is bound to the calico-apiserver ServiceAccount in
		// every tenant namespace via one ClusterRoleBinding (see linseedAccessClusterRoleBinding).
		globalEnterpriseObjects = append(globalEnterpriseObjects,
			c.linseedAccessClusterRole(),
			c.linseedAccessClusterRoleBinding(),
		)
	} else {
		// These resources are only installed in zero-tenant clusters. Multi-tenant clusters don't use the default
		// RBAC resources.
		globalEnterpriseObjects = append(globalEnterpriseObjects,
			c.tigeraUserClusterRole(),
			c.tigeraNetworkAdminClusterRole(),
		)
		// The Linseed-access RBAC is multi-tenant only; ensure it is cleaned up on zero/single-tenant clusters.
		objsToDelete = append(objsToDelete,
			c.linseedAccessClusterRoleBinding(),
			c.linseedAccessClusterRole(),
		)
	}

	if c.cfg.ManagementCluster != nil {
		globalEnterpriseObjects = append(globalEnterpriseObjects, c.managedClusterWatchClusterRole())
		if c.cfg.MultiTenant {
			// Multi-tenant management cluster API servers need access to per-tenant CA secrets in order to sign
			// per-tenant guardian certificates when creating ManagedClusters.
			globalEnterpriseObjects = append(globalEnterpriseObjects, c.multiTenantSecretsRBAC()...)
			// Multi-tenant management cluster components impersonate the single-tenant canonical service account
			// in order to retrieve informations from the managed cluster. A cluster role will be created and each
			// component will create a role binding in the tenant namespace
			globalEnterpriseObjects = append(globalEnterpriseObjects, c.multiTenantManagedClusterAccessClusterRoles()...)
		} else {
			globalEnterpriseObjects = append(globalEnterpriseObjects, c.secretsRBAC()...)
		}
	} else {
		// If we're not a management cluster, the API server doesn't need permissions to access secrets.
		objsToDelete = append(objsToDelete, c.multiTenantSecretsRBAC()...)
		objsToDelete = append(objsToDelete, c.secretsRBAC()...)
		objsToDelete = append(objsToDelete, c.multiTenantManagedClusterAccessClusterRoles()...)
		objsToDelete = append(objsToDelete, c.managedClusterWatchClusterRole())
	}

	// Namespaced enterprise-only objects.
	namespacedEnterpriseObjects := []client.Object{}

	if c.cfg.TrustedBundle != nil {
		namespacedEnterpriseObjects = append(namespacedEnterpriseObjects, c.cfg.TrustedBundle.ConfigMap(QueryserverNamespace))
	}
	if c.cfg.IsSidecarInjectionEnabled() {
		namespacedEnterpriseObjects = append(namespacedEnterpriseObjects, c.sidecarMutatingWebhookConfig())
	} else {
		objsToDelete = append(objsToDelete, &admregv1.MutatingWebhookConfiguration{ObjectMeta: metav1.ObjectMeta{Name: common.SidecarMutatingWebhookConfigName}})
	}
	if c.cfg.ManagementClusterConnection != nil {
		namespacedEnterpriseObjects = append(namespacedEnterpriseObjects,
			c.externalLinseedRoleBinding(),
		)
	}

	// Compile the final arrays based on the variant.
	if c.cfg.Installation.Variant.IsEnterprise() {
		// Create any enterprise specific objects.
		globalObjects = append(globalObjects, globalEnterpriseObjects...)
		namespacedObjects = append(namespacedObjects, namespacedEnterpriseObjects...)

		// Clean up cluster-scoped resources that were created with the 'tigera' prefix.
		// The apiserver now uses consistent resource names with 'calico' prefix across both EE and OSS variants.
		objsToDelete = append(objsToDelete, c.deprecatedResources()...)
	} else {
		// Explicitly delete any global enterprise objects.
		// Namespaced objects will be handled by namespace deletion.
		objsToDelete = append(objsToDelete, globalEnterpriseObjects...)
	}

	// Clean up deprecated k8s NetworkPolicy, regardless of variant,
	// avoiding leftovers in the case of switching between variants.
	objsToDelete = append(objsToDelete, &netv1.NetworkPolicy{
		TypeMeta:   metav1.TypeMeta{Kind: "NetworkPolicy", APIVersion: "networking.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{Name: "allow-apiserver", Namespace: APIServerNamespace},
	})

	// Add or remove the aggregation API server objects as needed.
	if c.cfg.RequiresAggregationServer {
		// Include the aggregation API server objects.
		globalObjects = append(globalObjects, aggregationAPIServerObjects...)
	} else {
		// If we're not running an aggregation API server, we need to delete the objects that are only needed for it.
		objsToDelete = append(objsToDelete, aggregationAPIServerObjects...)
	}

	// Explicitly delete any renamed/deprecated objects.
	objsToDelete = append(objsToDelete, c.getDeprecatedResources()...)
	objsToCreate := append(globalObjects, namespacedObjects...)

	return objsToCreate, objsToDelete
}

func (c *apiServerComponent) Ready() bool {
	return true
}

// For legacy reasons we use apiserver: true here instead of the k8s-app: name label,
// so we need to set it explicitly rather than use the common labeling logic.
func (c *apiServerComponent) deploymentSelector() *metav1.LabelSelector {
	return &metav1.LabelSelector{
		MatchLabels: map[string]string{
			"apiserver": "true",
		},
	}
}

func (c *apiServerComponent) apiServerPodDisruptionBudget() *policyv1.PodDisruptionBudget {
	maxUnavailable := intstr.FromInt(1)
	return &policyv1.PodDisruptionBudget{
		TypeMeta: metav1.TypeMeta{Kind: "PodDisruptionBudget", APIVersion: "policy/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      APIServerName,
			Namespace: APIServerNamespace,
		},
		Spec: policyv1.PodDisruptionBudgetSpec{
			MaxUnavailable: &maxUnavailable,
			Selector:       c.deploymentSelector(),
		},
	}
}

// apiServiceRegistration creates an API service that registers Tigera Secure APIs (and API server).
//
// Both Calico and Calico Enterprise, with the same name.
func (c *apiServerComponent) apiServiceRegistration(cert []byte) *apiregv1.APIService {
	// The APIService is the same for OSS and Enterprise, with the exception that
	// it points to a different Service and Namespace for each.
	s := &apiregv1.APIService{
		TypeMeta: metav1.TypeMeta{Kind: "APIService", APIVersion: "apiregistration.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name: "v3.projectcalico.org",
		},
		Spec: apiregv1.APIServiceSpec{
			Group:                "projectcalico.org",
			VersionPriority:      200,
			GroupPriorityMinimum: 1500,
			Service: &apiregv1.ServiceReference{
				Name:      APIServerServiceName,
				Namespace: APIServerNamespace,
			},
			Version:  "v3",
			CABundle: cert,
		},
	}
	return s
}

// delegateAuthClusterRoleBinding creates a clusterrolebinding that allows the API server to delegate
// authn/authz requests to main API server.
//
// Both Calico and Calico Enterprise, but different names.
func (c *apiServerComponent) delegateAuthClusterRoleBinding() client.Object {
	// Determine names based on the configured variant.
	return &rbacv1.ClusterRoleBinding{
		TypeMeta: metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name: "calico-apiserver-delegate-auth",
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      "ServiceAccount",
				Name:      APIServerServiceAccountName,
				Namespace: APIServerNamespace,
			},
		},
		RoleRef: rbacv1.RoleRef{
			Kind:     "ClusterRole",
			Name:     "system:auth-delegator",
			APIGroup: "rbac.authorization.k8s.io",
		},
	}
}

// authReaderRoleBinding creates a rolebinding that allows the API server to access the
// extension-apiserver-authentication configmap. That configmap contains the client CA file that
// the main API server was configured with.
//
// Both Calico and Calico Enterprise, but different names.
func (c *apiServerComponent) authReaderRoleBinding() client.Object {
	return &rbacv1.RoleBinding{
		TypeMeta: metav1.TypeMeta{Kind: "RoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "calico-apiserver-auth-reader",
			Namespace: "kube-system",
		},
		RoleRef: rbacv1.RoleRef{
			Kind:     "Role",
			Name:     "extension-apiserver-authentication-reader",
			APIGroup: "rbac.authorization.k8s.io",
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      "ServiceAccount",
				Name:      APIServerServiceAccountName,
				Namespace: APIServerNamespace,
			},
		},
	}
}

// apiServerServiceAccount creates the service account used by the API server.
//
// Both Calico and Calico Enterprise, but in different namespaces.
func (c *apiServerComponent) apiServerServiceAccount() *corev1.ServiceAccount {
	return &corev1.ServiceAccount{
		TypeMeta: metav1.TypeMeta{Kind: "ServiceAccount", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      APIServerServiceAccountName,
			Namespace: APIServerNamespace,
		},
	}
}

// linseedAccessClusterRole is a minimal, least-privilege ClusterRole granting the calico-apiserver identity
// read access to Linseed policy activity data (for queryserver enrichment). On a multi-tenant management
// cluster it is bound to each tenant's calico-apiserver ServiceAccount so that tenant's managed clusters can
// reach Linseed. The full backing-storage/queryserver rules live on the calico-apiserver ClusterRole, which is
// bound only to the calico-system API server itself.
//
// Calico Enterprise, multi-tenant only.
func (c *apiServerComponent) linseedAccessClusterRole() *rbacv1.ClusterRole {
	return &rbacv1.ClusterRole{
		TypeMeta:   metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{Name: APIServerLinseedAccessClusterRoleName},
		Rules: []rbacv1.PolicyRule{
			{
				// Read access to Linseed policy activity data for queryserver enrichment.
				APIGroups: []string{"linseed.tigera.io"},
				Resources: []string{"policyactivity"},
				Verbs:     []string{"get"},
			},
		},
	}
}

// linseedAccessClusterRoleBinding binds the Linseed-access ClusterRole to the calico-apiserver ServiceAccount
// in each tenant namespace. Linseed authorizes with a cluster-scoped SubjectAccessReview, so this is a single
// ClusterRoleBinding with one ServiceAccount subject per tenant namespace - mirroring how compliance,
// intrusion-detection, and the manager grant their managed-cluster components Linseed access.
//
// Calico Enterprise, multi-tenant only.
func (c *apiServerComponent) linseedAccessClusterRoleBinding() *rbacv1.ClusterRoleBinding {
	return rcomp.ClusterRoleBinding(APIServerLinseedAccessClusterRoleName, APIServerLinseedAccessClusterRoleName, APIServerServiceAccountName, c.cfg.BindingNamespaces)
}

func calicoSystemAPIServerPolicy(cfg *APIServerConfiguration) *v3.NetworkPolicy {
	egressRules := []v3.Rule{}
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
			Destination: DexEntityRule,
		},
		{
			// Allow queryserver to reach Linseed for policy activity enrichment.
			Action:      v3.Allow,
			Protocol:    &networkpolicy.TCPProtocol,
			Destination: networkpolicy.DefaultHelper().LinseedEntityRule(),
		},
	}...)

	if cfg.KeyValidatorConfig != nil {
		if parsedURL, err := url.Parse(cfg.KeyValidatorConfig.Issuer()); err == nil {
			oidcEgressRule := networkpolicy.GetOIDCEgressRule(parsedURL)
			egressRules = append(egressRules, oidcEgressRule)
		}
	}

	if r, err := cfg.K8SServiceEndpoint.DestinationEntityRule(); r != nil && err == nil {
		egressRules = append(egressRules, v3.Rule{
			Action:      v3.Allow,
			Protocol:    &networkpolicy.TCPProtocol,
			Destination: *r,
		})
	}

	// add pass after all egress rules
	egressRules = append(egressRules, v3.Rule{
		// Pass to subsequent tiers for further enforcement
		Action: v3.Pass,
	})

	apiServerContainerPort := getContainerPort(cfg, APIServerContainerName).ContainerPort
	queryServerContainerPort := getContainerPort(cfg, TigeraAPIServerQueryServerContainerName).ContainerPort
	l7AdmCtrlContainerPort := getContainerPort(cfg, L7AdmissionControllerContainerName).ContainerPort

	// The ports Calico Enterprise API Server and Calico Enterprise Query Server are configured to listen on.
	ingressPorts := networkpolicy.Ports(443, uint16(apiServerContainerPort), uint16(queryServerContainerPort), 10443)
	if cfg.IsSidecarInjectionEnabled() {
		ingressPorts = append(ingressPorts, numorstring.Port{MinPort: uint16(l7AdmCtrlContainerPort), MaxPort: uint16(l7AdmCtrlContainerPort)})
	}

	return &v3.NetworkPolicy{
		TypeMeta: metav1.TypeMeta{Kind: "NetworkPolicy", APIVersion: "projectcalico.org/v3"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      APIServerPolicyName,
			Namespace: APIServerNamespace,
		},
		Spec: v3.NetworkPolicySpec{
			Order:    &networkpolicy.HighPrecedenceOrder,
			Tier:     networkpolicy.CalicoTierName,
			Selector: networkpolicy.KubernetesAppSelector(APIServerName),
			Types:    []v3.PolicyType{v3.PolicyTypeIngress, v3.PolicyTypeEgress},
			Ingress: []v3.Rule{
				{
					Action:   v3.Allow,
					Protocol: &networkpolicy.TCPProtocol,
					// This policy allows Calico Enterprise API Server access from anywhere.
					Source: v3.EntityRule{
						Nets: []string{"0.0.0.0/0"},
					},
					Destination: v3.EntityRule{
						Ports: ingressPorts,
					},
				},
				{
					Action:   v3.Allow,
					Protocol: &networkpolicy.TCPProtocol,
					Source: v3.EntityRule{
						Nets: []string{"::/0"},
					},
					Destination: v3.EntityRule{
						Ports: ingressPorts,
					},
				},
			},
			Egress: egressRules,
		},
	}
}

// calicoCustomResourcesClusterRole creates a clusterrole that gives permissions to access backing CRDs and k8s networkpolicies.
//
// Both Calico and Calico Enterprise, with the same name.
func (c *apiServerComponent) calicoCustomResourcesClusterRole() *rbacv1.ClusterRole {
	rules := []rbacv1.PolicyRule{
		{
			// Core Kubernetes resources.
			APIGroups: []string{""},
			Resources: []string{
				"nodes",
				"namespaces",
				"pods",
				"serviceaccounts",
			},
			Verbs: []string{
				"get",
				"list",
				"watch",
			},
		},
		{
			// Kubernetes network policy resources.
			APIGroups: []string{"networking.k8s.io"},
			Resources: []string{"networkpolicies"},
			Verbs: []string{
				"get",
				"list",
				"watch",
			},
		},
		{
			// Kubernetes cluster network policy resources.
			APIGroups: []string{"policy.networking.k8s.io"},
			Resources: []string{
				"clusternetworkpolicies",
				"adminnetworkpolicies",
				"baselineadminnetworkpolicies",
			},
			Verbs: []string{
				"get",
				"list",
				"watch",
			},
		},
		{
			// Core Calico backing storage.
			APIGroups: []string{"projectcalico.org", "crd.projectcalico.org"},
			Resources: []string{
				"globalnetworkpolicies",
				"networkpolicies",
				"stagedkubernetesnetworkpolicies",
				"stagednetworkpolicies",
				"stagedglobalnetworkpolicies",
				"caliconodestatuses",
				"clusterinformations",
				"hostendpoints",
				"globalnetworksets",
				"networksets",
				"bgpconfigurations",
				"bgpfilters",
				"bgppeers",
				"felixconfigurations",
				"kubecontrollersconfigurations",
				"ippools",
				"ipreservations",
				"ipamblocks",
				"blockaffinities",
				"ipamconfigs",
				"tiers",
			},
			Verbs: []string{
				"get",
				"list",
				"watch",
				"create",
				"update",
				"delete",
				"patch",
			},
		},
	}
	//nolint:staticcheck // Ignore QF1001 could apply De Morgan's law
	if c.cfg.KubernetesVersion == nil || !(c.cfg.KubernetesVersion != nil && c.cfg.KubernetesVersion.Major < 2 && c.cfg.KubernetesVersion.Minor < 30) {
		// If the kubernetes version is higher than 1.30, we add extra RBAC permissions to allow establishing watches.
		// https://v1-30.docs.kubernetes.io/docs/reference/access-authn-authz/validating-admission-policy/
		rules = append(rules, rbacv1.PolicyRule{
			// Kubernetes validating admission policy resources.
			APIGroups: []string{"admissionregistration.k8s.io"},
			Resources: []string{
				"validatingadmissionpolicies",
				"validatingadmissionpolicybindings",
			},
			Verbs: []string{
				"get",
				"list",
				"watch",
			},
		})
	}
	return &rbacv1.ClusterRole{
		TypeMeta: metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name: "calico-crds",
		},
		Rules: rules,
	}
}

// calicoCustomResourcesClusterRoleBinding creates a clusterrolebinding that applies calicoCustomResourcesClusterRole to
// the calico-apiserver service account.
//
// Both Calico and Calico Enterprise, with the same name.
func (c *apiServerComponent) calicoCustomResourcesClusterRoleBinding() *rbacv1.ClusterRoleBinding {
	return &rbacv1.ClusterRoleBinding{
		TypeMeta: metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name: "calico-apiserver-access-calico-crds",
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      "ServiceAccount",
				Name:      APIServerServiceAccountName,
				Namespace: APIServerNamespace,
			},
		},
		RoleRef: rbacv1.RoleRef{
			Kind:     "ClusterRole",
			Name:     "calico-crds",
			APIGroup: "rbac.authorization.k8s.io",
		},
	}
}

// authClusterRole returns the cluster role to create, and one to delete, based on the variant.
//
// Both Calico and Calico Enterprise, with different names.
func (c *apiServerComponent) authClusterRole() client.Object {
	rules := []rbacv1.PolicyRule{
		{
			APIGroups: []string{
				"",
			},
			Resources: []string{
				"configmaps",
			},
			Verbs: []string{
				"list",
				"watch",
			},
			ResourceNames: []string{
				"extension-apiserver-authentication",
			},
		},
		{
			APIGroups: []string{
				"rbac.authorization.k8s.io",
			},
			Resources: []string{
				"clusterroles",
				"clusterrolebindings",
				"roles",
				"rolebindings",
			},
			Verbs: []string{
				"get",
				"list",
				"watch",
			},
		},
	}

	if c.cfg.OpenShift {
		rules = append(rules, rbacv1.PolicyRule{
			APIGroups:     []string{"security.openshift.io"},
			Resources:     []string{"securitycontextconstraints"},
			Verbs:         []string{"use"},
			ResourceNames: []string{securitycontextconstraints.Privileged},
		},
			// Starting with OCP 4.20, these permissions are required at startup when it sets up watches.
			rbacv1.PolicyRule{
				APIGroups: []string{"config.openshift.io"},
				Resources: []string{"infrastructures"},
				Verbs:     []string{"get", "list", "watch"},
			},
		)
	}

	return &rbacv1.ClusterRole{
		TypeMeta: metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name: "calico-extension-apiserver-auth-access",
		},
		Rules: rules,
	}
}

// multiTenantSecretsRBAC provides the tigera API server with the ability to read secrets on the cluster.
// This is needed in multi-tenant management clusters only, in order to read tenant secrets for signing managed cluster certificates.
func (c *apiServerComponent) multiTenantSecretsRBAC() []client.Object {
	return TunnelSecretRBAC(APIServerSecretsRBACName, APIServerServiceAccountName, c.cfg.ManagementCluster, true)
}

// secretsRBAC provides the tigera API server with the ability to read secrets from the API server's namespace.
func (c *apiServerComponent) secretsRBAC() []client.Object {
	return TunnelSecretRBAC(APIServerSecretsRBACName, APIServerServiceAccountName, c.cfg.ManagementCluster, false)
}

// authClusterRoleBinding returns a clusterrolebinding to create, and a clusterrolebinding to delete.
//
// Both Calico and Calico Enterprise, with different names.
func (c *apiServerComponent) authClusterRoleBinding() client.Object {
	return &rbacv1.ClusterRoleBinding{
		TypeMeta: metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name: "calico-extension-apiserver-auth-access",
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      "ServiceAccount",
				Name:      APIServerServiceAccountName,
				Namespace: APIServerNamespace,
			},
		},
		RoleRef: rbacv1.RoleRef{
			Kind:     "ClusterRole",
			Name:     "calico-extension-apiserver-auth-access",
			APIGroup: "rbac.authorization.k8s.io",
		},
	}
}

// webhookReaderClusterRole returns a ClusterRole to read MutatingWebhookConfigurations and ValidatingWebhookConfigurations and an
// equivalent one to delete based on variant.
//
// Both Calico and Calico Enterprise, with different names.
func (c *apiServerComponent) webhookReaderClusterRole() client.Object {
	return &rbacv1.ClusterRole{
		TypeMeta: metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name: "calico-webhook-reader",
		},
		Rules: []rbacv1.PolicyRule{
			{
				APIGroups: []string{
					"admissionregistration.k8s.io",
				},
				Resources: []string{
					"mutatingwebhookconfigurations", "validatingwebhookconfigurations",
				},
				Verbs: []string{
					"get",
					"list",
					"watch",
				},
			},
		},
	}
}

// webhookReaderClusterRoleBinding binds the apiserver ServiceAccount to the webhook-reader. It also returns a version to
// delete, based on variant.
//
// Both Calico and Calico Enterprise, with different names.
func (c *apiServerComponent) webhookReaderClusterRoleBinding() client.Object {
	return &rbacv1.ClusterRoleBinding{
		TypeMeta:   metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{Name: "calico-apiserver-webhook-reader"},
		Subjects: []rbacv1.Subject{
			{
				Kind:      "ServiceAccount",
				Name:      APIServerServiceAccountName,
				Namespace: APIServerNamespace,
			},
		},
		RoleRef: rbacv1.RoleRef{
			Kind:     "ClusterRole",
			Name:     "calico-webhook-reader",
			APIGroup: "rbac.authorization.k8s.io",
		},
	}
}

func getContainerPort(cfg *APIServerConfiguration, containerName ContainerName) *operatorv1.APIServerDeploymentContainerPort {
	// Try to get the override port
	if cfg != nil &&
		cfg.APIServer != nil &&
		cfg.APIServer.APIServerDeployment != nil &&
		cfg.APIServer.APIServerDeployment.Spec != nil &&
		cfg.APIServer.APIServerDeployment.Spec.Template != nil &&
		cfg.APIServer.APIServerDeployment.Spec.Template.Spec != nil {

		containers := cfg.APIServer.APIServerDeployment.Spec.Template.Spec.Containers
		if len(containers) > 0 {
			for _, container := range containers {
				if container.Name == string(containerName) && len(container.Ports) > 0 {
					return &operatorv1.APIServerDeploymentContainerPort{
						ContainerPort: container.Ports[0].ContainerPort,
						Name:          container.Ports[0].Name,
					}
				}
			}
		}
	}

	// If no override port is found, return the default port
	switch containerName {
	case APIServerContainerName:
		return &operatorv1.APIServerDeploymentContainerPort{ContainerPort: APIServerPort}
	case TigeraAPIServerQueryServerContainerName:
		return &operatorv1.APIServerDeploymentContainerPort{ContainerPort: QueryServerPort}
	case L7AdmissionControllerContainerName:
		return &operatorv1.APIServerDeploymentContainerPort{ContainerPort: L7AdmissionControllerPort}
	}

	return nil
}

// apiServerService creates a service backed by the API server and - for enterprise - query server.
func (c *apiServerComponent) apiServerService() *corev1.Service {
	apiServerTargetPort := getContainerPort(c.cfg, APIServerContainerName)
	queryServerTargetPort := getContainerPort(c.cfg, TigeraAPIServerQueryServerContainerName)
	l7AdmissionControllerTargetPort := getContainerPort(c.cfg, L7AdmissionControllerContainerName)

	s := &corev1.Service{
		TypeMeta: metav1.TypeMeta{Kind: "Service", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      APIServerServiceName,
			Namespace: APIServerNamespace,
			Labels:    map[string]string{"k8s-app": QueryserverServiceName},
		},
		Spec: corev1.ServiceSpec{
			Ports: []corev1.ServicePort{
				{
					Name:       APIServerPortName,
					Port:       443,
					Protocol:   corev1.ProtocolTCP,
					TargetPort: intstr.FromInt32(apiServerTargetPort.ContainerPort),
				},
			},
			Selector: map[string]string{
				"apiserver": "true",
			},
		},
	}

	if c.cfg.Installation.Variant.IsEnterprise() {
		// Add port for queryserver if enterprise.
		s.Spec.Ports = append(s.Spec.Ports,
			corev1.ServicePort{
				Name:       QueryServerPortName,
				Port:       QueryServerPort,
				Protocol:   corev1.ProtocolTCP,
				TargetPort: intstr.FromInt32(queryServerTargetPort.ContainerPort),
			},
		)
	}

	if c.cfg.IsSidecarInjectionEnabled() {
		s.Spec.Ports = append(s.Spec.Ports,
			corev1.ServicePort{
				Name:       L7AdmissionControllerPortName,
				Port:       L7AdmissionControllerPort,
				Protocol:   corev1.ProtocolTCP,
				TargetPort: intstr.FromInt32(l7AdmissionControllerTargetPort.ContainerPort),
			},
		)
	}

	return s
}

// apiServer creates a deployment containing the API and query servers.
func (c *apiServerComponent) apiServerDeployment() *appsv1.Deployment {
	hostNetwork := c.hostNetwork()
	dnsPolicy := corev1.DNSClusterFirst
	deploymentStrategyType := appsv1.RollingUpdateDeploymentStrategyType
	if hostNetwork {
		// Adjust DNS policy so we can access in-cluster services.
		dnsPolicy = corev1.DNSClusterFirstWithHostNet
		deploymentStrategyType = appsv1.RecreateDeploymentStrategyType
	}

	annotations := map[string]string{
		c.cfg.TLSKeyPair.HashAnnotationKey(): c.cfg.TLSKeyPair.HashAnnotationValue(),
	}

	var initContainers []corev1.Container
	if c.cfg.TLSKeyPair.UseCertificateManagement() {
		if c.cfg.RequiresAggregationServer {
			// Only include the API server init container if we're running the aggregation API server!
			initContainerAPIServer := c.cfg.TLSKeyPair.InitContainer(APIServerNamespace, c.apiServerContainer().SecurityContext)
			initContainerAPIServer.Name = fmt.Sprintf("%s-%s", CalicoAPIServerTLSSecretName, certificatemanagement.CSRInitContainerName)
			initContainers = append(initContainers, initContainerAPIServer)
		}

		initContainerQueryServer := c.cfg.QueryServerTLSKeyPairCertificateManagementOnly.InitContainer(APIServerNamespace, c.queryServerContainer().SecurityContext)
		annotations[c.cfg.QueryServerTLSKeyPairCertificateManagementOnly.HashAnnotationKey()] = c.cfg.QueryServerTLSKeyPairCertificateManagementOnly.HashAnnotationValue()
		initContainers = append(initContainers, initContainerQueryServer)
	}

	// Determine which containers to run.
	containers := []corev1.Container{}
	if c.cfg.RequiresAggregationServer {
		containers = append(containers, c.apiServerContainer())
	}
	if c.cfg.IsSidecarInjectionEnabled() {
		containers = append(containers, c.l7AdmissionControllerContainer())
	}
	if c.cfg.Installation.Variant.IsEnterprise() {
		containers = append(containers, c.queryServerContainer())
	}

	d := &appsv1.Deployment{
		TypeMeta: metav1.TypeMeta{Kind: "Deployment", APIVersion: "apps/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      APIServerName,
			Namespace: APIServerNamespace,
			Labels: map[string]string{
				"apiserver": "true",
			},
		},
		Spec: appsv1.DeploymentSpec{
			Replicas: c.cfg.Installation.ControlPlaneReplicas,
			Strategy: appsv1.DeploymentStrategy{
				Type: deploymentStrategyType,
			},
			Selector: c.deploymentSelector(),
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Name:      APIServerName,
					Namespace: APIServerNamespace,
					Labels: map[string]string{
						"apiserver": "true",
					},
					Annotations: annotations,
				},
				Spec: corev1.PodSpec{
					DNSPolicy:          dnsPolicy,
					NodeSelector:       c.cfg.Installation.ControlPlaneNodeSelector,
					HostNetwork:        hostNetwork,
					ServiceAccountName: APIServerServiceAccountName,
					Tolerations:        c.tolerations(),
					ImagePullSecrets:   secret.GetReferenceList(c.cfg.PullSecrets),
					InitContainers:     initContainers,
					Containers:         containers,
					Volumes:            c.apiServerVolumes(),
				},
			},
		},
	}

	if c.cfg.Installation.ControlPlaneReplicas != nil && *c.cfg.Installation.ControlPlaneReplicas > 1 {
		d.Spec.Template.Spec.Affinity = podaffinity.NewPodAntiAffinity(APIServerName, []string{APIServerNamespace, "tigera-system", "calico-apiserver"})
	}

	if c.cfg.Installation.Variant.IsEnterprise() {
		if c.cfg.TrustedBundle != nil {
			trustedBundleHashAnnotations := c.cfg.TrustedBundle.HashAnnotations()
			for k, v := range trustedBundleHashAnnotations {
				d.Spec.Template.Annotations[k] = v
			}
		}
	}

	if overrides := c.cfg.APIServer.APIServerDeployment; overrides != nil {
		rcomp.ApplyDeploymentOverrides(d, overrides)
	}

	return d
}

// apiServer creates a MutatingWebhookConfiguration for sidecars.
func (c *apiServerComponent) sidecarMutatingWebhookConfig() *admregv1.MutatingWebhookConfiguration {
	var cacert []byte
	svcPort := getContainerPort(c.cfg, L7AdmissionControllerContainerName).ContainerPort

	svcpath := "/sidecar-webhook"
	svcref := admregv1.ServiceReference{
		Name:      QueryserverServiceName,
		Namespace: QueryserverNamespace,
		Path:      &svcpath,
		Port:      &svcPort,
	}
	failpol := admregv1.Fail
	labelsel := metav1.LabelSelector{
		MatchLabels: map[string]string{
			"applicationlayer.projectcalico.org/sidecar": "true",
		},
	}
	rules := []admregv1.RuleWithOperations{
		{
			Rule: admregv1.Rule{
				APIGroups:   []string{""},
				APIVersions: []string{"v1"},
				Resources:   []string{"pods"},
			},
			Operations: []admregv1.OperationType{admregv1.Create},
		},
	}
	sidefx := admregv1.SideEffectClassNone
	if !c.cfg.TLSKeyPair.UseCertificateManagement() {
		cacert = c.cfg.TLSKeyPair.GetIssuer().GetCertificatePEM()
	} else {
		cacert = c.cfg.Installation.CertificateManagement.CACert
	}
	mwc := admregv1.MutatingWebhookConfiguration{
		TypeMeta: metav1.TypeMeta{
			Kind:       "MutatingWebhookConfiguration",
			APIVersion: "admissionregistration.k8s.io/v1",
		},
		ObjectMeta: metav1.ObjectMeta{Name: common.SidecarMutatingWebhookConfigName},
		Webhooks: []admregv1.MutatingWebhook{
			{
				AdmissionReviewVersions: []string{"v1"},
				ClientConfig: admregv1.WebhookClientConfig{
					Service:  &svcref,
					CABundle: cacert,
				},
				Name:           "sidecar.projectcalico.org",
				FailurePolicy:  &failpol,
				ObjectSelector: &labelsel,
				Rules:          rules,
				SideEffects:    &sidefx,
			},
		},
	}

	return &mwc
}

func (c *apiServerComponent) hostNetwork() bool {
	if c.cfg.ForceHostNetwork {
		return true
	}
	return HostNetworkRequired(c.cfg.Installation)
}

func HostNetworkRequired(installation *operatorv1.InstallationSpec) bool {
	if (installation.KubernetesProvider.IsEKS() || installation.KubernetesProvider.IsTKG()) &&
		installation.CNI != nil &&
		installation.CNI.Type == operatorv1.PluginCalico {
		// Workaround the fact that webhooks don't work for non-host-networked pods
		// when in this networking mode on EKS or TKG, because the control plane nodes don't run
		// Calico.
		return true
	}
	return false
}

// apiServerContainer creates the API server container.
func (c *apiServerComponent) apiServerContainer() corev1.Container {
	volumeMounts := []corev1.VolumeMount{
		c.cfg.TLSKeyPair.VolumeMount(c.SupportedOSType()),
	}
	if c.cfg.Installation.Variant.IsEnterprise() {
		volumeMounts = append(volumeMounts,
			corev1.VolumeMount{Name: auditLogsVolumeName, MountPath: "/var/log/calico/audit"},
			corev1.VolumeMount{Name: auditPolicyVolumeName, MountPath: "/etc/tigera/audit"},
		)
	}

	env := []corev1.EnvVar{
		{Name: "DATASTORE_TYPE", Value: "kubernetes"},
	}

	if c.cfg.MultiTenant {
		env = append(env, corev1.EnvVar{Name: "MULTI_TENANT_ENABLED", Value: "true"})
	}

	if c.hostNetwork() {
		env = append(env, c.cfg.K8SServiceEndpoint.EnvVars()...)
	} else {
		env = append(env, c.cfg.K8SServiceEndpointPodNetwork.EnvVars()...)
	}

	// set Log_LEVEL for apiserver container
	if logging := c.cfg.APIServer.Logging; logging != nil &&
		logging.APIServerLogging != nil && logging.APIServerLogging.LogSeverity != nil {
		env = append(env,
			corev1.EnvVar{Name: "LOG_LEVEL", Value: strings.ToLower(string(*logging.APIServerLogging.LogSeverity))})
	} else {
		// set default LOG_LEVEL to info when not set by the user
		env = append(env, corev1.EnvVar{Name: "LOG_LEVEL", Value: "info"})
	}

	if c.cfg.Installation.CalicoNetwork != nil && c.cfg.Installation.CalicoNetwork.MultiInterfaceMode != nil {
		env = append(env, corev1.EnvVar{Name: "MULTI_INTERFACE_MODE", Value: c.cfg.Installation.CalicoNetwork.MultiInterfaceMode.Value()})
	}

	apiServerTargetPort := getContainerPort(c.cfg, APIServerContainerName).ContainerPort

	apiServer := corev1.Container{
		Name:         string(APIServerContainerName),
		Image:        c.calicoImage,
		Command:      []string{components.CalicoBinaryPath, "component", "apiserver"},
		Args:         c.startUpArgs(),
		Env:          env,
		VolumeMounts: volumeMounts,
		ReadinessProbe: &corev1.Probe{
			ProbeHandler: corev1.ProbeHandler{
				HTTPGet: &corev1.HTTPGetAction{
					Path:   "/readyz",
					Port:   intstr.FromInt32(apiServerTargetPort),
					Scheme: corev1.URISchemeHTTPS,
				},
			},
			// We expect the readiness probe to contact kube-apiserver.
			// A longer period is chosen to minimize load.
			PeriodSeconds: 60,
		},
	}
	// In case of OpenShift, apiserver needs privileged access to write audit logs to host path volume.
	// Audit logs are owned by root on hosts so we need to be root user and group. Audit logs are supported only in Enterprise version.
	if c.cfg.Installation.Variant.IsEnterprise() {
		apiServer.SecurityContext = securitycontext.NewRootContext(c.cfg.OpenShift)
	} else {
		apiServer.SecurityContext = securitycontext.NewNonRootContext()
	}

	return apiServer
}

func (c *apiServerComponent) startUpArgs() []string {
	apiServerTargetPort := getContainerPort(c.cfg, APIServerContainerName).ContainerPort

	args := []string{
		fmt.Sprintf("--secure-port=%d", apiServerTargetPort),
		fmt.Sprintf("--tls-private-key-file=%s", c.cfg.TLSKeyPair.VolumeMountKeyFilePath()),
		fmt.Sprintf("--tls-cert-file=%s", c.cfg.TLSKeyPair.VolumeMountCertificateFilePath()),
	}

	if c.cfg.Installation.Variant.IsEnterprise() {
		args = append(args,
			"--audit-policy-file=/etc/tigera/audit/policy.conf",
			"--audit-log-path=/var/log/calico/audit/tsee-audit.log",
		)
	}

	if c.cfg.ManagementCluster != nil {
		args = append(args, "--enable-managed-clusters-create-api=true")
		if c.cfg.ManagementCluster.Spec.Address != "" {
			args = append(args, fmt.Sprintf("--managementClusterAddr=%s", c.cfg.ManagementCluster.Spec.Address))
		}
		if c.cfg.ManagementCluster.Spec.TLS != nil && c.cfg.ManagementCluster.Spec.TLS.SecretName != "" {
			if c.cfg.ManagementCluster.Spec.TLS.SecretName == ManagerTLSSecretName {
				args = append(args, "--managementClusterCAType=Public")
			}
			args = append(args, fmt.Sprintf("--tunnelSecretName=%s", c.cfg.ManagementCluster.Spec.TLS.SecretName))
		}
	}
	if c.cfg.KubernetesVersion != nil && c.cfg.KubernetesVersion.Major < 2 && c.cfg.KubernetesVersion.Minor < 30 {
		// Disable this API as it is not available by default. If we don't, the server fails to start, due to trying to
		// establish watches for unavailable APIs.
		args = append(args, "--enable-validating-admission-policy=false")
	}
	return args
}

// queryServerContainer creates the query server container.
func (c *apiServerComponent) queryServerContainer() corev1.Container {
	queryServerTargetPort := getContainerPort(c.cfg, TigeraAPIServerQueryServerContainerName).ContainerPort

	var tlsSecret certificatemanagement.KeyPairInterface
	if c.cfg.QueryServerTLSKeyPairCertificateManagementOnly != nil {
		tlsSecret = c.cfg.QueryServerTLSKeyPairCertificateManagementOnly
	} else {
		tlsSecret = c.cfg.TLSKeyPair
	}
	env := []corev1.EnvVar{
		{Name: "DATASTORE_TYPE", Value: "kubernetes"},
		{Name: "LISTEN_ADDR", Value: fmt.Sprintf(":%d", queryServerTargetPort)},
		{Name: "TLS_CERT", Value: fmt.Sprintf("/%s/tls.crt", tlsSecret.GetName())},
		{Name: "TLS_KEY", Value: fmt.Sprintf("/%s/tls.key", tlsSecret.GetName())},
	}
	if c.cfg.TrustedBundle != nil {
		env = append(env, corev1.EnvVar{Name: "TRUSTED_BUNDLE_PATH", Value: c.cfg.TrustedBundle.MountPath()})
	}

	if c.hostNetwork() {
		env = append(env, c.cfg.K8SServiceEndpoint.EnvVars()...)
	} else {
		env = append(env, c.cfg.K8SServiceEndpointPodNetwork.EnvVars()...)
	}

	if c.cfg.Installation.CalicoNetwork != nil && c.cfg.Installation.CalicoNetwork.MultiInterfaceMode != nil {
		env = append(env, corev1.EnvVar{Name: "MULTI_INTERFACE_MODE", Value: c.cfg.Installation.CalicoNetwork.MultiInterfaceMode.Value()})
	}

	if c.cfg.KeyValidatorConfig != nil {
		env = append(env, c.cfg.KeyValidatorConfig.RequiredEnv("")...)
	}

	linseedURL := relasticsearch.LinseedEndpoint(c.SupportedOSType(), c.cfg.ClusterDomain, ElasticsearchNamespace, c.cfg.ManagementClusterConnection != nil, false)
	env = append(env,
		corev1.EnvVar{Name: "LINSEED_URL", Value: linseedURL},
		corev1.EnvVar{Name: "LINSEED_CLIENT_CERT", Value: fmt.Sprintf("/%s/tls.crt", tlsSecret.GetName())},
		corev1.EnvVar{Name: "LINSEED_CLIENT_KEY", Value: fmt.Sprintf("/%s/tls.key", tlsSecret.GetName())},
	)
	if c.cfg.ManagementClusterConnection != nil {
		env = append(env,
			corev1.EnvVar{Name: "CLUSTER_ID", Value: ""},
			corev1.EnvVar{Name: "LINSEED_TOKEN", Value: GetLinseedTokenPath(true)},
		)
	}
	if c.cfg.TrustedBundle != nil {
		env = append(env, corev1.EnvVar{Name: "LINSEED_CA", Value: c.cfg.TrustedBundle.MountPath()})
	}

	// set LogLEVEL for queryserver container
	if logging := c.cfg.APIServer.Logging; logging != nil &&
		logging.QueryServerLogging != nil && logging.QueryServerLogging.LogSeverity != nil {
		env = append(env,
			corev1.EnvVar{Name: "LOGLEVEL", Value: strings.ToLower(string(*logging.QueryServerLogging.LogSeverity))})
	} else {
		// set default LOGLEVEL to info when not set by the user
		env = append(env, corev1.EnvVar{Name: "LOGLEVEL", Value: "info"})
	}

	volumeMounts := []corev1.VolumeMount{
		tlsSecret.VolumeMount(c.SupportedOSType()),
	}
	if c.cfg.TrustedBundle != nil {
		volumeMounts = append(volumeMounts, c.cfg.TrustedBundle.VolumeMounts(c.SupportedOSType())...)
	}
	if c.cfg.ManagementClusterConnection != nil {
		volumeMounts = append(volumeMounts, corev1.VolumeMount{
			Name:      LinseedTokenVolumeName,
			MountPath: LinseedVolumeMountPath,
		})
	}

	container := corev1.Container{
		Name:    string(TigeraAPIServerQueryServerContainerName),
		Image:   c.calicoImage,
		Command: []string{components.CalicoBinaryPath, "component", "queryserver"},
		Env:     env,
		LivenessProbe: &corev1.Probe{
			ProbeHandler: corev1.ProbeHandler{
				HTTPGet: &corev1.HTTPGetAction{
					Path:   "/version",
					Port:   intstr.FromInt32(queryServerTargetPort),
					Scheme: corev1.URISchemeHTTPS,
				},
			},
			InitialDelaySeconds: 90,
		},
		SecurityContext: securitycontext.NewNonRootContext(),
		VolumeMounts:    volumeMounts,
	}
	return container
}

func (c *apiServerComponent) externalLinseedRoleBinding() *rbacv1.RoleBinding {
	return &rbacv1.RoleBinding{
		TypeMeta: metav1.TypeMeta{Kind: "RoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "tigera-linseed",
			Namespace: APIServerNamespace,
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "ClusterRole",
			Name:     TigeraLinseedSecretsClusterRole,
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

// apiServerVolumes creates the volumes used by the API server deployment.
func (c *apiServerComponent) apiServerVolumes() []corev1.Volume {
	volumes := []corev1.Volume{
		c.cfg.TLSKeyPair.Volume(),
	}
	if c.cfg.QueryServerTLSKeyPairCertificateManagementOnly != nil {
		volumes = append(volumes, c.cfg.QueryServerTLSKeyPairCertificateManagementOnly.Volume())
	}

	if c.cfg.Installation.Variant.IsEnterprise() && c.cfg.RequiresAggregationServer {
		// Only include these volumes if we're running the aggregation API server, since audit logging is done through the
		// main API server otherwise.
		volumes = append(volumes,
			corev1.Volume{
				Name: auditLogsVolumeName,
				VolumeSource: corev1.VolumeSource{
					HostPath: &corev1.HostPathVolumeSource{
						Path: "/var/log/calico/audit",
						Type: ptr.To(corev1.HostPathDirectoryOrCreate),
					},
				},
			},
			corev1.Volume{
				Name: auditPolicyVolumeName,
				VolumeSource: corev1.VolumeSource{
					ConfigMap: &corev1.ConfigMapVolumeSource{
						LocalObjectReference: corev1.LocalObjectReference{Name: auditPolicyVolumeName},
						Items: []corev1.KeyToPath{
							{
								Key:  "config",
								Path: "policy.conf",
							},
						},
					},
				},
			},
		)
	}

	if c.cfg.Installation.Variant.IsEnterprise() && c.cfg.TrustedBundle != nil {
		volumes = append(volumes, c.cfg.TrustedBundle.Volume())
	}

	if c.cfg.ManagementClusterConnection != nil {
		// Optional: the Secret is delivered over the Guardian tunnel, which can't be
		// established until calico-apiserver is Ready.
		volumes = append(volumes, corev1.Volume{
			Name: LinseedTokenVolumeName,
			VolumeSource: corev1.VolumeSource{
				Secret: &corev1.SecretVolumeSource{
					SecretName: fmt.Sprintf(LinseedTokenSecret, "calico-apiserver"),
					Items:      []corev1.KeyToPath{{Key: LinseedTokenKey, Path: LinseedTokenSubPath}},
					Optional:   ptr.To(true),
				},
			},
		})
	}

	return volumes
}

// tolerations creates the tolerations used by the API server deployment.
func (c *apiServerComponent) tolerations() []corev1.Toleration {
	if c.hostNetwork() {
		return rmeta.TolerateBootstrap
	}
	tolerations := append(c.cfg.Installation.ControlPlaneTolerations, rmeta.TolerateControlPlane...)
	if c.cfg.Installation.KubernetesProvider.IsGKE() {
		tolerations = append(tolerations, rmeta.TolerateGKEARM64NoSchedule)
	}
	return tolerations
}

// tigeraAPIServerClusterRole creates a clusterrole that gives permissions to access backing CRDs
//
// Calico Enterprise only
func (c *apiServerComponent) tigeraAPIServerClusterRole() *rbacv1.ClusterRole {
	rules := []rbacv1.PolicyRule{
		{
			// Read access to Linseed policy activity data for queryserver enrichment.
			APIGroups: []string{"linseed.tigera.io"},
			Resources: []string{"policyactivity"},
			Verbs:     []string{"get"},
		},
		{
			// Calico Enterprise backing storage.
			APIGroups: []string{"projectcalico.org", "crd.projectcalico.org"},
			Resources: []string{
				"alertexceptions",
				"bfdconfigurations",
				"deeppacketinspections",
				"deeppacketinspections/status",
				"egressgatewaypolicies",
				"externalnetworks",
				"globalalerts",
				"globalalerts/status",
				"globalalerttemplates",
				"globalreports",
				"globalreports/status",
				"globalreporttypes",
				"globalthreatfeeds",
				"globalthreatfeeds/status",
				"licensekeys",
				"managedclusters",
				"managedclusters/status",
				"networks",
				"packetcaptures",
				"packetcaptures/status",
				"policyrecommendationscopes",
				"policyrecommendationscopes/status",
				"remoteclusterconfigurations",
				"securityeventwebhooks",
				"securityeventwebhooks/status",
				"uisettings",
				"uisettingsgroups",
			},
			Verbs: []string{
				"get",
				"list",
				"watch",
				"create",
				"update",
				"delete",
				"patch",
			},
		},
		{
			// The queryserver's RBAC calculator needs to list tiers,
			// uisettingsgroups, and managedclusters via the aggregated
			// API to evaluate user permissions for the /policies endpoint.
			APIGroups: []string{"projectcalico.org"},
			Resources: []string{
				"tiers",
				"uisettingsgroups",
				"managedclusters",
			},
			Verbs: []string{"get", "list", "watch"},
		},
		{
			// Required by the AuthorizationReview calculator in queryserver to evaluate
			// RBAC permissions for users.
			APIGroups: []string{"rbac.authorization.k8s.io"},
			Resources: []string{
				"clusterroles",
				"clusterrolebindings",
				"roles",
				"rolebindings",
			},
			Verbs: []string{"get", "list", "watch"},
		},
	}

	return &rbacv1.ClusterRole{
		TypeMeta: metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name: APIServerName,
		},
		Rules: rules,
	}
}

// tigeraAPIServerClusterRoleBinding creates a clusterrolebinding that applies tigeraAPIServerClusterRole to
// the calico-apiserver service account. This is the aggregated API server's own identity, which always runs
// in calico-system - including on multi-tenant management clusters, where the API server is a single
// cluster-scoped component rather than a per-tenant one.
//
// Calico Enterprise only
func (c *apiServerComponent) tigeraAPIServerClusterRoleBinding() *rbacv1.ClusterRoleBinding {
	return &rbacv1.ClusterRoleBinding{
		TypeMeta: metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name: APIServerName,
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      "ServiceAccount",
				Name:      APIServerServiceAccountName,
				Namespace: APIServerNamespace,
			},
		},
		RoleRef: rbacv1.RoleRef{
			Kind:     "ClusterRole",
			Name:     APIServerName,
			APIGroup: "rbac.authorization.k8s.io",
		},
	}
}

// tierGetterClusterRole creates a clusterrole that gives permissions to get tiers.
func (c *apiServerComponent) tierGetterClusterRole() *rbacv1.ClusterRole {
	return &rbacv1.ClusterRole{
		TypeMeta: metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name: "calico-tier-getter",
		},
		Rules: []rbacv1.PolicyRule{
			{
				APIGroups: []string{"projectcalico.org"},
				Resources: []string{
					"tiers",
				},
				Verbs: []string{"get"},
			},
		},
	}
}

// kubeControllerMgrTierGetterClusterRoleBinding creates a rolebinding that allows the k8s kube-controller manager to
// get tiers. In k8s 1.15+, cascading resource deletions (for instance pods for a replicaset) failed
// due to k8s kube-controller not having permissions to get tiers.
func (c *apiServerComponent) kubeControllerMgrTierGetterClusterRoleBinding() *rbacv1.ClusterRoleBinding {
	return &rbacv1.ClusterRoleBinding{
		TypeMeta: metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name: "calico-tier-getter",
		},
		RoleRef: rbacv1.RoleRef{
			Kind:     "ClusterRole",
			Name:     "calico-tier-getter",
			APIGroup: "rbac.authorization.k8s.io",
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:     "User",
				Name:     "system:kube-controller-manager",
				APIGroup: "rbac.authorization.k8s.io",
			},
		},
	}
}

// uiSettingsGroupGetterClusterRole creates a clusterrole that gives permissions to get uisettingsgroups.
//
// Calico Enterprise only
func (c *apiServerComponent) uiSettingsGroupGetterClusterRole() *rbacv1.ClusterRole {
	return &rbacv1.ClusterRole{
		TypeMeta: metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name: "calico-uisettingsgroup-getter",
		},
		Rules: []rbacv1.PolicyRule{
			{
				APIGroups: []string{"projectcalico.org"},
				Resources: []string{
					"uisettingsgroups",
				},
				Verbs: []string{"get"},
			},
		},
	}
}

// kubeControllerManagerUISettingsGroupGetterClusterRoleBinding creates a rolebinding that allows the k8s kube-controller
// manager to get uisettingsgroups.
//
// In k8s 1.15+, cascading resource deletions (for instance pods for a replicaset) failed due to k8s kube-controller
// not having permissions to get tiers. UISettings and UISettingsGroups RBAC works in a similar way to tiered policy
// and so we need similar RBAC for UISettingsGroups.
//
// Calico Enterprise only
func (c *apiServerComponent) kubeControllerManagerUISettingsGroupGetterClusterRoleBinding() *rbacv1.ClusterRoleBinding {
	return &rbacv1.ClusterRoleBinding{
		TypeMeta: metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name: "calico-uisettingsgroup-getter",
		},
		RoleRef: rbacv1.RoleRef{
			Kind:     "ClusterRole",
			Name:     "calico-uisettingsgroup-getter",
			APIGroup: "rbac.authorization.k8s.io",
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:     "User",
				Name:     "system:kube-controller-manager",
				APIGroup: "rbac.authorization.k8s.io",
			},
		},
	}
}

// tigeraUserClusterRole returns a cluster role for a default Calico Enterprise user.
//
// Calico Enterprise only
func (c *apiServerComponent) tigeraUserClusterRole() *rbacv1.ClusterRole {
	rules := []rbacv1.PolicyRule{
		// List requests that the Tigera manager needs.
		{
			APIGroups: []string{
				"projectcalico.org",
				"networking.k8s.io",
				"extensions",
				"",
			},
			// Use both the networkpolicies and tier.networkpolicies resource types to ensure identical behavior
			// irrespective of the Calico RBAC scheme (see the ClusterRole "calico-tiered-policy-passthrough" for
			// more details).  Similar for all tiered policy resource types.
			Resources: []string{
				"tiers",
				"networkpolicies",
				"tier.networkpolicies",
				"globalnetworkpolicies",
				"tier.globalnetworkpolicies",
				"namespaces",
				"globalnetworksets",
				"networksets",
				"managedclusters",
				"stagedglobalnetworkpolicies",
				"tier.stagedglobalnetworkpolicies",
				"stagednetworkpolicies",
				"tier.stagednetworkpolicies",
				"stagedkubernetesnetworkpolicies",
				"policyrecommendationscopes",
			},
			Verbs: []string{"watch", "list"},
		},
		{
			APIGroups: []string{"policy.networking.k8s.io"},
			Resources: []string{
				"clusternetworkpolicies",
				"adminnetworkpolicies",
				"baselineadminnetworkpolicies",
			},
			Verbs: []string{"watch", "list"},
		},
		{
			APIGroups: []string{"projectcalico.org"},
			Resources: []string{"packetcaptures/files"},
			Verbs:     []string{"get"},
		},
		{
			APIGroups: []string{"projectcalico.org"},
			Resources: []string{"packetcaptures"},
			Verbs:     []string{"get", "list", "watch"},
		},
		// Allow the user to view Networks.
		{
			APIGroups: []string{"projectcalico.org"},
			Resources: []string{"networks"},
			Verbs:     []string{"get", "list", "watch"},
		},
		// Additional "list" requests required to view flows.
		{
			APIGroups: []string{""},
			Resources: []string{"pods"},
			Verbs:     []string{"list"},
		},
		// Additional "list" requests required to view serviceaccount labels.
		{
			APIGroups: []string{""},
			Resources: []string{"serviceaccounts"},
			Verbs:     []string{"list"},
		},
		// Access for WAF API to read in coreruleset configmap
		{
			APIGroups:     []string{""},
			Resources:     []string{"configmaps"},
			ResourceNames: []string{"coreruleset-default"},
			Verbs:         []string{"get"},
		},
		// Access to statistics.
		{
			APIGroups: []string{""},
			Resources: []string{"services/proxy"},
			ResourceNames: []string{
				"https:calico-api:8080", "calico-node-prometheus:9090",
			},
			Verbs: []string{"get", "create"},
		},
		// Access to policies in all tiers
		{
			APIGroups: []string{"projectcalico.org"},
			Resources: []string{"tiers"},
			Verbs:     []string{"get"},
		},
		// List and download the reports in the Tigera Secure manager.
		{
			APIGroups: []string{"projectcalico.org"},
			Resources: []string{"globalreports"},
			Verbs:     []string{"get", "list"},
		},
		{
			APIGroups: []string{"projectcalico.org"},
			Resources: []string{"globalreporttypes"},
			Verbs:     []string{"get"},
		},
		{
			APIGroups: []string{"projectcalico.org"},
			Resources: []string{"clusterinformations"},
			Verbs:     []string{"get", "list"},
		},
		// Access to hostendpoints from the UI ServiceGraph.
		{
			APIGroups: []string{"projectcalico.org"},
			Resources: []string{"hostendpoints"},
			Verbs:     []string{"get", "list"},
		},
		// List and view the threat defense configuration
		{
			APIGroups: []string{"projectcalico.org"},
			Resources: []string{
				"alertexceptions",
				"globalalerts",
				"globalalerts/status",
				"globalalerttemplates",
				"globalthreatfeeds",
				"globalthreatfeeds/status",
				"securityeventwebhooks",
			},
			Verbs: []string{"get", "watch", "list"},
		},
	}

	// User can:
	// - read UISettings in the cluster-settings group (non-cloud only)
	// - read and write UISettings in the user-settings group
	// Default settings group and settings are created in manager.go.
	// Calico Cloud exposes only per-user UISettings, so the cluster-settings group is omitted there.
	if c.cfg.Cloud {
		rules = append(rules,
			rbacv1.PolicyRule{
				APIGroups:     []string{"projectcalico.org"},
				Resources:     []string{"uisettingsgroups"},
				Verbs:         []string{"get"},
				ResourceNames: []string{"user-settings"},
			},
		)
	} else {
		rules = append(rules,
			rbacv1.PolicyRule{
				APIGroups:     []string{"projectcalico.org"},
				Resources:     []string{"uisettingsgroups"},
				Verbs:         []string{"get"},
				ResourceNames: []string{"cluster-settings", "user-settings"},
			},
			rbacv1.PolicyRule{
				APIGroups:     []string{"projectcalico.org"},
				Resources:     []string{"uisettingsgroups/data"},
				Verbs:         []string{"get", "list", "watch"},
				ResourceNames: []string{"cluster-settings"},
			},
		)
	}

	rules = append(rules, []rbacv1.PolicyRule{
		{
			APIGroups:     []string{"projectcalico.org"},
			Resources:     []string{"uisettingsgroups/data"},
			Verbs:         []string{"*"},
			ResourceNames: []string{"user-settings"},
		},
		// Allow the user to read applicationlayers to detect if WAF is enabled/disabled.
		{
			APIGroups: []string{"operator.tigera.io"},
			Resources: []string{"applicationlayers", "packetcaptureapis", "compliances", "intrusiondetections"},
			Verbs:     []string{"get"},
		},
		// Allow the user to read the gatewayapis CR to detect if Gateway API is enabled/disabled.
		{
			APIGroups: []string{"operator.tigera.io"},
			Resources: []string{"gatewayapis"},
			Verbs:     []string{"get"},
		},
		// Allow the user to read Gateways and HTTPRoutes to offer as WAF policy attach targets.
		{
			APIGroups: []string{"gateway.networking.k8s.io"},
			Resources: []string{"gateways", "httproutes"},
			Verbs:     []string{"get", "list", "watch"},
		},
		// Allow the user to view WAF policies, plugins, and validation policies.
		{
			APIGroups: []string{"applicationlayer.projectcalico.org"},
			Resources: []string{
				"globalwafpolicies",
				"globalwafplugins",
				"globalwafvalidationpolicies",
				"wafpolicies",
				"wafplugins",
				"wafvalidationpolicies",
			},
			Verbs: []string{"get", "watch", "list"},
		},
		{
			APIGroups: []string{"apps"},
			Resources: []string{"deployments"},
			Verbs:     []string{"get", "list", "watch"},
		},
		// Allow the user to read services to view WAF configuration.
		{
			APIGroups: []string{""},
			Resources: []string{"services"},
			Verbs:     []string{"get", "list", "watch"},
		},
		// Allow the user to read felixconfigurations to detect if wireguard and/or other features are enabled.
		{
			APIGroups: []string{"projectcalico.org"},
			Resources: []string{"felixconfigurations"},
			Verbs:     []string{"get", "list"},
		},
		// Allow the user to only view securityeventwebhooks.
		{
			APIGroups: []string{"projectcalico.org", "crd.projectcalico.org"},
			Resources: []string{"securityeventwebhooks"},
			Verbs:     []string{"get", "list"},
		},
	}...)

	// Privileges for lma.tigera.io have no effect on managed clusters.
	if c.cfg.ManagementClusterConnection == nil {
		// Access to flow logs, audit logs, and statistics.
		// Access to log into Kibana for oidc users.
		// Calico Cloud additionally grants access to runtime logs.
		resourceNames := []string{"flows", "audit*", "l7", "events", "dns", "waf", "kibana_login", "recommendations"}
		if c.cfg.Cloud {
			resourceNames = append([]string{"runtime"}, resourceNames...)
		}
		rules = append(rules, rbacv1.PolicyRule{
			APIGroups:     []string{"lma.tigera.io"},
			Resources:     []string{"*"},
			ResourceNames: resourceNames,
			Verbs:         []string{"get"},
		})
	}

	return &rbacv1.ClusterRole{
		TypeMeta: metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name: "tigera-ui-user",
		},
		Rules: rules,
	}
}

// tigeraNetworkAdminClusterRole returns a cluster role for a Tigera Secure manager network admin.
//
// Calico Enterprise only
func (c *apiServerComponent) tigeraNetworkAdminClusterRole() *rbacv1.ClusterRole {
	rules := []rbacv1.PolicyRule{
		// Full access to all network policies
		{
			APIGroups: []string{
				"projectcalico.org",
				"networking.k8s.io",
				"extensions",
			},
			// Use both the networkpolicies and tier.networkpolicies resource types to ensure identical behavior
			// irrespective of the Calico RBAC scheme (see the ClusterRole "calico-tiered-policy-passthrough" for
			// more details).  Similar for all tiered policy resource types.
			Resources: []string{
				"tiers",
				"networkpolicies",
				"tier.networkpolicies",
				"globalnetworkpolicies",
				"tier.globalnetworkpolicies",
				"stagedglobalnetworkpolicies",
				"tier.stagedglobalnetworkpolicies",
				"stagednetworkpolicies",
				"tier.stagednetworkpolicies",
				"stagedkubernetesnetworkpolicies",
				"globalnetworksets",
				"networksets",
				"managedclusters",
				"packetcaptures",
				"policyrecommendationscopes",
			},
			Verbs: []string{"create", "update", "delete", "patch", "get", "watch", "list"},
		},
		{
			APIGroups: []string{
				"policy.networking.k8s.io",
			},
			Resources: []string{
				"clusternetworkpolicies",
				"adminnetworkpolicies",
				"baselineadminnetworkpolicies",
			},
			Verbs: []string{"create", "update", "delete", "patch", "get", "watch", "list"},
		},
		{
			APIGroups: []string{"projectcalico.org"},
			Resources: []string{"packetcaptures/files"},
			Verbs:     []string{"get", "delete"},
		},
		// Allow the user to CRUD Networks.
		{
			APIGroups: []string{"projectcalico.org"},
			Resources: []string{"networks"},
			Verbs:     []string{"create", "update", "delete", "patch", "get", "watch", "list"},
		},
		// Additional "list" requests that the Tigera Secure manager needs
		{
			APIGroups: []string{""},
			Resources: []string{"namespaces"},
			Verbs:     []string{"watch", "list"},
		},
		// Additional "list" requests required to view flows.
		{
			APIGroups: []string{""},
			Resources: []string{"pods"},
			Verbs:     []string{"list"},
		},
		// Additional "list" requests required to view serviceaccount labels.
		{
			APIGroups: []string{""},
			Resources: []string{"serviceaccounts"},
			Verbs:     []string{"list"},
		},
		// Access for WAF API to read in coreruleset configmap
		{
			APIGroups:     []string{""},
			Resources:     []string{"configmaps"},
			ResourceNames: []string{"coreruleset-default"},
			Verbs:         []string{"get"},
		},
		// Access to statistics.
		{
			APIGroups: []string{""},
			Resources: []string{"services/proxy"},
			ResourceNames: []string{
				"https:calico-api:8080", "calico-node-prometheus:9090",
			},
			Verbs: []string{"get", "create"},
		},
		// Manage globalreport configuration, view report generation status, and list reports in the Tigera Secure manager.
		{
			APIGroups: []string{"projectcalico.org"},
			Resources: []string{"globalreports"},
			Verbs:     []string{"*"},
		},
		{
			APIGroups: []string{"projectcalico.org"},
			Resources: []string{"globalreports/status"},
			Verbs:     []string{"get", "list", "watch"},
		},
		// List and download the reports in the Tigera Secure manager.
		{
			APIGroups: []string{"projectcalico.org"},
			Resources: []string{"globalreporttypes"},
			Verbs:     []string{"get"},
		},
		// Access to cluster information containing Calico and EE versions from the UI.
		{
			APIGroups: []string{"projectcalico.org"},
			Resources: []string{"clusterinformations"},
			Verbs:     []string{"get", "list"},
		},
		// Access to hostendpoints from the UI ServiceGraph.
		{
			APIGroups: []string{"projectcalico.org"},
			Resources: []string{"hostendpoints"},
			Verbs:     []string{"get", "list"},
		},
		// Manage the threat defense configuration
		{
			APIGroups: []string{"projectcalico.org"},
			Resources: []string{
				"alertexceptions",
				"globalalerts",
				"globalalerts/status",
				"globalalerttemplates",
				"globalthreatfeeds",
				"globalthreatfeeds/status",
				"securityeventwebhooks",
			},
			Verbs: []string{"create", "update", "delete", "patch", "get", "watch", "list"},
		},
	}

	// User can:
	// - read and write UISettings in the cluster-settings group, and rename the group (non-cloud only)
	// - read and write UISettings in the user-settings group, and rename the group
	// Default settings group and settings are created in manager.go.
	// Calico Cloud exposes only per-user UISettings, so the cluster-settings group is omitted there.
	if c.cfg.Cloud {
		rules = append(rules,
			rbacv1.PolicyRule{
				APIGroups:     []string{"projectcalico.org"},
				Resources:     []string{"uisettingsgroups"},
				Verbs:         []string{"get"},
				ResourceNames: []string{"user-settings"},
			},
			rbacv1.PolicyRule{
				APIGroups:     []string{"projectcalico.org"},
				Resources:     []string{"uisettingsgroups/data"},
				Verbs:         []string{"*"},
				ResourceNames: []string{"user-settings"},
			},
		)
	} else {
		rules = append(rules,
			rbacv1.PolicyRule{
				APIGroups:     []string{"projectcalico.org"},
				Resources:     []string{"uisettingsgroups"},
				Verbs:         []string{"get", "patch", "update"},
				ResourceNames: []string{"cluster-settings", "user-settings"},
			},
			rbacv1.PolicyRule{
				APIGroups:     []string{"projectcalico.org"},
				Resources:     []string{"uisettingsgroups/data"},
				Verbs:         []string{"*"},
				ResourceNames: []string{"cluster-settings", "user-settings"},
			},
		)
	}

	rules = append(rules, []rbacv1.PolicyRule{
		// Allow the user to read and write applicationlayers to enable/disable WAF.
		{
			APIGroups: []string{"operator.tigera.io"},
			Resources: []string{"applicationlayers", "packetcaptureapis", "compliances", "intrusiondetections"},
			Verbs:     []string{"get", "update", "patch", "create", "delete"},
		},
		// Allow the user to read the gatewayapis CR to detect if Gateway API is enabled/disabled.
		// Read-only: enabling Gateway API from the WAF UI is intentionally deferred.
		{
			APIGroups: []string{"operator.tigera.io"},
			Resources: []string{"gatewayapis"},
			Verbs:     []string{"get"},
		},
		// Allow the user to read Gateways and HTTPRoutes to offer as WAF policy attach targets.
		{
			APIGroups: []string{"gateway.networking.k8s.io"},
			Resources: []string{"gateways", "httproutes"},
			Verbs:     []string{"get", "list", "watch"},
		},
		// Allow the user to manage WAF policies, plugins, and validation policies.
		{
			APIGroups: []string{"applicationlayer.projectcalico.org"},
			Resources: []string{
				"globalwafpolicies",
				"globalwafplugins",
				"globalwafvalidationpolicies",
				"wafpolicies",
				"wafplugins",
				"wafvalidationpolicies",
			},
			Verbs: []string{"create", "update", "delete", "patch", "get", "watch", "list"},
		},
		// Allow the user to read deployments to view WAF configuration.
		{
			APIGroups: []string{"apps"},
			Resources: []string{"deployments"},
			Verbs:     []string{"get", "list", "watch", "patch"},
		},
		{
			APIGroups: []string{""},
			Resources: []string{"services"},
			Verbs:     []string{"get", "list", "watch", "patch"},
		},
		// Allow the user to read felixconfigurations to detect if wireguard and/or other features are enabled.
		{
			APIGroups: []string{"projectcalico.org"},
			Resources: []string{"felixconfigurations"},
			Verbs:     []string{"get", "list"},
		},
		// Allow the user to perform CRUD operations on securityeventwebhooks.
		{
			APIGroups: []string{"projectcalico.org", "crd.projectcalico.org"},
			Resources: []string{"securityeventwebhooks"},
			Verbs:     []string{"get", "list", "update", "patch", "create", "delete"},
		},
		// Allow the user to create secrets.
		{
			APIGroups: []string{""},
			Resources: []string{
				"secrets",
			},
			Verbs: []string{"create"},
		},
		// Allow the user to patch webhooks-secret secret.
		{
			APIGroups: []string{""},
			Resources: []string{
				"secrets",
			},
			ResourceNames: []string{
				"webhooks-secret",
			},
			Verbs: []string{"patch"},
		},
	}...)

	// Role/binding access for the RBAC management UI. ui-apis writes these
	// impersonating the caller, so the apiserver enforces escalation against the
	// user's own permissions. The UI reads the role catalogue and manages group
	// membership through both cluster- and namespace-scoped bindings.
	if c.cfg.RBACManagementEnabled {
		rules = append(rules,
			rbacv1.PolicyRule{
				APIGroups: []string{"rbac.authorization.k8s.io"},
				Resources: []string{"clusterroles", "roles"},
				Verbs:     []string{"get", "list", "watch"},
			},
			rbacv1.PolicyRule{
				APIGroups: []string{"rbac.authorization.k8s.io"},
				Resources: []string{"clusterrolebindings", "rolebindings"},
				Verbs:     []string{"get", "list", "watch", "create", "update", "delete"},
			},
		)
	}

	// Privileges for lma.tigera.io have no effect on managed clusters.
	if c.cfg.ManagementClusterConnection == nil {
		// Access to flow logs, audit logs, and statistics.
		// Elasticsearch superuser access once logged into Kibana.
		// Calico Cloud additionally grants access to runtime logs.
		resourceNames := []string{"flows", "audit*", "l7", "events", "dns", "waf", "kibana_login", "elasticsearch_superuser", "recommendations"}
		if c.cfg.Cloud {
			resourceNames = append([]string{"runtime"}, resourceNames...)
		}
		rules = append(rules, rbacv1.PolicyRule{
			APIGroups:     []string{"lma.tigera.io"},
			Resources:     []string{"*"},
			ResourceNames: resourceNames,
			Verbs:         []string{"get"},
		})
	}

	// In v3 CRD / webhooks mode there is no aggregated apiserver, and the
	// calico-uisettings-passthrough ClusterRole that normally grants the broad
	// uisettings permission isn't deployed. Grant write verbs here so the
	// calico-webhooks UISettings handler (which narrows access via a SAR on
	// uisettingsgroups/data) gets invoked instead of being short-circuited by
	// kube-apiserver RBAC.
	if !c.cfg.RequiresAggregationServer {
		rules = append(rules, rbacv1.PolicyRule{
			APIGroups: []string{"projectcalico.org"},
			Resources: []string{"uisettings"},
			Verbs:     []string{"create", "update", "delete", "patch"},
		})
	}

	return &rbacv1.ClusterRole{
		TypeMeta: metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name: "tigera-network-admin",
		},
		Rules: rules,
	}
}

// calicoPolicyPassthruClusterRole creates a clusterrole that is used to control the RBAC
// mechanism for Calico tiered policy.
func (c *apiServerComponent) calicoPolicyPassthruClusterRole() *rbacv1.ClusterRole {
	resources := []string{"networkpolicies", "globalnetworkpolicies"}

	// Append additional resources for enterprise Variant.
	if c.cfg.Installation.Variant.IsEnterprise() {
		resources = append(resources, "stagednetworkpolicies", "stagedglobalnetworkpolicies")
	}

	return &rbacv1.ClusterRole{
		TypeMeta: metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name: "calico-tiered-policy-passthrough",
		},
		// If tiered policy is enabled we allow all authenticated users to access the main tier resource, instead
		// restricting access using the tier.xxx resource type. Kubernetes NetworkPolicy and
		// StagedKubernetesNetworkPolicy objects are handled using normal (non-tiered) RBAC.
		Rules: []rbacv1.PolicyRule{
			{
				APIGroups: []string{"projectcalico.org"},
				Resources: resources,
				Verbs:     allVerbs,
			},
		},
	}
}

// calicoPolicyPassthruClusterRolebinding creates a clusterrolebinding that applies calicoPolicyPassthruClusterRole to all users.
func (c *apiServerComponent) calicoPolicyPassthruClusterRolebinding() *rbacv1.ClusterRoleBinding {
	return &rbacv1.ClusterRoleBinding{
		TypeMeta: metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name: "calico-tiered-policy-passthrough",
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:     "Group",
				Name:     "system:authenticated",
				APIGroup: "rbac.authorization.k8s.io",
			},
		},
		RoleRef: rbacv1.RoleRef{
			Kind:     "ClusterRole",
			Name:     "calico-tiered-policy-passthrough",
			APIGroup: "rbac.authorization.k8s.io",
		},
	}
}

// uiSettingsPassthruClusterRole creates a clusterrole that is used to control the RBAC mechanism for Tigera UI Settings.
// RBAC for these is handled within the Tigera API Server which checks uisettingsgroups/data permissions for the user.
//
// Calico Enterprise only
func (c *apiServerComponent) uiSettingsPassthruClusterRole() *rbacv1.ClusterRole {
	return &rbacv1.ClusterRole{
		TypeMeta: metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name: "calico-uisettings-passthrough",
		},
		Rules: []rbacv1.PolicyRule{
			{
				APIGroups: []string{"projectcalico.org"},
				Resources: []string{"uisettings"},
				Verbs:     []string{"*"},
			},
		},
	}
}

// uiSettingsPassthruClusterRolebinding creates a clusterrolebinding that applies uiSettingsPassthruClusterRole to all
// users.
//
// Calico Enterprise only.
func (c *apiServerComponent) uiSettingsPassthruClusterRolebinding() *rbacv1.ClusterRoleBinding {
	return &rbacv1.ClusterRoleBinding{
		TypeMeta: metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name: "calico-uisettings-passthrough",
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:     "Group",
				Name:     "system:authenticated",
				APIGroup: "rbac.authorization.k8s.io",
			},
		},
		RoleRef: rbacv1.RoleRef{
			Kind:     "ClusterRole",
			Name:     "calico-uisettings-passthrough",
			APIGroup: "rbac.authorization.k8s.io",
		},
	}
}

// auditPolicyConfigMap returns a configmap with contents to configure audit logging for
// projectcalico.org/v3 APIs.
//
// Calico Enterprise only
func (c *apiServerComponent) auditPolicyConfigMap() *corev1.ConfigMap {
	const defaultAuditPolicy = `apiVersion: audit.k8s.io/v1
kind: Policy
rules:
- level: RequestResponse
  omitStages:
  - RequestReceived
  verbs:
  - create
  - patch
  - update
  - delete
  resources:
  - group: projectcalico.org
    resources:
    - globalnetworkpolicies
    - networkpolicies
    - stagedglobalnetworkpolicies
    - stagednetworkpolicies
    - stagedkubernetesnetworkpolicies
    - globalnetworksets
    - networksets
    - tiers
    - hostendpoints`

	return &corev1.ConfigMap{
		TypeMeta: metav1.TypeMeta{Kind: "ConfigMap", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{
			// This object is for Enterprise only, so pass it explicitly.
			Namespace: APIServerNamespace,
			Name:      auditPolicyVolumeName,
		},
		Data: map[string]string{
			"config": defaultAuditPolicy,
		},
	}
}

func (c *apiServerComponent) multiTenantManagedClusterAccessClusterRoles() []client.Object {
	var objects []client.Object
	objects = append(objects, &rbacv1.ClusterRole{
		TypeMeta:   metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{Name: MultiTenantManagedClustersAccessClusterRoleName},
		Rules: []rbacv1.PolicyRule{
			{
				APIGroups: []string{"projectcalico.org"},
				Resources: []string{"managedclusters"},
				Verbs: []string{
					// The Authentication Proxy in Voltron checks if Enterprise Components (using impersonation headers for
					// the service in the canonical namespace) can get a managed clusters before sending the request down the tunnel.
					// This ClusterRole will be assigned to each component using a RoleBinding in the canonical or tenant namespace.
					"get",
				},
			},
		},
	})

	return objects
}

// managedClusterWatchClusterRole creates a ClusterRole for watching the ManagedCluster API
func (c *apiServerComponent) managedClusterWatchClusterRole() client.Object {
	return &rbacv1.ClusterRole{
		TypeMeta:   metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{Name: ManagedClustersWatchClusterRoleName},
		Rules: []rbacv1.PolicyRule{
			{
				APIGroups: []string{"projectcalico.org"},
				Resources: []string{"managedclusters"},
				Verbs: []string{
					"get", "list", "watch",
				},
			},
		},
	}
}

func (c *apiServerComponent) getDeprecatedResources() []client.Object {
	var renamedRscList []client.Object

	// renamed clusterrole tigera-crds to tigera-apiserver
	renamedRscList = append(renamedRscList, &rbacv1.ClusterRole{
		TypeMeta: metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name: "tigera-crds",
		},
	})

	// renamed clusterrolebinding tigera-apiserver-access-tigera-crds to tigera-apiserver
	renamedRscList = append(renamedRscList, &rbacv1.ClusterRoleBinding{
		TypeMeta: metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name: "tigera-apiserver-access-tigera-crds",
		},
	})

	// The following resources were not present in Calico OSS, so there is no need to clean up in OSS.
	if c.cfg.Installation.Variant.IsEnterprise() {
		// Renamed ClusterRoleBinging tigera-tier-getter to calico-tier-getter since Tier is available in OSS
		renamedRscList = append(renamedRscList, &rbacv1.ClusterRoleBinding{
			TypeMeta: metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"},
			ObjectMeta: metav1.ObjectMeta{
				Name: "tigera-tier-getter",
			},
		})
		// Renamed ClusterRole tigera-tier-getter to calico-tier-getter since Tier is available in OSS
		renamedRscList = append(renamedRscList, &rbacv1.ClusterRole{
			TypeMeta: metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"},
			ObjectMeta: metav1.ObjectMeta{
				Name: "tigera-tier-getter",
			},
		})
	}

	renamedRscList = append(renamedRscList, &corev1.Namespace{
		TypeMeta: metav1.TypeMeta{Kind: "Namespace", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name: "calico-apiserver",
		},
	})

	renamedRscList = append(renamedRscList, &corev1.Namespace{
		TypeMeta: metav1.TypeMeta{Kind: "Namespace", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name: "tigera-system",
		},
	})

	// Renamed ClusterRole tigera-managed-cluster-watch to calico-managed-cluster-watch
	renamedRscList = append(renamedRscList, &rbacv1.ClusterRole{
		TypeMeta:   metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{Name: "tigera-managed-cluster-watch"},
	})

	return renamedRscList
}

func (cfg *APIServerConfiguration) IsSidecarInjectionEnabled() bool {
	return cfg.ApplicationLayer != nil &&
		cfg.ApplicationLayer.Spec.SidecarInjection != nil &&
		*cfg.ApplicationLayer.Spec.SidecarInjection == operatorv1.SidecarEnabled
}

func (c *apiServerComponent) l7AdmissionControllerContainer() corev1.Container {
	volumeMounts := []corev1.VolumeMount{
		c.cfg.TLSKeyPair.VolumeMount(c.SupportedOSType()),
	}

	l7AdmissionControllerTargetPort := getContainerPort(c.cfg, L7AdmissionControllerContainerName).ContainerPort

	dataplane := "iptables"
	if c.cfg.Installation.IsNftables() {
		dataplane = "nftables"
	}

	l7AdmssCtrl := corev1.Container{
		Name:    string(L7AdmissionControllerContainerName),
		Image:   c.calicoImage,
		Command: []string{components.CalicoBinaryPath, "component", "l7-admission-controller"},
		Env: []corev1.EnvVar{
			{
				Name:  "L7ADMCTRL_TLSCERTPATH",
				Value: c.cfg.TLSKeyPair.VolumeMountCertificateFilePath(),
			},
			{
				Name:  "L7ADMCTRL_TLSKEYPATH",
				Value: c.cfg.TLSKeyPair.VolumeMountKeyFilePath(),
			},
			{
				Name:  "L7ADMCTRL_ENVOYIMAGE",
				Value: c.l7AdmissionControllerEnvoyImage,
			},
			{
				Name:  "L7ADMCTRL_DIKASTESIMAGE",
				Value: c.dikastesImage,
			},
			{
				Name:  "L7ADMCTRL_LISTENADDR",
				Value: fmt.Sprintf(":%d", l7AdmissionControllerTargetPort),
			},
			{
				Name:  "DATAPLANE",
				Value: dataplane,
			},
		},
		VolumeMounts: volumeMounts,
		LivenessProbe: &corev1.Probe{
			ProbeHandler: corev1.ProbeHandler{
				HTTPGet: &corev1.HTTPGetAction{
					Path:   "/live",
					Port:   intstr.FromInt32(l7AdmissionControllerTargetPort),
					Scheme: corev1.URISchemeHTTPS,
				},
			},
		},
	}

	return l7AdmssCtrl
}

// deprecatedResources removes legacy cluster-scoped resources created with the 'tigera' prefix (EE-only).
// Moving forward, both EE and OSS variants standardize on the 'calico' prefix for all shared resources.
// TODO to clean up the below deprecated logic with 14 resources in 3.25+
func (c *apiServerComponent) deprecatedResources() []client.Object {
	return []client.Object{
		&rbacv1.ClusterRole{
			TypeMeta:   metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"},
			ObjectMeta: metav1.ObjectMeta{Name: "tigera-extension-apiserver-secrets-access"},
		},
		&rbacv1.ClusterRoleBinding{
			TypeMeta:   metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"},
			ObjectMeta: metav1.ObjectMeta{Name: "tigera-extension-apiserver-secrets-access"},
		},

		// delegateAuthClusterRoleBinding
		&rbacv1.ClusterRoleBinding{
			TypeMeta:   metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"},
			ObjectMeta: metav1.ObjectMeta{Name: "tigera-apiserver-delegate-auth"},
		},

		// authClusterRole
		&rbacv1.ClusterRole{
			TypeMeta:   metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"},
			ObjectMeta: metav1.ObjectMeta{Name: "tigera-extension-apiserver-auth-access"},
		},

		// authClusterRoleBinding
		&rbacv1.ClusterRoleBinding{
			TypeMeta:   metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"},
			ObjectMeta: metav1.ObjectMeta{Name: "tigera-extension-apiserver-auth-access"},
		},
		// authReaderRoleBinding - need clean up in diff namespace kube-system
		&rbacv1.RoleBinding{
			TypeMeta: metav1.TypeMeta{Kind: "RoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"},
			ObjectMeta: metav1.ObjectMeta{
				Name:      "tigera-auth-reader",
				Namespace: "kube-system",
			},
		},
		// webhookReaderClusterRole
		&rbacv1.ClusterRole{
			TypeMeta:   metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"},
			ObjectMeta: metav1.ObjectMeta{Name: "tigera-webhook-reader"},
		},

		// webhookReaderClusterRoleBinding
		&rbacv1.ClusterRoleBinding{
			TypeMeta:   metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"},
			ObjectMeta: metav1.ObjectMeta{Name: "tigera-apiserver-webhook-reader"},
		},

		// calico-apiserver CR and CRB
		&rbacv1.ClusterRole{
			TypeMeta:   metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"},
			ObjectMeta: metav1.ObjectMeta{Name: "tigera-apiserver"},
		},
		&rbacv1.ClusterRoleBinding{
			TypeMeta:   metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"},
			ObjectMeta: metav1.ObjectMeta{Name: "tigera-apiserver"},
		},

		&rbacv1.ClusterRole{
			TypeMeta:   metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"},
			ObjectMeta: metav1.ObjectMeta{Name: "tigera-uisettingsgroup-getter"},
		},
		&rbacv1.ClusterRoleBinding{
			TypeMeta:   metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"},
			ObjectMeta: metav1.ObjectMeta{Name: "tigera-uisettingsgroup-getter"},
		},

		&rbacv1.ClusterRole{
			TypeMeta:   metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"},
			ObjectMeta: metav1.ObjectMeta{Name: "tigera-tiered-policy-passthrough"},
		},
		&rbacv1.ClusterRoleBinding{
			TypeMeta:   metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"},
			ObjectMeta: metav1.ObjectMeta{Name: "tigera-tiered-policy-passthrough"},
		},

		&rbacv1.ClusterRole{
			TypeMeta:   metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"},
			ObjectMeta: metav1.ObjectMeta{Name: "tigera-uisettings-passthrough"},
		},
		&rbacv1.ClusterRoleBinding{
			TypeMeta:   metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"},
			ObjectMeta: metav1.ObjectMeta{Name: "tigera-uisettings-passthrough"},
		},

		// Clean up legacy secrets in the tigera-operator namespace
		&corev1.Secret{
			TypeMeta:   metav1.TypeMeta{Kind: "Secret", APIVersion: "v1"},
			ObjectMeta: metav1.ObjectMeta{Name: "tigera-api-cert", Namespace: common.OperatorNamespace()},
		},
	}
}
