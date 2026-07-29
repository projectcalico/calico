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

package render

import (
	"crypto/x509"
	"fmt"
	"net"
	"strconv"
	"strings"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"sigs.k8s.io/controller-runtime/pkg/client"

	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/components"
	"github.com/tigera/operator/pkg/render/common/authentication"
	tigerakvc "github.com/tigera/operator/pkg/render/common/authentication/tigera/key_validator_config"
	rcomponents "github.com/tigera/operator/pkg/render/common/components"
	"github.com/tigera/operator/pkg/render/common/configmap"
	rkibana "github.com/tigera/operator/pkg/render/common/kibana"
	rmeta "github.com/tigera/operator/pkg/render/common/meta"
	"github.com/tigera/operator/pkg/render/common/networkpolicy"
	"github.com/tigera/operator/pkg/render/common/podaffinity"
	"github.com/tigera/operator/pkg/render/common/secret"
	"github.com/tigera/operator/pkg/render/common/securitycontext"
	"github.com/tigera/operator/pkg/render/common/securitycontextconstraints"
	"github.com/tigera/operator/pkg/render/manager"
	"github.com/tigera/operator/pkg/tls/certificatemanagement"
	"github.com/tigera/operator/pkg/tls/certkeyusage"
)

const (
	ManagerPort                 = 9443
	managerTargetPort           = 9443
	ManagerServiceName          = "calico-manager"
	LegacyManagerServiceName    = "tigera-manager"
	ManagerDeploymentName       = "calico-manager"
	LegacyManagerDeploymentName = "tigera-manager"
	ManagerNamespace            = common.CalicoNamespace
	LegacyManagerNamespace      = "tigera-manager"
	ManagerServiceAccount       = "calico-manager"
	LegacyManagerServiceAccount = "tigera-manager"

	// Default manager RBAC resources.
	ManagerClusterRole              = "calico-manager-role"
	LegacyManagerClusterRole        = "tigera-manager-role"
	ManagerClusterRoleBinding       = "calico-manager-binding"
	LegacyManagerClusterRoleBinding = "tigera-manager-binding"

	// Manager RBAC resources for Calico managed clusters.
	ManagerManagedCalicoClusterRole              = "calico-manager-managed-calico"
	LegacyManagerManagedCalicoClusterRole        = "tigera-manager-managed-calico"
	ManagerManagedCalicoClusterRoleBinding       = "calico-manager-managed-calico"
	LegacyManagerManagedCalicoClusterRoleBinding = "tigera-manager-managed-calico"

	ManagerTLSSecretName         = "manager-tls"
	ManagerInternalTLSSecretName = "internal-manager-tls"
	ManagerPolicyName            = networkpolicy.CalicoComponentPolicyPrefix + "manager-access"
	ManagerPortName              = "https"

	// RBACManagementLDAPConfigSecretName is the RBAC-UI LDAP directory-sync config
	// Secret (calico-system) the rbacsync process reads to perform the sync.
	// Keep in sync with ui-apis rbacmanagement/idp LDAPConfigSecretName.
	RBACManagementLDAPConfigSecretName = "tigera-idp-ldap-config"

	// The name of the TLS certificate used by Voltron to authenticate connections from managed
	// cluster clients talking to Linseed.
	VoltronLinseedTLS              = "calico-voltron-linseed-tls"
	VoltronLinseedPublicCert       = "calico-voltron-linseed-certs-public"
	LegacyVoltronLinseedPublicCert = "tigera-voltron-linseed-certs-public"

	ManagerClusterSettings            = "cluster-settings"
	ManagerUserSettings               = "user-settings"
	ManagerClusterSettingsLayerTigera = "cluster-settings.layer.tigera-infrastructure"
	ManagerClusterSettingsViewDefault = "cluster-settings.view.default"

	ElasticsearchUserHashAnnotation                                     = "hash.operator.tigera.io/elasticsearch-user"
	ManagerMultiTenantManagedClustersAccessClusterRoleBindingName       = "calico-manager-managed-cluster-access"
	LegacyManagerMultiTenantManagedClustersAccessClusterRoleBindingName = "tigera-manager-managed-cluster-access"
	ManagerManagedClustersWatchRoleBindingName                          = "calico-manager-managed-cluster-watch"
	LegacyManagerManagedClustersWatchRoleBindingName                    = "tigera-manager-managed-cluster-watch"
	ManagerManagedClustersUpdateRBACName                                = "calico-manager-managed-cluster-write-access"
	LegacyManagerManagedClustersUpdateRBACName                          = "tigera-manager-managed-cluster-write-access"
)

// ManagementClusterConnection configuration constants
const (
	ManagerName              = "calico-manager"
	UIAPIsName               = "calico-ui-apis"
	VoltronName              = "calico-voltron"
	VoltronTunnelSecretName  = "calico-management-cluster-connection"
	defaultVoltronPort       = "9443"
	defaultTunnelVoltronPort = "9449"
	DashboardAPIPort         = "8444"
	DashboardAPIHealthPort   = "8090"
	DashboardAPIName         = "calico-dashboard-api"

	// VoltronAdditionalTunnelSecretName is the name of an optional, pre-provisioned secret
	// in the truth namespace that holds an additional CA used by Voltron for tunnel server
	// certificates. When the secret is present the manager controller wires it into the
	// Voltron deployment. It is managed out-of-band; the operator only consumes it.
	VoltronAdditionalTunnelSecretName = "calico-management-additional-cluster-connection"
)

// Manager returns a component for rendering namespaced manager resources.
func init() {
	certkeyusage.SetCertKeyUsage(ManagerTLSSecretName, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth})
	certkeyusage.SetCertKeyUsage(ManagerInternalTLSSecretName, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth})
}

// Manager returns a component for rendering namespaced manager resources.
func Manager(cfg *ManagerConfiguration) (Component, error) {
	var tlsSecrets []*corev1.Secret
	tlsAnnotations := cfg.TrustedCertBundle.HashAnnotations()
	tlsAnnotations[cfg.TLSKeyPair.HashAnnotationKey()] = cfg.TLSKeyPair.HashAnnotationValue()

	if cfg.VoltronLinseedKeyPair != nil {
		tlsAnnotations[cfg.VoltronLinseedKeyPair.HashAnnotationKey()] = cfg.VoltronLinseedKeyPair.HashAnnotationValue()
	}

	if cfg.KeyValidatorConfig != nil {
		tlsSecrets = append(tlsSecrets, cfg.KeyValidatorConfig.RequiredSecrets(cfg.Namespace)...)
		for key, value := range cfg.KeyValidatorConfig.RequiredAnnotations() {
			tlsAnnotations[key] = value
		}
	}

	tlsAnnotations[cfg.InternalTLSKeyPair.HashAnnotationKey()] = cfg.InternalTLSKeyPair.HashAnnotationValue()
	if cfg.ManagementCluster != nil {
		tlsAnnotations[cfg.TunnelServerCert.HashAnnotationKey()] = cfg.TunnelServerCert.HashAnnotationValue()
		if cfg.AdditionalTunnelServerCert != nil {
			tlsAnnotations[cfg.AdditionalTunnelServerCert.HashAnnotationKey()] = cfg.AdditionalTunnelServerCert.HashAnnotationValue()
		}
	}

	return &managerComponent{
		cfg:            cfg,
		tlsSecrets:     tlsSecrets,
		tlsAnnotations: tlsAnnotations,
	}, nil
}

// ManagerConfiguration contains all the config information needed to render the component.
type ManagerConfiguration struct {
	VoltronRouteConfig *manager.VoltronRouteConfig

	KeyValidatorConfig authentication.KeyValidatorConfig
	PullSecrets        []*corev1.Secret
	OpenShift          bool
	Installation       *operatorv1.InstallationSpec
	ManagementCluster  *operatorv1.ManagementCluster
	NonClusterHost     *operatorv1.NonClusterHost

	// If provided, the KeyPair to used for external connections terminated by Voltron,
	// and connections from the manager pod to Linseed.
	TLSKeyPair certificatemanagement.KeyPairInterface

	// The key pair to use for TLS between Linseed clients in managed clusters and Voltron
	// in the management cluster.
	VoltronLinseedKeyPair certificatemanagement.KeyPairInterface

	// KeyPair used by Voltron as the server certificate when establishing an mTLS tunnel with Guardian.
	TunnelServerCert certificatemanagement.KeyPairInterface

	// AdditionalTunnelServerCert is an optional additional CA used by Voltron for tunnel server
	// certificates. It is populated by the manager controller when a pre-provisioned secret named
	// VoltronAdditionalTunnelSecretName exists in the truth namespace, and is mounted into the
	// Voltron container so Voltron can serve TLS from it.
	AdditionalTunnelServerCert certificatemanagement.KeyPairInterface

	// TLS KeyPair used by both Voltron and ui-apis, presented by each as part of the mTLS handshake with
	// other services within the cluster. This is used in both management and standalone clusters.
	InternalTLSKeyPair certificatemanagement.KeyPairInterface

	// Certificate bundle used by the manager pod to verify certificates presented
	// by clients as part of mTLS authentication.
	TrustedCertBundle certificatemanagement.TrustedBundleRO

	ClusterDomain           string
	ESLicenseType           ElasticsearchLicenseType
	Replicas                *int32
	Compliance              *operatorv1.Compliance
	ComplianceLicenseActive bool
	ComplianceNamespace     string

	Namespace      string
	TruthNamespace string

	// Single namespace to which RBAC should be bound, in single-tenant systems.
	// List of all tenant namespaces, in a multi-tenant system.
	BindingNamespaces []string

	// List of namespaces for Tenants who manage Calico OSS clusters, in a multi-tenant system.
	OSSTenantNamespaces []string

	// Whether to run the rendered components in multi-tenant, single-tenant, or zero-tenant mode
	Tenant          *operatorv1.Tenant
	ExternalElastic bool

	Manager        *operatorv1.Manager
	Authentication *operatorv1.Authentication
	KibanaEnabled  bool

	// CACertCommonName is the CommonName from the CA certificate used for operator-managed certificates.
	// Passed to Voltron so it can identify the correct CA issuer public key.
	CACertCommonName string

	// Cloud indicates the manager is being rendered for a Calico Cloud install. When false (regular
	// Calico/Calico Enterprise) all cloud decorations below are inert and CloudResources is ignored.
	Cloud bool

	// CloudResources holds Calico Cloud specific manager/voltron customizations. Only consumed when
	// Cloud is true.
	CloudResources ManagerCloudResources
}

type managerComponent struct {
	cfg            *ManagerConfiguration
	tlsSecrets     []*corev1.Secret
	tlsAnnotations map[string]string
	managerImage   string
	calicoImage    string
}

func (c *managerComponent) ResolveImages(is *operatorv1.ImageSet) error {
	reg := c.cfg.Installation.Registry
	path := c.cfg.Installation.ImagePath
	prefix := c.cfg.Installation.ImagePrefix
	var err error
	errMsgs := []string{}

	c.managerImage, err = components.GetReference(components.ComponentManager, reg, path, prefix, is)
	if err != nil {
		errMsgs = append(errMsgs, err.Error())
	}

	c.calicoImage, err = components.GetReference(components.CombinedCalicoImage(c.cfg.Installation), reg, path, prefix, is)
	if err != nil {
		errMsgs = append(errMsgs, err.Error())
	}

	if len(errMsgs) != 0 {
		return fmt.Errorf("%s", strings.Join(errMsgs, ","))
	}

	// run cloud image customizations (no-op when not in cloud mode)
	c.resolveCloudImages()

	return nil
}

func (c *managerComponent) SupportedOSType() rmeta.OSType {
	return rmeta.OSTypeLinux
}

func (c *managerComponent) Objects() ([]client.Object, []client.Object) {
	objsToCreate := []client.Object{}
	var objsToDelete []client.Object

	if !c.cfg.Tenant.MultiTenant() {
		// For multi-tenant environments, the management cluster itself isn't shown in the UI so we only need to create these
		// when there is no tenant.
		objsToCreate = append(objsToCreate,
			managerClusterWideSettingsGroup(),
			managerUserSpecificSettingsGroup(),
			managerClusterWideTigeraLayer(),
			managerClusterWideDefaultView(),
		)
		// Continue to create the legacy namespace so that we can create our external name service that points to the new
		// manager service. This will help ease transition for customers and avoid outages caused by the name and namespace
		// changes.
		objsToCreate = append(objsToCreate, c.managerLegacyNamespace())
	}

	objsToDelete = c.deprecatedResources(c.cfg.Tenant, c.cfg.Namespace, c.cfg.TruthNamespace)

	objsToCreate = append(objsToCreate,
		managerClusterRoleBinding(c.cfg.Tenant, c.cfg.BindingNamespaces, c.cfg.OSSTenantNamespaces),
		managerClusterRole(false, c.cfg.Installation.KubernetesProvider, c.cfg.Tenant, c.cfg.Manager.RBACManagementEnabled()),
		c.managedClustersWatchRoleBinding(),
	)
	objsToCreate = append(objsToCreate, c.managedClustersUpdateRBAC()...)
	if c.cfg.Manager.RBACManagementEnabled() && !c.cfg.Tenant.MultiTenant() {
		objsToCreate = append(objsToCreate, c.rbacManagementUINamespacedRole()...)
	}
	if c.cfg.Tenant.MultiTenant() {
		objsToCreate = append(objsToCreate, c.multiTenantManagedClustersAccess()...)
	}

	objsToCreate = append(objsToCreate,
		c.managerCalicoSystemNetworkPolicy(),
		managerServiceAccount(c.cfg.Namespace),
	)
	// The default-deny policy in calico-system is owned by the Installation
	// controller, which uses a selector that excludes calico-apiserver so the
	// API server remains reachable. Skip rendering it here when the Manager is
	// being installed into calico-system (single-tenant), otherwise the two
	// controllers fight over the policy's selector. In multi-tenant mode the
	// Manager lives in a tenant namespace that Installation doesn't manage, so
	// the Manager is responsible for the default-deny there.
	if c.cfg.Namespace != common.CalicoNamespace {
		objsToCreate = append(objsToCreate, networkpolicy.CalicoSystemDefaultDeny(c.cfg.Namespace))
	}
	objsToCreate = append(objsToCreate, c.getTLSObjects()...)
	objsToCreate = append(objsToCreate, c.managerService())
	objsToCreate = append(objsToCreate, c.managerExternalNameService())

	if c.cfg.VoltronRouteConfig != nil {
		objsToCreate = append(objsToCreate, c.cfg.VoltronRouteConfig.RoutesConfigMap(c.cfg.Namespace))
	}

	objsToCreate = append(objsToCreate, c.managerDeployment())
	if c.cfg.KeyValidatorConfig != nil {
		objsToCreate = append(objsToCreate, configmap.ToRuntimeObjects(c.cfg.KeyValidatorConfig.RequiredConfigMaps(c.cfg.Namespace)...)...)
	}

	// The following secret is read by kube controllers and sent to managed clusters so that linseed clients in the managed cluster
	// can authenticate the certificate presented by Voltron.
	if c.cfg.VoltronLinseedKeyPair != nil {
		if c.cfg.VoltronLinseedKeyPair.UseCertificateManagement() {
			objsToCreate = append(objsToCreate, CreateCertificateSecret(c.cfg.Installation.CertificateManagement.CACert, VoltronLinseedPublicCert, c.cfg.TruthNamespace))
		} else {
			objsToCreate = append(objsToCreate, CreateCertificateSecret(c.cfg.VoltronLinseedKeyPair.GetCertificatePEM(), VoltronLinseedPublicCert, c.cfg.TruthNamespace))
		}
	}

	return objsToCreate, objsToDelete
}

func (c *managerComponent) Ready() bool {
	return true
}

// managerDeployment creates a deployment for the Tigera Secure manager component.
func (c *managerComponent) managerDeployment() *appsv1.Deployment {
	var initContainers []corev1.Container
	if c.cfg.TLSKeyPair.UseCertificateManagement() {
		initContainers = append(initContainers, c.cfg.TLSKeyPair.InitContainer(c.cfg.Namespace, securitycontext.NewNonRootContext()))
	}

	// Containers for the manager pod.
	if c.cfg.InternalTLSKeyPair != nil && c.cfg.InternalTLSKeyPair.UseCertificateManagement() {
		initContainers = append(initContainers, c.cfg.InternalTLSKeyPair.InitContainer(ManagerNamespace, securitycontext.NewNonRootContext()))
	}
	if c.cfg.VoltronLinseedKeyPair != nil && c.cfg.VoltronLinseedKeyPair.UseCertificateManagement() {
		initContainers = append(initContainers, c.cfg.VoltronLinseedKeyPair.InitContainer(ManagerNamespace, securitycontext.NewNonRootContext()))
	}

	managerPodContainers := []corev1.Container{c.decorateCloudUIAPIsContainer(c.managerUIAPIsContainer()), c.decorateCloudVoltronContainer(c.voltronContainer())}
	if c.cfg.Tenant == nil {
		managerPodContainers = append(managerPodContainers, c.dashboardContainer(), c.managerContainer())
	}
	annotations := c.tlsAnnotations
	if c.cfg.VoltronRouteConfig != nil {
		for key, value := range c.cfg.VoltronRouteConfig.Annotations() {
			annotations[key] = value
		}
	}

	podTemplate := &corev1.PodTemplateSpec{
		ObjectMeta: metav1.ObjectMeta{
			Name:        ManagerDeploymentName,
			Namespace:   c.cfg.Namespace,
			Annotations: annotations,
		},
		Spec: corev1.PodSpec{
			NodeSelector:       c.cfg.Installation.ControlPlaneNodeSelector,
			ServiceAccountName: ManagerServiceAccount,
			Tolerations:        c.managerTolerations(),
			ImagePullSecrets:   secret.GetReferenceList(c.cfg.PullSecrets),
			InitContainers:     initContainers,
			Containers:         managerPodContainers,
			Volumes:            c.managerVolumes(),
		},
	}

	if c.cfg.Replicas != nil && *c.cfg.Replicas > 1 {
		podTemplate.Spec.Affinity = podaffinity.NewPodAntiAffinity(ManagerName, []string{c.cfg.Namespace})
	}

	d := &appsv1.Deployment{
		TypeMeta: metav1.TypeMeta{Kind: "Deployment", APIVersion: "apps/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      ManagerDeploymentName,
			Namespace: c.cfg.Namespace,
		},
		Spec: appsv1.DeploymentSpec{
			Replicas: c.cfg.Replicas,
			Strategy: appsv1.DeploymentStrategy{
				Type: appsv1.RecreateDeploymentStrategyType,
			},
			Template: c.decorateCloudDeploymentSpec(*podTemplate),
		},
	}

	if c.cfg.Manager != nil {
		if overrides := c.cfg.Manager.Spec.ManagerDeployment; overrides != nil {
			rcomponents.ApplyDeploymentOverrides(d, overrides)
		}
	}
	return d
}

// managerVolumes returns the volumes for the Tigera Secure manager component.
func (c *managerComponent) managerVolumeMounts() []corev1.VolumeMount {
	if c.cfg.KeyValidatorConfig != nil {
		return c.cfg.KeyValidatorConfig.RequiredVolumeMounts()
	}
	return nil
}

// managerVolumes returns the volumes for the Tigera Secure manager component.
func (c *managerComponent) managerVolumes() []corev1.Volume {
	v := []corev1.Volume{
		c.cfg.TLSKeyPair.Volume(),
		c.cfg.TrustedCertBundle.Volume(),
		c.cfg.InternalTLSKeyPair.Volume(),
	}
	if c.cfg.ManagementCluster != nil {
		v = append(v,
			c.cfg.TunnelServerCert.Volume(),
			c.cfg.VoltronLinseedKeyPair.Volume(),
		)
		if c.cfg.AdditionalTunnelServerCert != nil {
			v = append(v, c.cfg.AdditionalTunnelServerCert.Volume())
		}
	}
	if c.cfg.KeyValidatorConfig != nil {
		v = append(v, c.cfg.KeyValidatorConfig.RequiredVolumes()...)
	}

	if c.cfg.VoltronRouteConfig != nil {
		v = append(v, c.cfg.VoltronRouteConfig.Volumes()...)
	}

	return v
}

// managerProbe returns the probe for the manager container.
func (c *managerComponent) managerProbe() *corev1.Probe {
	return &corev1.Probe{
		ProbeHandler: corev1.ProbeHandler{
			HTTPGet: &corev1.HTTPGetAction{
				Path:   "/",
				Port:   intstr.FromInt(ManagerPort),
				Scheme: corev1.URISchemeHTTPS,
			},
		},
		InitialDelaySeconds: 90,
	}
}

// managerUIAPIsProbe returns the probe for the ES proxy container.
func (c *managerComponent) managerUIAPIsProbe() *corev1.Probe {
	return &corev1.Probe{
		ProbeHandler: corev1.ProbeHandler{
			HTTPGet: &corev1.HTTPGetAction{
				Path:   "/tigera-elasticsearch/version",
				Port:   intstr.FromInt(ManagerPort),
				Scheme: corev1.URISchemeHTTPS,
			},
		},
		InitialDelaySeconds: 90,
	}
}

// managerProxyProbe returns the probe for the proxy container.
func (c *managerComponent) managerProxyProbe() *corev1.Probe {
	return &corev1.Probe{
		ProbeHandler: corev1.ProbeHandler{
			HTTPGet: &corev1.HTTPGetAction{
				Path:   "/voltron/api/health",
				Port:   intstr.FromInt(ManagerPort),
				Scheme: corev1.URISchemeHTTPS,
			},
		},
		InitialDelaySeconds: 90,
	}
}

// managerEnvVars returns the envvars for the manager container.
func (c *managerComponent) managerEnvVars() []corev1.EnvVar {
	envs := []corev1.EnvVar{
		// TODO: Prometheus URL will need to change.
		{Name: "CNX_PROMETHEUS_API_URL", Value: fmt.Sprintf("/api/v1/namespaces/%s/services/calico-node-prometheus:9090/proxy/api/v1", common.TigeraPrometheusNamespace)},
		{Name: "CNX_COMPLIANCE_REPORTS_API_URL", Value: "/compliance/reports"},
		{Name: "CNX_QUERY_API_URL", Value: "/api/v1/namespaces/calico-system/services/https:calico-api:8080/proxy"},
		{Name: "DASHBOARD_API_URL", Value: "/dashboards"},
		{Name: "CNX_ELASTICSEARCH_API_URL", Value: "/tigera-elasticsearch"},
		{Name: "CNX_ELASTICSEARCH_KIBANA_URL", Value: fmt.Sprintf("/%s", KibanaBasePath)},
		{Name: "CNX_ENABLE_ERROR_TRACKING", Value: "false"},
		{Name: "CNX_ALP_SUPPORT", Value: "true"},
		{Name: "CNX_CLUSTER_NAME", Value: "cluster"},
		{Name: "CNX_POLICY_RECOMMENDATION_SUPPORT", Value: "true"},
		{Name: "ENABLE_MULTI_CLUSTER_MANAGEMENT", Value: strconv.FormatBool(c.cfg.ManagementCluster != nil)},
		{Name: "ENABLE_KIBANA", Value: strconv.FormatBool(c.cfg.KibanaEnabled)},
	}

	envs = append(envs, c.managerOAuth2EnvVars()...)
	envs = c.setManagerCloudEnvs(envs)
	return envs
}

// managerContainer returns the manager container.
func (c *managerComponent) managerContainer() corev1.Container {
	return corev1.Container{
		Name:            ManagerName,
		Image:           c.managerImage,
		Env:             c.managerEnvVars(),
		LivenessProbe:   c.managerProbe(),
		SecurityContext: securitycontext.NewNonRootContext(),
		VolumeMounts:    c.managerVolumeMounts(),
	}
}

// managerOAuth2EnvVars returns the OAuth2/OIDC envvars depending on the authentication type.
func (c *managerComponent) managerOAuth2EnvVars() []corev1.EnvVar {
	var envs []corev1.EnvVar

	if c.cfg.KeyValidatorConfig == nil {
		envs = []corev1.EnvVar{{Name: "CNX_WEB_AUTHENTICATION_TYPE", Value: "Token"}}
	} else {
		envs = []corev1.EnvVar{
			{Name: "CNX_WEB_AUTHENTICATION_TYPE", Value: "OIDC"},
			{Name: "CNX_WEB_OIDC_CLIENT_ID", Value: c.cfg.KeyValidatorConfig.ClientID()},
		}

		switch c.cfg.KeyValidatorConfig.(type) {
		case *DexKeyValidatorConfig:
			envs = append(envs, corev1.EnvVar{Name: "CNX_WEB_OIDC_AUTHORITY", Value: c.cfg.KeyValidatorConfig.Issuer()})
		case *tigerakvc.KeyValidatorConfig:
			envs = append(envs, corev1.EnvVar{Name: "CNX_WEB_OIDC_AUTHORITY", Value: ""})
		}

		// Apply cloud-only OIDC workarounds (no-op for non-cloud installs).
		envs = c.decorateCloudOAuth2EnvVars(envs)
	}
	return envs
}

// voltronContainer returns the container for the manager proxy container - voltron.
func (c *managerComponent) voltronContainer() corev1.Container {
	var keyPath, certPath, intKeyPath, intCertPath, tunnelKeyPath, tunnelCertPath string
	var linseedKeyPath, linseedCertPath string
	if c.cfg.TLSKeyPair != nil {
		// This should never be nil, but we check it anyway just to be safe.
		keyPath, certPath = c.cfg.TLSKeyPair.VolumeMountKeyFilePath(), c.cfg.TLSKeyPair.VolumeMountCertificateFilePath()
	}
	if c.cfg.InternalTLSKeyPair != nil {
		intKeyPath, intCertPath = c.cfg.InternalTLSKeyPair.VolumeMountKeyFilePath(), c.cfg.InternalTLSKeyPair.VolumeMountCertificateFilePath()
	}
	if c.cfg.TunnelServerCert != nil {
		tunnelKeyPath, tunnelCertPath = c.cfg.TunnelServerCert.VolumeMountKeyFilePath(), c.cfg.TunnelServerCert.VolumeMountCertificateFilePath()
	}
	if c.cfg.VoltronLinseedKeyPair != nil {
		linseedKeyPath, linseedCertPath = c.cfg.VoltronLinseedKeyPair.VolumeMountKeyFilePath(), c.cfg.VoltronLinseedKeyPair.VolumeMountCertificateFilePath()
	}
	defaultForwardServer := "tigera-secure-es-gateway-http.tigera-elasticsearch.svc:9200"
	if c.cfg.Tenant.MultiTenant() {
		// Use the local namespace instead of tigera-elasticsearch.
		defaultForwardServer = fmt.Sprintf("tigera-secure-es-gateway-http.%s.svc:9200", c.cfg.Namespace)
	}

	env := []corev1.EnvVar{
		{Name: "VOLTRON_PORT", Value: defaultVoltronPort},
		{Name: "VOLTRON_COMPLIANCE_ENDPOINT", Value: fmt.Sprintf("https://compliance.%s.svc.%s", c.cfg.ComplianceNamespace, c.cfg.ClusterDomain)},
		{Name: "VOLTRON_LOGLEVEL", Value: "Info"},
		{Name: "VOLTRON_KIBANA_ENDPOINT", Value: rkibana.HTTPSEndpoint(c.SupportedOSType(), c.cfg.ClusterDomain)},
		{Name: "VOLTRON_KIBANA_BASE_PATH", Value: fmt.Sprintf("/%s/", KibanaBasePath)},
		{Name: "VOLTRON_KIBANA_CA_BUNDLE_PATH", Value: c.cfg.TrustedCertBundle.MountPath()},
		{Name: "VOLTRON_PACKET_CAPTURE_CA_BUNDLE_PATH", Value: c.cfg.TrustedCertBundle.MountPath()},
		{Name: "VOLTRON_PROMETHEUS_CA_BUNDLE_PATH", Value: c.cfg.TrustedCertBundle.MountPath()},
		{Name: "VOLTRON_COMPLIANCE_CA_BUNDLE_PATH", Value: c.cfg.TrustedCertBundle.MountPath()},
		{Name: "VOLTRON_DEX_CA_BUNDLE_PATH", Value: c.cfg.TrustedCertBundle.MountPath()},
		// Voltron verifies the in-cluster fluent-bit http input (non-cluster-host
		// log ingestion) against the same trusted bundle. Without this the config
		// default (/etc/pki/tls/certs/ca.crt) is used, which is not mounted, so the
		// mTLS handshake to calico-fluent-bit-http-input fails.
		{Name: "VOLTRON_LOG_COLLECTOR_CA_BUNDLE_PATH", Value: c.cfg.TrustedCertBundle.MountPath()},
		{Name: "VOLTRON_QUERYSERVER_ENDPOINT", Value: fmt.Sprintf("https://%s.%s.svc:%d", QueryserverServiceName, QueryserverNamespace, QueryServerPort)},
		{Name: "VOLTRON_QUERYSERVER_BASE_PATH", Value: fmt.Sprintf("/api/v1/namespaces/%s/services/https:%s:%d/proxy/", QueryserverNamespace, QueryserverServiceName, QueryServerPort)},
		{Name: "VOLTRON_QUERYSERVER_CA_BUNDLE_PATH", Value: c.cfg.TrustedCertBundle.MountPath()},
		{Name: "VOLTRON_HTTPS_KEY", Value: keyPath},
		{Name: "VOLTRON_HTTPS_CERT", Value: certPath},
		{Name: "VOLTRON_TUNNEL_KEY", Value: tunnelKeyPath},
		{Name: "VOLTRON_TUNNEL_CERT", Value: tunnelCertPath},
		{Name: "VOLTRON_INTERNAL_HTTPS_KEY", Value: intKeyPath},
		{Name: "VOLTRON_INTERNAL_HTTPS_CERT", Value: intCertPath},
		{Name: "VOLTRON_ENABLE_MULTI_CLUSTER_MANAGEMENT", Value: strconv.FormatBool(c.cfg.ManagementCluster != nil)},
		{Name: "VOLTRON_ENABLE_NONCLUSTER_HOST", Value: strconv.FormatBool(c.cfg.NonClusterHost != nil)},
		{Name: "VOLTRON_TUNNEL_PORT", Value: defaultTunnelVoltronPort},
		{Name: "VOLTRON_DEFAULT_FORWARD_SERVER", Value: defaultForwardServer},
		{Name: "VOLTRON_ENABLE_COMPLIANCE", Value: strconv.FormatBool(c.cfg.ComplianceLicenseActive)},
	}

	if c.cfg.VoltronRouteConfig != nil {
		env = append(env, c.cfg.VoltronRouteConfig.EnvVars()...)
	}

	if c.cfg.ManagementCluster != nil {
		env = append(env, corev1.EnvVar{Name: "VOLTRON_USE_HTTPS_CERT_ON_TUNNEL", Value: strconv.FormatBool(c.cfg.ManagementCluster.Spec.TLS != nil && c.cfg.ManagementCluster.Spec.TLS.SecretName == ManagerTLSSecretName)})
		env = append(env, corev1.EnvVar{Name: "VOLTRON_LINSEED_SERVER_KEY", Value: linseedKeyPath})
		env = append(env, corev1.EnvVar{Name: "VOLTRON_LINSEED_SERVER_CERT", Value: linseedCertPath})
		if c.cfg.AdditionalTunnelServerCert != nil {
			// Voltron scans a single parent directory for additional cert/key pairs. Each
			// cert/key pair is mounted into its own subdirectory so multiple can coexist.
			// The tls.crt from each pair is also used as an additional CA to verify
			// client (guardian) connections.
			env = append(env,
				corev1.EnvVar{Name: "VOLTRON_ADDITIONAL_CERT_KEY_PAIRS_PATH", Value: "/additional-tunnel-certificates"},
			)
		}
	}

	if c.cfg.CACertCommonName != "" {
		env = append(env, corev1.EnvVar{Name: "VOLTRON_CA_SIGNER_NAME", Value: c.cfg.CACertCommonName})
	}

	if c.cfg.KeyValidatorConfig != nil {
		env = append(env, c.cfg.KeyValidatorConfig.RequiredEnv("VOLTRON_")...)
	}

	// Determine the volume mounts to use. This varies based on the type of cluster.
	mounts := c.cfg.TrustedCertBundle.VolumeMounts(c.SupportedOSType())
	mounts = append(mounts, corev1.VolumeMount{Name: ManagerTLSSecretName, MountPath: "/manager-tls", ReadOnly: true})
	if c.cfg.ManagementCluster != nil || c.cfg.NonClusterHost != nil {
		// We need the internal tls key pair for voltron and linseed mtls connection
		// when in a management cluster or non-cluster host log ingestion is enabled.
		mounts = append(mounts, c.cfg.InternalTLSKeyPair.VolumeMount(c.SupportedOSType()))
		if c.cfg.ManagementCluster != nil {
			mounts = append(mounts, c.cfg.TunnelServerCert.VolumeMount(c.SupportedOSType()))
			mounts = append(mounts, c.cfg.VoltronLinseedKeyPair.VolumeMount(c.SupportedOSType()))
			if c.cfg.AdditionalTunnelServerCert != nil {
				mounts = append(mounts, corev1.VolumeMount{
					Name:      c.cfg.AdditionalTunnelServerCert.GetName(),
					MountPath: fmt.Sprintf("/additional-tunnel-certificates/%s", c.cfg.AdditionalTunnelServerCert.GetName()),
					ReadOnly:  true,
				})
			}
		}
	}

	linseedEndpointEnv := corev1.EnvVar{Name: "VOLTRON_LINSEED_ENDPOINT", Value: fmt.Sprintf("https://tigera-linseed.%s.svc.%s", ElasticsearchNamespace, c.cfg.ClusterDomain)}
	if c.cfg.Tenant != nil {
		// Configure the tenant id in order to read /write linseed data using the correct tenant ID
		// Multi-tenant and single tenant with external elastic needs this variable set
		if c.cfg.ExternalElastic {
			env = append(env, corev1.EnvVar{Name: "VOLTRON_TENANT_ID", Value: c.cfg.Tenant.Spec.ID})
		}

		// Always configure the Tenant Claim for all multi-tenancy setups (single tenant and multi tenant)
		// This will check the tenant claim when a Bearer token is presented to Voltron
		// The actual value of the token is extracted from the tenant claim
		env = append(env, corev1.EnvVar{Name: "VOLTRON_REQUIRE_TENANT_CLAIM", Value: "true"})
		env = append(env, corev1.EnvVar{Name: "VOLTRON_TENANT_CLAIM", Value: c.cfg.Tenant.Spec.ID})

		if c.cfg.Tenant.MultiTenant() {
			env = append(env, corev1.EnvVar{Name: "VOLTRON_TENANT_NAMESPACE", Value: c.cfg.Tenant.Namespace})
			linseedEndpointEnv = corev1.EnvVar{Name: "VOLTRON_LINSEED_ENDPOINT", Value: fmt.Sprintf("https://tigera-linseed.%s.svc", c.cfg.Tenant.Namespace)}
		}

		if c.cfg.Tenant.ManagedClusterIsCalico() {
			// Enable access to / from Goldmane in Voltron.
			env = append(env, corev1.EnvVar{Name: "VOLTRON_GOLDMANE_ENABLED", Value: "true"})
			env = append(env, corev1.EnvVar{Name: "VOLTRON_MANAGED_CLUSTER_SUPPORTS_IMPERSONATION", Value: "false"})
		}
	}
	env = append(env, linseedEndpointEnv)

	if c.cfg.VoltronRouteConfig != nil {
		mounts = append(mounts, c.cfg.VoltronRouteConfig.VolumeMounts()...)
	}

	return corev1.Container{
		Name:            VoltronName,
		Image:           c.calicoImage,
		Command:         []string{components.CalicoBinaryPath, "component", "voltron"},
		Env:             env,
		VolumeMounts:    mounts,
		LivenessProbe:   c.managerProxyProbe(),
		SecurityContext: securitycontext.NewNonRootContext(),
	}
}

// dashboardContainer returns the dashboard sidecar container that only gets created in Enterprise (where tenancy is
// not enabled).
func (c *managerComponent) dashboardContainer() corev1.Container {
	var keyPath, certPath string
	if c.cfg.InternalTLSKeyPair != nil {
		keyPath, certPath = c.cfg.InternalTLSKeyPair.VolumeMountKeyFilePath(), c.cfg.InternalTLSKeyPair.VolumeMountCertificateFilePath()
	}

	env := []corev1.EnvVar{
		{Name: "LISTEN_ADDR", Value: fmt.Sprintf("127.0.0.1:%s", DashboardAPIPort)},
		{Name: "LOG_LEVEL", Value: "Info"},
		{Name: "LINSEED_URL", Value: fmt.Sprintf("https://tigera-linseed.%s.svc.%s", ElasticsearchNamespace, c.cfg.ClusterDomain)},
		{Name: "LINSEED_CLIENT_KEY", Value: keyPath},
		{Name: "LINSEED_CLIENT_CERT", Value: certPath},
		{Name: "MULTI_CLUSTER_FORWARDING_ENDPOINT", Value: ManagerService(c.cfg.Tenant)},
		{Name: "HEALTH_PORT", Value: DashboardAPIHealthPort},
	}

	if c.cfg.KeyValidatorConfig != nil {
		env = append(env, c.cfg.KeyValidatorConfig.RequiredEnv("")...)
	}

	mounts := append(
		c.cfg.TrustedCertBundle.VolumeMounts(c.SupportedOSType()),
		c.cfg.InternalTLSKeyPair.VolumeMount(c.SupportedOSType()),
	)

	return corev1.Container{
		Name:            DashboardAPIName,
		Image:           c.calicoImage,
		Command:         []string{components.CalicoBinaryPath, "component", "dashboards"},
		Env:             env,
		VolumeMounts:    mounts,
		SecurityContext: securitycontext.NewNonRootContext(),
		ReadinessProbe: &corev1.Probe{
			ProbeHandler: corev1.ProbeHandler{
				Exec: &corev1.ExecAction{
					Command: []string{components.CalicoBinaryPath, "component", "dashboards", "ready"},
				},
			},
			FailureThreshold:    3,
			PeriodSeconds:       30,
			SuccessThreshold:    1,
			TimeoutSeconds:      5,
			InitialDelaySeconds: 5,
		},
		LivenessProbe: &corev1.Probe{
			ProbeHandler: corev1.ProbeHandler{
				Exec: &corev1.ExecAction{
					Command: []string{components.CalicoBinaryPath, "component", "dashboards", "ready"},
				},
			},
			FailureThreshold: 3,
			PeriodSeconds:    30,
			SuccessThreshold: 1,
			TimeoutSeconds:   5,
		},
	}
}

// managerUIAPIsContainer returns the ES proxy container
func (c *managerComponent) managerUIAPIsContainer() corev1.Container {
	var keyPath, certPath string
	if c.cfg.InternalTLSKeyPair != nil {
		// This should never be nil, but we check it anyway just to be safe.
		keyPath, certPath = c.cfg.InternalTLSKeyPair.VolumeMountKeyFilePath(), c.cfg.InternalTLSKeyPair.VolumeMountCertificateFilePath()
	}

	env := []corev1.EnvVar{
		{Name: "ELASTIC_LICENSE_TYPE", Value: string(c.cfg.ESLicenseType)},
		{Name: "ELASTIC_KIBANA_ENDPOINT", Value: rkibana.HTTPSEndpoint(c.SupportedOSType(), c.cfg.ClusterDomain)},
		{Name: "LINSEED_CLIENT_CERT", Value: certPath},
		{Name: "LINSEED_CLIENT_KEY", Value: keyPath},
		{Name: "ELASTIC_KIBANA_DISABLED", Value: strconv.FormatBool(c.cfg.Tenant.MultiTenant())},
		{Name: "VOLTRON_URL", Value: ManagerService(c.cfg.Tenant)},
		{Name: "RBAC_UI_ENABLED", Value: strconv.FormatBool(c.cfg.Manager.RBACManagementEnabled() && !c.cfg.Tenant.MultiTenant())},
	}

	// Determine the Linseed location. Use code default unless in multi-tenant mode,
	// in which case use the Linseed in the current namespace.
	if c.cfg.Tenant != nil {

		if c.cfg.ExternalElastic {
			// A tenant was specified, ensure we set the tenant ID.
			env = append(env, corev1.EnvVar{Name: "TENANT_ID", Value: c.cfg.Tenant.Spec.ID})
		}

		if c.cfg.Tenant.MultiTenant() {
			// This cluster supports multiple tenants. Point the manager at the correct Linseed instance for this tenant.
			env = append(env, corev1.EnvVar{Name: "LINSEED_URL", Value: fmt.Sprintf("https://tigera-linseed.%s.svc", c.cfg.Namespace)})
			env = append(env, corev1.EnvVar{Name: "TENANT_NAMESPACE", Value: c.cfg.Namespace})
		}

		if c.cfg.Tenant.ManagedClusterIsCalico() {
			// Calico clusters do not give Guardian impersonation permissions.
			env = append(env, corev1.EnvVar{Name: "IMPERSONATE", Value: "false"})

			// Calico clusters use Goldmane for policy metrics and stats.
			env = append(env, corev1.EnvVar{Name: "GOLDMANE_ENABLED", Value: "true"})

			env = append(env, corev1.EnvVar{Name: "L7_LOGS_ENABLED", Value: "false"})
			env = append(env, corev1.EnvVar{Name: "DNS_LOGS_ENABLED", Value: "false"})
			env = append(env, corev1.EnvVar{Name: "EVENTS_ENABLED", Value: "false"})
		}
	}

	volumeMounts := append(
		c.cfg.TrustedCertBundle.VolumeMounts(c.SupportedOSType()),
		c.cfg.InternalTLSKeyPair.VolumeMount(c.SupportedOSType()),
	)
	if c.cfg.ManagementCluster != nil {
		env = append(env, corev1.EnvVar{Name: "VOLTRON_CA_PATH", Value: certificatemanagement.TrustedCertBundleMountPath})
	}

	if c.cfg.KeyValidatorConfig != nil {
		env = append(env, c.cfg.KeyValidatorConfig.RequiredEnv("")...)
	}

	return corev1.Container{
		Name:            UIAPIsName,
		Image:           c.calicoImage,
		Command:         []string{components.CalicoBinaryPath, "component", "ui-apis"},
		LivenessProbe:   c.managerUIAPIsProbe(),
		SecurityContext: securitycontext.NewNonRootContext(),
		Env:             env,
		VolumeMounts:    volumeMounts,
	}
}

// managerTolerations returns the tolerations for the Tigera Secure manager deployment pods.
func (c *managerComponent) managerTolerations() []corev1.Toleration {
	tolerations := append(c.cfg.Installation.ControlPlaneTolerations, rmeta.TolerateCriticalAddonsAndControlPlane...)
	if c.cfg.Installation.KubernetesProvider.IsGKE() {
		tolerations = append(tolerations, rmeta.TolerateGKEARM64NoSchedule)
	}
	return tolerations
}

// managerService returns the service exposing the Tigera Secure web app.
func (c *managerComponent) managerService() *corev1.Service {
	return &corev1.Service{
		TypeMeta: metav1.TypeMeta{Kind: "Service", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      ManagerServiceName,
			Namespace: c.cfg.Namespace,
		},
		Spec: corev1.ServiceSpec{
			Ports: []corev1.ServicePort{
				{
					// OpenShift's Ingress→Route conversion requires a named target port.
					Name:       ManagerPortName,
					Port:       ManagerPort,
					Protocol:   corev1.ProtocolTCP,
					TargetPort: intstr.FromInt(managerTargetPort),
				},
			},
			Selector: map[string]string{
				"k8s-app": ManagerDeploymentName,
			},
		},
	}
}

func (c *managerComponent) managerLegacyNamespace() *corev1.Namespace {
	return CreateNamespace(LegacyManagerNamespace, c.cfg.Installation.KubernetesProvider, PSSRestricted, c.cfg.Installation.Azure)
}

// managerExternalNameService acts as a safety net for migration of manager service from legacy namespace (tigera-manager)
// to new namespace (calico-system) and from legacy name (tigera-manager) to new name (calico-manager)
func (c *managerComponent) managerExternalNameService() *corev1.Service {
	var legacyNamespace string
	if c.cfg.Tenant.MultiTenant() {
		// For multi-tenant case the old service reference will be to the same namespace just with a different name eg.
		// tigera-manager.cc-tenant-1234 vs calico-manager.cc-tenant-1234
		legacyNamespace = c.cfg.Namespace
	} else {
		legacyNamespace = LegacyManagerNamespace
	}
	return &corev1.Service{
		TypeMeta: metav1.TypeMeta{Kind: "Service", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      LegacyManagerServiceName,
			Namespace: legacyNamespace,
		},
		Spec: corev1.ServiceSpec{
			Type:         corev1.ServiceTypeExternalName,
			ExternalName: fmt.Sprintf("%s.%s.svc.cluster.local", ManagerServiceName, c.cfg.Namespace),
		},
	}
}

// managerServiceAccount creates the serviceaccount used by the Tigera Secure web app.
func managerServiceAccount(ns string) *corev1.ServiceAccount {
	return &corev1.ServiceAccount{
		TypeMeta:   metav1.TypeMeta{Kind: "ServiceAccount", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{Name: ManagerServiceAccount, Namespace: ns},
	}
}

func managerClusterRoleBinding(tenant *operatorv1.Tenant, namespaces, calicoNamespaces []string) client.Object {
	// Different tenant types use different permission sets.
	roleName := ManagerClusterRole
	bindingName := ManagerClusterRoleBinding
	chosenNamespaces := namespaces
	if tenant.ManagedClusterIsCalico() {
		roleName = ManagerManagedCalicoClusterRole
		bindingName = ManagerManagedCalicoClusterRoleBinding
		chosenNamespaces = calicoNamespaces
	}
	return rcomponents.ClusterRoleBinding(bindingName, roleName, ManagerServiceAccount, chosenNamespaces)
}

func (c *managerComponent) managedClustersWatchRoleBinding() client.Object {
	if c.cfg.Tenant.MultiTenant() {
		return rcomponents.RoleBinding(ManagerManagedClustersWatchRoleBindingName, ManagedClustersWatchClusterRoleName, ManagerServiceAccount, c.cfg.Namespace)
	} else {
		return rcomponents.ClusterRoleBinding(ManagerManagedClustersWatchRoleBindingName, ManagedClustersWatchClusterRoleName, ManagerServiceAccount, []string{c.cfg.Namespace})
	}
}

func (c *managerComponent) managedClustersUpdateRBAC() []client.Object {
	if c.cfg.Tenant.MultiTenant() {
		return []client.Object{
			&rbacv1.Role{
				TypeMeta:   metav1.TypeMeta{Kind: "Role", APIVersion: "rbac.authorization.k8s.io/v1"},
				ObjectMeta: metav1.ObjectMeta{Name: ManagerManagedClustersUpdateRBACName, Namespace: c.cfg.Namespace},
				Rules: []rbacv1.PolicyRule{
					{
						APIGroups: []string{"projectcalico.org"},
						Resources: []string{"managedclusters", "managedclusters/status"},
						Verbs:     []string{"update"},
					},
				},
			},
			&rbacv1.RoleBinding{
				TypeMeta:   metav1.TypeMeta{Kind: "RoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"},
				ObjectMeta: metav1.ObjectMeta{Name: ManagerManagedClustersUpdateRBACName, Namespace: c.cfg.Namespace},
				RoleRef: rbacv1.RoleRef{
					APIGroup: "rbac.authorization.k8s.io",
					Kind:     "Role",
					Name:     ManagerManagedClustersUpdateRBACName,
				},
				Subjects: []rbacv1.Subject{
					{
						Kind:      "ServiceAccount",
						Name:      ManagerServiceName,
						Namespace: c.cfg.Namespace,
					},
				},
			},
		}
	}

	return []client.Object{
		&rbacv1.ClusterRole{
			TypeMeta:   metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"},
			ObjectMeta: metav1.ObjectMeta{Name: ManagerManagedClustersUpdateRBACName},
			Rules: []rbacv1.PolicyRule{
				{
					APIGroups: []string{"projectcalico.org"},
					Resources: []string{"managedclusters", "managedclusters/status"},
					Verbs:     []string{"update"},
				},
			},
		},
		&rbacv1.ClusterRoleBinding{
			TypeMeta:   metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"},
			ObjectMeta: metav1.ObjectMeta{Name: ManagerManagedClustersUpdateRBACName},
			RoleRef: rbacv1.RoleRef{
				APIGroup: "rbac.authorization.k8s.io",
				Kind:     "ClusterRole",
				Name:     ManagerManagedClustersUpdateRBACName,
			},
			Subjects: []rbacv1.Subject{
				{
					Kind:      "ServiceAccount",
					Name:      ManagerServiceName,
					Namespace: c.cfg.Namespace,
				},
			},
		},
	}
}

// managerClusterRole returns a clusterrole that allows authn/authz review requests.
// When rbacManagementEnabled is true it also carries the RBAC management UI rules.
func managerClusterRole(managedCluster bool, kubernetesProvider operatorv1.Provider, tenant *operatorv1.Tenant, rbacManagementEnabled bool) *rbacv1.ClusterRole {
	// Different tenant types use different permission sets.
	name := ManagerClusterRole
	if tenant.ManagedClusterIsCalico() {
		name = ManagerManagedCalicoClusterRole
	}

	cr := &rbacv1.ClusterRole{
		TypeMeta:   metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Rules: []rbacv1.PolicyRule{
			{
				APIGroups: []string{"authorization.k8s.io"},
				Resources: []string{"subjectaccessreviews"},
				Verbs:     []string{"create"},
			},
			{
				APIGroups: []string{"authentication.k8s.io"},
				Resources: []string{"tokenreviews"},
				Verbs:     []string{"create"},
			},
			{
				APIGroups: []string{"projectcalico.org"},
				Resources: []string{
					"networksets",
					"globalnetworksets",
					"globalnetworkpolicies",
					"tier.globalnetworkpolicies",
					"networkpolicies",
					"tier.networkpolicies",
					"stagedglobalnetworkpolicies",
					"tier.stagedglobalnetworkpolicies",
					"stagednetworkpolicies",
					"tier.stagednetworkpolicies",
					"stagedkubernetesnetworkpolicies",
				},
				Verbs: []string{"list"},
			},
			{
				// ui-apis needs read access to UISettings and UISettingsGroups to serve
				// requests on behalf of users. It performs SubjectAccessReviews to enforce
				// per-group RBAC before returning results.
				APIGroups: []string{"projectcalico.org"},
				Resources: []string{
					"uisettings",
					"uisettingsgroups",
					"uisettingsgroups/data",
				},
				Verbs: []string{"get", "list", "watch"},
			},
			{
				// Delete is granted on the leaf UISettings resource (the ui-apis DELETE
				// handler issues this call with its own SA token after the cloud security
				// fix moved writes off user impersonation). The aggregated apiserver
				// gates leaf writes on the uisettingsgroups/data subresource RBAC, so
				// delete is granted there too. The bare uisettingsgroups resource is
				// intentionally omitted — ui-apis never deletes groups themselves.
				APIGroups: []string{"projectcalico.org"},
				Resources: []string{"uisettings", "uisettingsgroups/data"},
				Verbs:     []string{"delete"},
			},
			{
				// ClusterInformation read: surfaces the management-cluster version in the UI.
				// Served by the ui-apis ClusterInformation handler using its own SA token.
				APIGroups: []string{"projectcalico.org"},
				Resources: []string{"clusterinformations"},
				Verbs:     []string{"get", "list"},
			},
			{
				APIGroups: []string{"projectcalico.org"},
				Resources: []string{
					"stagednetworkpolicies",
					"tier.stagednetworkpolicies",
				},
				Verbs: []string{"patch"},
			},
			{
				APIGroups: []string{"projectcalico.org"},
				Resources: []string{
					"tiers",
				},
				Verbs: []string{"get", "list"},
			},
			{
				APIGroups: []string{"projectcalico.org"},
				Resources: []string{
					"hostendpoints",
				},
				Verbs: []string{"list"},
			},
			// Allow Enterprise Custom Dashboards to access managed clusters. Create/delete
			// were added when the ui-apis ManagedCluster handler took over CRUD with its
			// own SA token (replacing the impersonated /apis/.../managedclusters proxy).
			// Update is granted separately via managedClustersUpdateRBAC().
			{
				APIGroups: []string{"projectcalico.org"},
				Resources: []string{"managedclusters"},
				Verbs:     []string{"get", "list", "watch", "create", "delete"},
			},
			{
				APIGroups: []string{"projectcalico.org"},
				Resources: []string{
					"felixconfigurations",
				},
				ResourceNames: []string{
					"default",
				},
				Verbs: []string{"get"},
			},
			{
				APIGroups: []string{"projectcalico.org"},
				Resources: []string{
					"alertexceptions",
				},
				Verbs: []string{"get", "list", "update"},
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
				// Get:  required by Voltron to validate non-cluster host service accounts
				//       when handling proxied requests for the Kubernetes API server.
				// List: required by Voltron when performing impersonation for components
				//       such as Compliance.
				APIGroups: []string{""},
				Resources: []string{"serviceaccounts"},
				Verbs:     []string{"get", "list"},
			},
			{
				APIGroups: []string{""},
				Resources: []string{"namespaces", "nodes", "events", "services", "pods"},
				Verbs:     []string{"list"},
			},
			{
				APIGroups: []string{"apps"},
				Resources: []string{"replicasets", "statefulsets", "daemonsets"},
				Verbs:     []string{"list"},
			},
			// When a request is made in the manager UI, they are proxied through the Voltron backend server. If the
			// request is targeting a k8s api or when it is targeting a managed cluster, Voltron will authenticate the
			// user based on the auth header and then impersonate the user.
			{
				APIGroups: []string{""},
				Resources: []string{"users", "groups", "serviceaccounts"},
				Verbs:     []string{"impersonate"},
			},
			// Allow query server talk to Prometheus via the manager user.
			{
				APIGroups: []string{""},
				Resources: []string{"services/proxy"},
				ResourceNames: []string{
					"https:calico-api:8080", "calico-node-prometheus:9090",
				},
				Verbs: []string{"get", "create"},
			},
			{
				// Add access to Linseed APIs. Those multi-cluster variants are for Linseed to query across multiple
				// clusters for Enterprise Custom Dashboards.
				APIGroups: []string{"linseed.tigera.io"},
				Resources: []string{
					"flows",
					"flowlogs",
					"flowlogs-multi-cluster",
					"bgplogs",
					"auditlogs",
					"dnsflows",
					"dnslogs",
					"dnslogs-multi-cluster",
					"l7flows",
					"l7logs",
					"l7logs-multi-cluster",
					"events",
					"processes",
					"policyactivity",
				},
				Verbs: []string{"get"},
			},
			{
				// Dismiss events.
				APIGroups: []string{"linseed.tigera.io"},
				Resources: []string{
					"events",
				},
				Verbs: []string{"dismiss", "delete"},
			},
			{
				// Required by the AuthorizationReview calculator in ui-apis to evaluate
				// RBAC permissions for users.
				APIGroups: []string{"rbac.authorization.k8s.io"},
				Resources: []string{"clusterroles", "clusterrolebindings", "roles", "rolebindings"},
				Verbs:     []string{"get", "list", "watch"},
			},
		},
	}

	// Not rendered on multi-tenant management clusters. Keep this condition in
	// sync with the rbacManagementUINamespacedRole gate; the cluster rules and
	// the namespaced grant are rendered together.
	if rbacManagementEnabled && !tenant.MultiTenant() {
		cr.Rules = append(cr.Rules, rbacManagementUIRules()...)
	}

	if tenant.MultiTenant() {
		cr.Rules = append(cr.Rules,
			rbacv1.PolicyRule{
				APIGroups: []string{"authorization.k8s.io"},
				Resources: []string{"localsubjectaccessreviews"},
				Verbs:     []string{"create"},
			},
		)

		if tenant.ManagedClusterIsCalico() {
			// Voltron needs permissions to write flow logs.
			cr.Rules = append(cr.Rules,
				rbacv1.PolicyRule{
					APIGroups: []string{"linseed.tigera.io"},
					Resources: []string{"flowlogs"},
					Verbs:     []string{"create"},
				})
		}
	}

	if kubernetesProvider.IsOpenShift() {
		cr.Rules = append(cr.Rules,
			rbacv1.PolicyRule{
				APIGroups:     []string{"security.openshift.io"},
				Resources:     []string{"securitycontextconstraints"},
				Verbs:         []string{"use"},
				ResourceNames: []string{securitycontextconstraints.NonRootV2},
			},
		)
	}

	return cr
}

// rbacManagementUIRules returns the cluster-scoped rules the RBAC management
// UI adds to calico-manager-role. Named-resource access is scoped separately
// on rbacManagementUINamespacedRole.
func rbacManagementUIRules() []rbacv1.PolicyRule {
	return []rbacv1.PolicyRule{
		{
			// Lets ui-apis read the Compliance CR (the operator singleton) so the
			// UI can tell whether compliance is installed before offering
			// compliance-scoped RBAC.
			APIGroups: []string{"operator.tigera.io"},
			Resources: []string{"compliances"},
			Verbs:     []string{"get"},
		},
	}
}

// rbacManagementUINamespacedRole returns the Role + RoleBinding that scopes
// the RBAC management UI's Secret/ConfigMap access to calico-system, where
// tigera-idp-groups and tigera-idp-ldap-config live.
func (c *managerComponent) rbacManagementUINamespacedRole() []client.Object {
	return []client.Object{
		&rbacv1.Role{
			TypeMeta:   metav1.TypeMeta{Kind: "Role", APIVersion: "rbac.authorization.k8s.io/v1"},
			ObjectMeta: metav1.ObjectMeta{Name: ManagerClusterRole, Namespace: common.CalicoNamespace},
			Rules: []rbacv1.PolicyRule{
				{
					// create carries the object name in the request body, not the
					// URL path, so RBAC cannot restrict it by resource name; it is
					// scoped to this namespace instead.
					APIGroups: []string{""},
					Resources: []string{"configmaps", "secrets"},
					Verbs:     []string{"create"},
				},
				{
					APIGroups:     []string{""},
					Resources:     []string{"secrets"},
					ResourceNames: []string{RBACManagementLDAPConfigSecretName},
					Verbs:         []string{"get", "list", "watch", "update", "patch", "delete"},
				},
				{
					APIGroups:     []string{""},
					Resources:     []string{"configmaps"},
					ResourceNames: []string{"tigera-idp-groups"},
					Verbs:         []string{"get", "list", "watch", "update", "patch", "delete"},
				},
			},
		},
		&rbacv1.RoleBinding{
			TypeMeta:   metav1.TypeMeta{Kind: "RoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"},
			ObjectMeta: metav1.ObjectMeta{Name: ManagerClusterRole, Namespace: common.CalicoNamespace},
			RoleRef: rbacv1.RoleRef{
				APIGroup: "rbac.authorization.k8s.io",
				Kind:     "Role",
				Name:     ManagerClusterRole,
			},
			Subjects: []rbacv1.Subject{
				{
					Kind:      "ServiceAccount",
					Name:      ManagerServiceAccount,
					Namespace: c.cfg.Namespace,
				},
			},
		},
	}
}

func (c *managerComponent) getTLSObjects() []client.Object {
	objs := []client.Object{}
	for _, s := range c.tlsSecrets {
		objs = append(objs, s)
	}

	return objs
}

// Allow users to access Calico Enterprise Manager.
func (c *managerComponent) managerCalicoSystemNetworkPolicy() *v3.NetworkPolicy {
	networkpolicyHelper := networkpolicy.Helper(c.cfg.Tenant.MultiTenant(), c.cfg.Namespace)
	egressRules := []v3.Rule{
		{
			Action:      v3.Allow,
			Protocol:    &networkpolicy.TCPProtocol,
			Destination: networkpolicyHelper.ManagerEntityRule(),
		},
		{
			Action:      v3.Allow,
			Protocol:    &networkpolicy.TCPProtocol,
			Destination: TigeraAPIServerEntityRule,
		},
		{
			Action:      v3.Allow,
			Protocol:    &networkpolicy.TCPProtocol,
			Source:      v3.EntityRule{},
			Destination: networkpolicyHelper.ESGatewayEntityRule(),
		},
		{
			Action:      v3.Allow,
			Protocol:    &networkpolicy.TCPProtocol,
			Source:      v3.EntityRule{},
			Destination: networkpolicyHelper.LinseedEntityRule(),
		},
		{
			Action:      v3.Allow,
			Protocol:    &networkpolicy.TCPProtocol,
			Destination: networkpolicyHelper.ComplianceServerEntityRule(),
		},
		{
			Action:      v3.Allow,
			Protocol:    &networkpolicy.TCPProtocol,
			Destination: DexEntityRule,
		},
		{
			Action:      v3.Allow,
			Protocol:    &networkpolicy.TCPProtocol,
			Destination: PacketCaptureEntityRule,
		},
		{
			Action:      v3.Allow,
			Protocol:    &networkpolicy.TCPProtocol,
			Destination: networkpolicy.KubeAPIServerEntityRule,
		},
	}

	if c.cfg.NonClusterHost != nil {
		egressRules = append(egressRules, v3.Rule{
			Action:   v3.Allow,
			Protocol: &networkpolicy.TCPProtocol,
			Destination: v3.EntityRule{
				Services: &v3.ServiceMatch{
					Namespace: LogCollectorNamespace,
					Name:      FluentBitInputService,
				},
			},
		})
	}

	if c.cfg.Manager.RBACManagementEnabled() && !c.cfg.Tenant.MultiTenant() &&
		c.cfg.Authentication != nil && c.cfg.Authentication.Spec.LDAP != nil {
		// LDAP/AD egress (389, 636) for the RBAC-UI directory sync, gated on LDAP
		// being configured on the Authentication CR. The destination is scoped to
		// Authentication.spec.ldap.host — a domain match for a hostname or a
		// /32/128 for a literal IP. Both standard ports stay open (the host may
		// specify a non-standard port; scoping the port too would risk denying a
		// valid config), so only the host is narrowed.
		dest := v3.EntityRule{Ports: networkpolicy.Ports(389, 636)}
		if host := ldapEgressHost(c.cfg.Authentication.Spec.LDAP.Host); host != "" {
			if ip := net.ParseIP(host); ip != nil {
				suffix := "/32"
				if ip.To4() == nil {
					suffix = "/128"
				}
				dest.Nets = []string{ip.String() + suffix}
			} else {
				dest.Domains = []string{host}
			}
		}
		egressRules = append(egressRules, v3.Rule{
			Action:      v3.Allow,
			Protocol:    &networkpolicy.TCPProtocol,
			Destination: dest,
		})
	}

	egressRules = networkpolicy.AppendDNSEgressRules(egressRules, c.cfg.OpenShift)
	egressRules = append(egressRules, v3.Rule{
		Action:      v3.Allow,
		Protocol:    &networkpolicy.TCPProtocol,
		Destination: networkpolicy.PrometheusEntityRule,
	})

	ingressRules := []v3.Rule{
		{
			Action:   v3.Allow,
			Protocol: &networkpolicy.TCPProtocol,
			Source: v3.EntityRule{
				// This policy allows access to Calico Enterprise Manager from anywhere
				Nets: []string{"0.0.0.0/0"},
			},
			Destination: v3.EntityRule{
				// By default, Calico Enterprise Manager is accessed over https
				Ports: networkpolicy.Ports(managerTargetPort),
			},
		},
		{
			Action:   v3.Allow,
			Protocol: &networkpolicy.TCPProtocol,
			Source: v3.EntityRule{
				// This policy allows access to Calico Enterprise Manager from anywhere
				Nets: []string{"::/0"},
			},
			Destination: v3.EntityRule{
				// By default, Calico Enterprise Manager is accessed over https
				Ports: networkpolicy.Ports(managerTargetPort),
			},
		},
	}

	voltronTunnelPort, err := strconv.ParseUint(defaultTunnelVoltronPort, 10, 16)
	if err == nil {
		ingressRules = append(ingressRules, v3.Rule{
			Action:   v3.Allow,
			Protocol: &networkpolicy.TCPProtocol,
			Source:   v3.EntityRule{},
			Destination: v3.EntityRule{
				// This policy is used for multi-cluster management to establish a tunnel from another cluster.
				Ports: networkpolicy.Ports(uint16(voltronTunnelPort)),
			},
		})
	}

	return &v3.NetworkPolicy{
		TypeMeta: metav1.TypeMeta{Kind: "NetworkPolicy", APIVersion: "projectcalico.org/v3"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      ManagerPolicyName,
			Namespace: c.cfg.Namespace,
		},
		Spec: v3.NetworkPolicySpec{
			Order:    &networkpolicy.HighPrecedenceOrder,
			Tier:     networkpolicy.CalicoTierName,
			Selector: networkpolicy.KubernetesAppSelector(ManagerDeploymentName),
			Types:    []v3.PolicyType{v3.PolicyTypeIngress, v3.PolicyTypeEgress},
			Ingress:  ingressRules,
			Egress:   egressRules,
		},
	}
}

// ldapEgressHost returns the host (without port) from an
// Authentication.spec.ldap.host value, used to scope the manager's LDAP egress
// policy. The value carries an optional port (e.g. "ad.example.com:636"); when
// no port is present the value is already the host. IPv6 literals are returned
// unbracketed so the caller can parse them with net.ParseIP.
func ldapEgressHost(host string) string {
	if h, _, err := net.SplitHostPort(host); err == nil {
		return h
	}
	return strings.TrimSuffix(strings.TrimPrefix(host, "["), "]")
}

func (c *managerComponent) multiTenantManagedClustersAccess() []client.Object {
	var objects []client.Object

	// In a single tenant setup we want to create a role that binds using service account
	// tigera-manager from tigera-manager namespace. In a multi-tenant setup
	// ui-apis from the tenant's namespace impersonates service tigera-manager
	// from tigera-manager namespace
	objects = append(objects, &rbacv1.RoleBinding{
		TypeMeta:   metav1.TypeMeta{Kind: "RoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{Name: ManagerMultiTenantManagedClustersAccessClusterRoleBindingName, Namespace: c.cfg.Namespace},
		RoleRef: rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "ClusterRole",
			Name:     MultiTenantManagedClustersAccessClusterRoleName,
		},
		Subjects: []rbacv1.Subject{
			// requests from ui-apis to managed clusters are done using service account tigera-manager
			// from tigera-manager namespace regardless of tenancy mode (single tenant or multi-tenant)
			{
				Kind:      "ServiceAccount",
				Name:      ManagerServiceName,
				Namespace: ManagerNamespace,
			},
		},
	})

	return objects
}

// managerClusterWideSettingsGroup returns a UISettingsGroup with the description "cluster-wide settings"
//
// Calico Enterprise only
func managerClusterWideSettingsGroup() *v3.UISettingsGroup {
	return &v3.UISettingsGroup{
		TypeMeta: metav1.TypeMeta{Kind: "UISettingsGroup", APIVersion: "projectcalico.org/v3"},
		ObjectMeta: metav1.ObjectMeta{
			Name: ManagerClusterSettings,
		},
		Spec: v3.UISettingsGroupSpec{
			Description: "Cluster Settings",
		},
	}
}

// managerUserSpecificSettingsGroup returns a UISettingsGroup with the description "user settings"
//
// Calico Enterprise only
func managerUserSpecificSettingsGroup() *v3.UISettingsGroup {
	return &v3.UISettingsGroup{
		TypeMeta: metav1.TypeMeta{Kind: "UISettingsGroup", APIVersion: "projectcalico.org/v3"},
		ObjectMeta: metav1.ObjectMeta{
			Name: ManagerUserSettings,
		},
		Spec: v3.UISettingsGroupSpec{
			Description: "User Settings",
			FilterType:  v3.FilterTypeUser,
		},
	}
}

// managerClusterWideTigeraLayer returns a UISettings layer belonging to the cluster-wide settings group that contains
// all of the tigera namespaces.
//
// Calico Enterprise only
func managerClusterWideTigeraLayer() *v3.UISettings {
	namespaces := []string{
		"tigera-compliance",
		"tigera-dex",
		"tigera-dpi",
		"tigera-eck-operator",
		"tigera-elasticsearch",
		"tigera-intrusion-detection",
		"tigera-kibana",
		"tigera-manager",
		"tigera-operator",
		"tigera-packetcapture",
		"tigera-prometheus",
		"calico-system",
		"tigera-firewall-controller",
		"calico-cloud",
		"tigera-image-assurance",
		"tigera-runtime-security",
		"tigera-skraper",
	}
	nodes := make([]v3.UIGraphNode, len(namespaces))
	for i := range namespaces {
		ns := namespaces[i]
		nodes[i] = v3.UIGraphNode{
			ID:   "namespace/" + ns,
			Type: "namespace",
			Name: ns,
		}
	}

	return &v3.UISettings{
		TypeMeta: metav1.TypeMeta{Kind: "UISettings", APIVersion: "projectcalico.org/v3"},
		ObjectMeta: metav1.ObjectMeta{
			Name: ManagerClusterSettingsLayerTigera,
		},
		Spec: v3.UISettingsSpec{
			Group:       "cluster-settings",
			Description: "Tigera Infrastructure",
			Layer: &v3.UIGraphLayer{
				Nodes: nodes,
			},
		},
	}
}

// managerClusterWideDefaultView returns a UISettings view belonging to the cluster-wide settings group that shows
// everything and uses the tigera-infrastructure layer.
//
// Calico Enterprise only
func managerClusterWideDefaultView() *v3.UISettings {
	return &v3.UISettings{
		TypeMeta: metav1.TypeMeta{Kind: "UISettings", APIVersion: "projectcalico.org/v3"},
		ObjectMeta: metav1.ObjectMeta{
			Name: ManagerClusterSettingsViewDefault,
		},
		Spec: v3.UISettingsSpec{
			Group:       "cluster-settings",
			Description: "Default",
			View: &v3.UIGraphView{
				Nodes: []v3.UIGraphNodeView{{
					UIGraphNode: v3.UIGraphNode{
						ID:   "layer/cluster-settings.layer.tigera-infrastructure",
						Type: "layer",
						Name: "cluster-settings.layer.tigera-infrastructure",
					},
				}},
			},
		},
	}
}

// These resources became deprecated in Calico Enterprise v3.23 which corresponds to operator version <todo>. This function
// can be removed for Calico Enterprise v3.26 which corresponds to operator version <todo> when the legacy names will no
// longer be valid in our official support window
func (m *managerComponent) deprecatedResources(tenant *operatorv1.Tenant, installNS, truthNS string) []client.Object {
	objs := []client.Object{}
	clusterRoleName := LegacyManagerClusterRole
	clusterRoleBindingName := LegacyManagerClusterRoleBinding
	managedClustersWatchRoleBindingName := LegacyManagerManagedClustersWatchRoleBindingName
	managedClustersUpdateRBACName := LegacyManagerManagedClustersUpdateRBACName
	multiTenantManagedClustersAccessName := LegacyManagerMultiTenantManagedClustersAccessClusterRoleBindingName
	if tenant.ManagedClusterIsCalico() {
		clusterRoleName = LegacyManagerManagedCalicoClusterRole
		clusterRoleBindingName = LegacyManagerManagedCalicoClusterRoleBinding
	}

	var legacyNamespace string
	if m.cfg.Tenant.MultiTenant() {
		// For multi-tenant case the old service reference will be to the same namespace just with a different name eg.
		// tigera-manager.cc-tenant-1234 vs calico-manager.cc-tenant-1234
		legacyNamespace = installNS
	} else {
		legacyNamespace = LegacyManagerNamespace
	}

	var managedClustersWatchObj client.Object
	var managedClustersUpdateRBACObjs []client.Object
	if tenant.MultiTenant() {
		managedClustersWatchObj = &rbacv1.RoleBinding{
			TypeMeta:   metav1.TypeMeta{Kind: "RoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"},
			ObjectMeta: metav1.ObjectMeta{Namespace: legacyNamespace},
		}

		managedClustersUpdateRBACObjs = []client.Object{
			&rbacv1.Role{
				TypeMeta:   metav1.TypeMeta{Kind: "Role", APIVersion: "rbac.authorization.k8s.io/v1"},
				ObjectMeta: metav1.ObjectMeta{Namespace: legacyNamespace},
			},
			&rbacv1.RoleBinding{
				TypeMeta:   metav1.TypeMeta{Kind: "RoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"},
				ObjectMeta: metav1.ObjectMeta{Namespace: legacyNamespace},
			},
		}

		objs = append(objs,
			&rbacv1.RoleBinding{
				TypeMeta:   metav1.TypeMeta{Kind: "RoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"},
				ObjectMeta: metav1.ObjectMeta{Name: multiTenantManagedClustersAccessName, Namespace: legacyNamespace},
			},
		)
	} else {
		managedClustersWatchObj = &rbacv1.ClusterRoleBinding{
			TypeMeta: metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"},
		}
		managedClustersUpdateRBACObjs = []client.Object{
			&rbacv1.ClusterRole{
				TypeMeta: metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"},
			},
			&rbacv1.ClusterRoleBinding{
				TypeMeta: metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"},
			},
		}
		objs = append(objs,
			networkpolicy.DeprecatedAllowTigeraNetworkPolicyObject("manager-access", legacyNamespace),
			networkpolicy.DeprecatedAllowTigeraNetworkPolicyObject("default-deny", legacyNamespace),
		)
	}

	managedClustersWatchObj.SetName(managedClustersWatchRoleBindingName)
	for _, o := range managedClustersUpdateRBACObjs {
		o.SetName(managedClustersUpdateRBACName)
	}

	objs = append(objs, managedClustersWatchObj)
	objs = append(objs, managedClustersUpdateRBACObjs...)

	objs = append(objs,
		&rbacv1.ClusterRole{
			TypeMeta:   metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"},
			ObjectMeta: metav1.ObjectMeta{Name: clusterRoleName},
		},
		&rbacv1.ClusterRoleBinding{
			TypeMeta:   metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"},
			ObjectMeta: metav1.ObjectMeta{Name: clusterRoleBindingName},
		},
		&appsv1.Deployment{
			TypeMeta:   metav1.TypeMeta{Kind: "Deployment", APIVersion: "apps/v1"},
			ObjectMeta: metav1.ObjectMeta{Name: LegacyManagerServiceName, Namespace: legacyNamespace},
		},
		&corev1.ServiceAccount{
			TypeMeta:   metav1.TypeMeta{Kind: "ServiceAccount", APIVersion: "v1"},
			ObjectMeta: metav1.ObjectMeta{Name: LegacyManagerServiceName, Namespace: legacyNamespace},
		},
		&corev1.Secret{
			TypeMeta:   metav1.TypeMeta{Kind: "Secret", APIVersion: "v1"},
			ObjectMeta: metav1.ObjectMeta{Name: LegacyVoltronLinseedPublicCert, Namespace: truthNS},
		},
	)

	// allow-tigera Tier was renamed to calico-system
	objs = append(objs,
		networkpolicy.DeprecatedAllowTigeraNetworkPolicyObject("manager-access", installNS),
		networkpolicy.DeprecatedAllowTigeraNetworkPolicyObject("default-deny", installNS),
	)

	return objs
}
