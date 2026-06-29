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
	"crypto/x509"
	"fmt"
	"net/url"
	"strings"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/apiserver/pkg/authentication/serviceaccount"
	"sigs.k8s.io/controller-runtime/pkg/client"

	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/components"
	"github.com/tigera/operator/pkg/render/common/authentication"
	rcomponents "github.com/tigera/operator/pkg/render/common/components"
	"github.com/tigera/operator/pkg/render/common/configmap"
	relasticsearch "github.com/tigera/operator/pkg/render/common/elasticsearch"
	rmeta "github.com/tigera/operator/pkg/render/common/meta"
	"github.com/tigera/operator/pkg/render/common/networkpolicy"
	"github.com/tigera/operator/pkg/render/common/secret"
	"github.com/tigera/operator/pkg/render/common/securitycontext"
	"github.com/tigera/operator/pkg/render/common/securitycontextconstraints"
	"github.com/tigera/operator/pkg/tls/certificatemanagement"
	"github.com/tigera/operator/pkg/tls/certkeyusage"
)

const (
	ComplianceNamespace                                       = "tigera-compliance"
	ComplianceServiceName                                     = "compliance"
	ComplianceServerName                                      = "compliance-server"
	ComplianceControllerName                                  = "compliance-controller"
	ComplianceSnapshotterName                                 = "compliance-snapshotter"
	ComplianceReporterName                                    = "compliance-reporter"
	ComplianceBenchmarkerName                                 = "compliance-benchmarker"
	ComplianceAccessPolicyName                                = networkpolicy.CalicoComponentPolicyPrefix + "compliance-access"
	ComplianceServerPolicyName                                = networkpolicy.CalicoComponentPolicyPrefix + ComplianceServerName
	MultiTenantComplianceManagedClustersAccessRoleBindingName = "compliance-server-managed-cluster-access"

	// ServiceAccount names.
	ComplianceServerServiceAccount      = "tigera-compliance-server"
	ComplianceSnapshotterServiceAccount = "tigera-compliance-snapshotter"
	ComplianceBenchmarkerServiceAccount = "tigera-compliance-benchmarker"
	ComplianceReporterServiceAccount    = "tigera-compliance-reporter"
	ComplianceControllerServiceAccount  = "tigera-compliance-controller"
)

const (
	ElasticsearchCuratorUserSecret = "tigera-ee-curator-elasticsearch-access"

	ComplianceServerCertSecret  = "tigera-compliance-server-tls"
	ComplianceSnapshotterSecret = "tigera-compliance-snapshotter-tls"
	ComplianceBenchmarkerSecret = "tigera-compliance-benchmarker-tls"
	ComplianceControllerSecret  = "tigera-compliance-controller-tls"
	ComplianceReporterSecret    = "tigera-compliance-reporter-tls"
)

// Register secret/certs that need Server and Client Key usage
func init() {
	certkeyusage.SetCertKeyUsage(ComplianceServerCertSecret, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth})
	certkeyusage.SetCertKeyUsage(ComplianceSnapshotterSecret, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth})
	certkeyusage.SetCertKeyUsage(ComplianceBenchmarkerSecret, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth})
	certkeyusage.SetCertKeyUsage(ComplianceReporterSecret, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth})
}

func Compliance(cfg *ComplianceConfiguration) (Component, error) {
	return &complianceComponent{
		cfg: cfg,
	}, nil
}

// ComplianceConfiguration contains all the config information needed to render the component.
type ComplianceConfiguration struct {
	Installation                *operatorv1.InstallationSpec
	PullSecrets                 []*corev1.Secret
	OpenShift                   bool
	ManagementCluster           *operatorv1.ManagementCluster
	ManagementClusterConnection *operatorv1.ManagementClusterConnection
	KeyValidatorConfig          authentication.KeyValidatorConfig
	ClusterDomain               string
	HasNoLicense                bool

	// Trusted certificate bundle for all compliance pods.
	TrustedBundle certificatemanagement.TrustedBundleRO

	// Key pairs used for mTLS.
	ServerKeyPair      certificatemanagement.KeyPairInterface
	BenchmarkerKeyPair certificatemanagement.KeyPairInterface
	ReporterKeyPair    certificatemanagement.KeyPairInterface
	SnapshotterKeyPair certificatemanagement.KeyPairInterface
	ControllerKeyPair  certificatemanagement.KeyPairInterface

	Namespace         string
	BindingNamespaces []string

	// Whether to run the rendered components in multi-tenant, single-tenant, or zero-tenant mode
	Tenant          *operatorv1.Tenant
	ExternalElastic bool
	Compliance      *operatorv1.Compliance

	// Cloud indicates compliance is being rendered for a Calico Cloud install. When false the cloud
	// NetworkPolicy below is not created and enterprise behavior is unchanged.
	Cloud bool
}

type complianceComponent struct {
	cfg              *ComplianceConfiguration
	benchmarkerImage string
	calicoImage      string
}

func (c *complianceComponent) ResolveImages(is *operatorv1.ImageSet) error {
	reg := c.cfg.Installation.Registry
	path := c.cfg.Installation.ImagePath
	prefix := c.cfg.Installation.ImagePrefix
	var err error
	errMsgs := []string{}

	c.benchmarkerImage, err = components.GetReference(components.ComponentComplianceBenchmarker, reg, path, prefix, is)
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
	return nil
}

func (c *complianceComponent) SupportedOSType() rmeta.OSType {
	return rmeta.OSTypeLinux
}

func (c *complianceComponent) Objects() ([]client.Object, []client.Object) {
	var complianceObjs, objsToDelete []client.Object
	if c.cfg.Tenant.MultiTenant() {
		complianceObjs = append(complianceObjs, c.multiTenantManagedClustersAccess()...)
		// We need to bind compliance components that run inside the managed cluster
		// to have the correct RBAC for linseed API
		complianceObjs = append(complianceObjs,
			c.complianceControllerClusterRole(),
			c.complianceControllerClusterRoleBinding(),
		)
		complianceObjs = append(complianceObjs,
			c.complianceReporterClusterRole(),
			c.complianceReporterClusterRoleBinding(),
		)
		complianceObjs = append(complianceObjs,
			c.complianceBenchmarkerClusterRole(),
			c.complianceBenchmarkerClusterRoleBinding(),
		)
		complianceObjs = append(complianceObjs,
			c.complianceSnapshotterClusterRole(),
			c.complianceSnapshotterClusterRoleBinding())
	} else {
		complianceObjs = append(complianceObjs,
			c.complianceAccessCalicoSystemNetworkPolicy(),
			networkpolicy.CalicoSystemDefaultDeny(c.cfg.Namespace),
		)
		complianceObjs = append(complianceObjs,
			c.complianceControllerServiceAccount(),
			c.complianceControllerRole(),
			c.complianceControllerClusterRole(),
			c.complianceControllerRoleBinding(),
			c.complianceControllerClusterRoleBinding(),
			c.complianceControllerDeployment(),

			c.complianceReporterServiceAccount(),
			c.complianceReporterClusterRole(),
			c.complianceReporterClusterRoleBinding(),
			c.complianceReporterPodTemplate(),

			c.complianceSnapshotterServiceAccount(),
			c.complianceSnapshotterClusterRole(),
			c.complianceSnapshotterClusterRoleBinding(),
			c.complianceSnapshotterDeployment(),

			c.complianceBenchmarkerServiceAccount(),
			c.complianceBenchmarkerClusterRole(),
			c.complianceBenchmarkerClusterRoleBinding(),
			c.complianceBenchmarkerDaemonSet(),

			c.complianceGlobalReportInventory(),
			c.complianceGlobalReportNetworkAccess(),
			c.complianceGlobalReportPolicyAudit(),
			c.complianceGlobalReportCISBenchmark(),
		)
	}

	if c.cfg.KeyValidatorConfig != nil {
		complianceObjs = append(complianceObjs, secret.ToRuntimeObjects(c.cfg.KeyValidatorConfig.RequiredSecrets(c.cfg.Namespace)...)...)
		complianceObjs = append(complianceObjs, configmap.ToRuntimeObjects(c.cfg.KeyValidatorConfig.RequiredConfigMaps(c.cfg.Namespace)...)...)
	}

	if c.cfg.ManagementClusterConnection == nil {
		complianceObjs = append(complianceObjs,
			c.complianceServerCalicoSystemNetworkPolicy(),
			c.complianceServerClusterRole(),
			c.complianceServerService(),
			c.complianceServerDeployment(),

			// We need compliance server ServiceAccount and ClusterRoleBinding only for standalone and management clusters.
			// In managed clusters, the Guardian ServiceAccount handles this RBAC.
			c.complianceServerServiceAccount(),
			c.complianceServerClusterRoleBinding(),
		)

		if c.cfg.Cloud {
			// Cloud modifications: add a network policy to talk to the OIDC issuer if one is being used.
			// Note this is only strictly required when not using dex and the provider is outside the
			// cluster, but that knowledge is not currently available in the compliance renderer, so
			// enable it for all OIDC providers.
			if c.cfg.KeyValidatorConfig != nil {
				complianceObjs = append(complianceObjs, c.cloudComplianceServerAllowTigeraNetworkPolicy(c.cfg.KeyValidatorConfig.Issuer()))
			}
			// allow-tigera Tier was renamed to calico-system
			objsToDelete = append(objsToDelete,
				networkpolicy.DeprecatedAllowTigeraNetworkPolicyObject("cloud-compliance-server", c.cfg.Namespace),
			)
		}
	} else {
		// Compliance server is only for Standalone or Management clusters
		objsToDelete = append(objsToDelete, &appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: ComplianceServerName, Namespace: c.cfg.Namespace}})

		// This ClusterRole was previously needed for the compliance server to fetch compliance reports
		// from the managed cluster. Guardian now handles this, so we can delete it.
		objsToDelete = append(objsToDelete,
			&rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: ComplianceServerServiceAccount}},
			&rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: ComplianceServerServiceAccount}},
			&corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: ComplianceServerServiceAccount, Namespace: "tigera-compliance"}},
		)

		complianceObjs = append(complianceObjs,
			c.externalLinseedRoleBinding(),
		)
	}

	// Need to grant cluster admin permissions in DockerEE to the controller since a pod starting pods with
	// host path volumes requires cluster admin permissions.
	if c.cfg.Installation.KubernetesProvider.IsDockerEE() && !c.cfg.Tenant.MultiTenant() {
		complianceObjs = append(complianceObjs, c.complianceControllerClusterAdminClusterRoleBinding())
	}

	deprecatedObjs := []client.Object{
		// allow-tigera Tier was renamed to calico-system
		networkpolicy.DeprecatedAllowTigeraNetworkPolicyObject("compliance-server", c.cfg.Namespace),
		networkpolicy.DeprecatedAllowTigeraNetworkPolicyObject("compliance-access", c.cfg.Namespace),
		networkpolicy.DeprecatedAllowTigeraNetworkPolicyObject("default-deny", c.cfg.Namespace),
	}

	if c.cfg.HasNoLicense {
		return nil, append(complianceObjs, deprecatedObjs...)
	}

	return complianceObjs, append(objsToDelete, deprecatedObjs...)
}

func (c *complianceComponent) Ready() bool {
	return true
}

var (
	complianceReplicas int32 = 1
)

const complianceServerPort = 5443

func (c *complianceComponent) complianceControllerServiceAccount() *corev1.ServiceAccount {
	return &corev1.ServiceAccount{
		TypeMeta:   metav1.TypeMeta{Kind: "ServiceAccount", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{Name: ComplianceControllerServiceAccount, Namespace: c.cfg.Namespace},
	}
}

func (c *complianceComponent) complianceControllerRole() *rbacv1.Role {
	rules := []rbacv1.PolicyRule{
		{
			APIGroups: []string{"batch"},
			Resources: []string{"jobs"},
			Verbs:     []string{"create", "list", "get", "delete"},
		},
		{
			APIGroups: []string{""},
			Resources: []string{"podtemplates"},
			Verbs:     []string{"get"},
		},
	}

	if c.cfg.OpenShift {
		rules = append(rules, rbacv1.PolicyRule{
			APIGroups:     []string{"security.openshift.io"},
			Resources:     []string{"securitycontextconstraints"},
			Verbs:         []string{"use"},
			ResourceNames: []string{securitycontextconstraints.NonRootV2},
		})
	}

	return &rbacv1.Role{
		TypeMeta:   metav1.TypeMeta{Kind: "Role", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{Name: ComplianceControllerServiceAccount, Namespace: c.cfg.Namespace},
		Rules:      rules,
	}
}

func (c *complianceComponent) complianceControllerClusterRole() *rbacv1.ClusterRole {
	var rules []rbacv1.PolicyRule
	if !c.cfg.Tenant.MultiTenant() {
		// We want to include this RBAC for zero and single tenant
		rules = []rbacv1.PolicyRule{
			{
				APIGroups: []string{"projectcalico.org"},
				Resources: []string{"globalreports"},
				Verbs:     []string{"list"},
			},
			{
				APIGroups: []string{"projectcalico.org"},
				Resources: []string{"globalreports/status"},
				Verbs:     []string{"update", "list"},
			},
			{
				APIGroups: []string{"projectcalico.org"},
				Resources: []string{"globalreports/finalizers"},
				Verbs:     []string{"update"},
			},
		}
	}

	// We need to allow access on Linseed API inside the management cluster
	// for all configurations or for standalone
	rules = append(rules, rbacv1.PolicyRule{
		APIGroups: []string{"linseed.tigera.io"},
		Resources: []string{"compliancereports"},
		Verbs:     []string{"create", "get"},
	})

	return &rbacv1.ClusterRole{
		TypeMeta:   metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{Name: ComplianceControllerServiceAccount},
		Rules:      rules,
	}
}

func (c *complianceComponent) complianceControllerRoleBinding() *rbacv1.RoleBinding {
	return &rbacv1.RoleBinding{
		TypeMeta:   metav1.TypeMeta{Kind: "RoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{Name: ComplianceControllerServiceAccount, Namespace: c.cfg.Namespace},
		RoleRef: rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "Role",
			Name:     ComplianceControllerServiceAccount,
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      "ServiceAccount",
				Name:      ComplianceControllerServiceAccount,
				Namespace: c.cfg.Namespace,
			},
		},
	}
}

func (c *complianceComponent) complianceControllerClusterRoleBinding() *rbacv1.ClusterRoleBinding {
	return rcomponents.ClusterRoleBinding(ComplianceControllerServiceAccount, ComplianceControllerServiceAccount, ComplianceControllerServiceAccount, c.cfg.BindingNamespaces)
}

// This clusterRoleBinding is only needed in DockerEE since a pod starting pods with host path volumes requires cluster admin permissions.
func (c *complianceComponent) complianceControllerClusterAdminClusterRoleBinding() *rbacv1.ClusterRoleBinding {
	return &rbacv1.ClusterRoleBinding{
		TypeMeta:   metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{Name: "tigera-compliance-controller-cluster-admin"},
		RoleRef: rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "ClusterRole",
			Name:     "cluster-admin",
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      "ServiceAccount",
				Name:      ComplianceControllerServiceAccount,
				Namespace: c.cfg.Namespace,
			},
		},
	}
}

func (c *complianceComponent) complianceControllerDeployment() *appsv1.Deployment {
	var keyPath, certPath string
	if c.cfg.ControllerKeyPair != nil {
		// This should never be nil, but we check it anyway just to be safe.
		keyPath, certPath = c.cfg.ControllerKeyPair.VolumeMountKeyFilePath(), c.cfg.ControllerKeyPair.VolumeMountCertificateFilePath()
	}

	volumes := []corev1.Volume{
		c.cfg.ControllerKeyPair.Volume(),
		c.cfg.TrustedBundle.Volume(),
	}
	volumeMounts := append(c.cfg.TrustedBundle.VolumeMounts(c.SupportedOSType()), c.cfg.ControllerKeyPair.VolumeMount(c.SupportedOSType()))
	if c.cfg.ManagementClusterConnection != nil {
		// For managed clusters, we need to mount the token for Linseed access.
		volumes = append(volumes,
			corev1.Volume{
				Name: LinseedTokenVolumeName,
				VolumeSource: corev1.VolumeSource{
					Secret: &corev1.SecretVolumeSource{
						SecretName: fmt.Sprintf(LinseedTokenSecret, ComplianceControllerServiceAccount),
						Items:      []corev1.KeyToPath{{Key: LinseedTokenKey, Path: LinseedTokenSubPath}},
					},
				},
			})
		volumeMounts = append(volumeMounts,
			corev1.VolumeMount{
				Name:      LinseedTokenVolumeName,
				MountPath: LinseedVolumeMountPath,
			})
	}

	envVars := []corev1.EnvVar{
		{Name: "LOG_LEVEL", Value: "info"},
		{Name: "TIGERA_COMPLIANCE_JOB_NAMESPACE", Value: c.cfg.Namespace},
		{Name: "TIGERA_COMPLIANCE_MAX_FAILED_JOBS_HISTORY", Value: "3"},
		{Name: "TIGERA_COMPLIANCE_MAX_JOB_RETRIES", Value: "6"},
		{Name: "LINSEED_CLIENT_CERT", Value: certPath},
		{Name: "LINSEED_CLIENT_KEY", Value: keyPath},
		{Name: "LINSEED_TOKEN", Value: GetLinseedTokenPath(c.cfg.ManagementClusterConnection != nil)},
		{
			Name:  "LINSEED_URL",
			Value: relasticsearch.LinseedEndpoint(c.SupportedOSType(), c.cfg.ClusterDomain, LinseedNamespace(c.cfg.Tenant), c.cfg.ManagementClusterConnection != nil, false),
		},
	}
	if c.cfg.Tenant != nil {
		// Configure the tenant id in order to read /write linseed data using the correct tenant ID
		// Multi-tenant and single tenant with external elastic needs this variable set
		if c.cfg.ExternalElastic {
			envVars = append(envVars, corev1.EnvVar{Name: "TENANT_ID", Value: c.cfg.Tenant.Spec.ID})
		}
	}
	sc := securitycontext.NewNonRootContext()
	var initContainers []corev1.Container
	if c.cfg.ControllerKeyPair != nil && c.cfg.ControllerKeyPair.UseCertificateManagement() {
		initContainers = append(initContainers, c.cfg.ControllerKeyPair.InitContainer(c.cfg.Namespace, sc))
	}

	tolerations := append(c.cfg.Installation.ControlPlaneTolerations, rmeta.TolerateControlPlane...)
	if c.cfg.Installation.KubernetesProvider.IsGKE() {
		tolerations = append(tolerations, rmeta.TolerateGKEARM64NoSchedule)
	}

	podTemplate := &corev1.PodTemplateSpec{
		ObjectMeta: metav1.ObjectMeta{
			Name:      ComplianceControllerName,
			Namespace: c.cfg.Namespace,
		},
		Spec: corev1.PodSpec{
			ServiceAccountName: ComplianceControllerServiceAccount,
			Tolerations:        tolerations,
			NodeSelector:       c.cfg.Installation.ControlPlaneNodeSelector,
			ImagePullSecrets:   secret.GetReferenceList(c.cfg.PullSecrets),
			InitContainers:     initContainers,
			Containers: []corev1.Container{
				{
					Name:    ComplianceControllerName,
					Image:   c.calicoImage,
					Command: []string{components.CalicoBinaryPath, "component", "compliance-controller"},
					Env:     envVars,
					LivenessProbe: &corev1.Probe{
						ProbeHandler: corev1.ProbeHandler{
							HTTPGet: &corev1.HTTPGetAction{
								Path: "/liveness",
								Port: intstr.FromInt(9099),
							},
						},
					},
					SecurityContext: sc,
					VolumeMounts:    volumeMounts,
				},
			},
			Volumes: volumes,
		},
	}

	d := &appsv1.Deployment{
		TypeMeta: metav1.TypeMeta{Kind: "Deployment", APIVersion: "apps/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      ComplianceControllerName,
			Namespace: c.cfg.Namespace,
			Labels: map[string]string{
				"k8s-app": ComplianceControllerName,
			},
		},
		Spec: appsv1.DeploymentSpec{
			Replicas: &complianceReplicas,
			Strategy: appsv1.DeploymentStrategy{
				Type: appsv1.RecreateDeploymentStrategyType,
			},
			Template: *podTemplate,
		},
	}

	if c.cfg.Compliance != nil {
		if overrides := c.cfg.Compliance.Spec.ComplianceControllerDeployment; overrides != nil {
			rcomponents.ApplyDeploymentOverrides(d, overrides)
		}
	}
	return d
}

func (c *complianceComponent) complianceReporterServiceAccount() *corev1.ServiceAccount {
	return &corev1.ServiceAccount{
		TypeMeta:   metav1.TypeMeta{Kind: "ServiceAccount", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{Name: ComplianceReporterServiceAccount, Namespace: c.cfg.Namespace},
	}
}

func (c *complianceComponent) complianceReporterClusterRole() *rbacv1.ClusterRole {
	var rules []rbacv1.PolicyRule
	if !c.cfg.Tenant.MultiTenant() {
		// We want to include this RBAC for zero and single tenant
		rules = []rbacv1.PolicyRule{
			{
				APIGroups: []string{"projectcalico.org"},
				Resources: []string{"globalreporttypes", "globalreports"},
				Verbs:     []string{"get"},
			},
		}
	}

	// We need to allow access on Linseed API inside the management cluster
	// for all configurations or for standalone
	rules = append(rules,
		rbacv1.PolicyRule{
			APIGroups: []string{"linseed.tigera.io"},
			Resources: []string{"snapshots", "benchmarks", "auditlogs", "flows"},
			Verbs:     []string{"get"},
		},
		rbacv1.PolicyRule{
			APIGroups: []string{"linseed.tigera.io"},
			Resources: []string{"compliancereports"},
			Verbs:     []string{"create"},
		})

	if c.cfg.OpenShift {
		rules = append(rules, rbacv1.PolicyRule{
			APIGroups:     []string{"security.openshift.io"},
			Resources:     []string{"securitycontextconstraints"},
			Verbs:         []string{"use"},
			ResourceNames: []string{securitycontextconstraints.HostAccess},
		})
	}
	return &rbacv1.ClusterRole{
		TypeMeta:   metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{Name: ComplianceReporterServiceAccount},
		Rules:      rules,
	}
}

func (c *complianceComponent) complianceReporterClusterRoleBinding() *rbacv1.ClusterRoleBinding {
	return rcomponents.ClusterRoleBinding(ComplianceReporterServiceAccount, ComplianceReporterServiceAccount, ComplianceReporterServiceAccount, c.cfg.BindingNamespaces)
}

func (c *complianceComponent) complianceReporterPodTemplate() *corev1.PodTemplate {
	var keyPath, certPath string
	if c.cfg.ReporterKeyPair != nil {
		// This should never be nil, but we check it anyway just to be safe.
		keyPath, certPath = c.cfg.ReporterKeyPair.VolumeMountKeyFilePath(), c.cfg.ReporterKeyPair.VolumeMountCertificateFilePath()
	}

	dirOrCreate := corev1.HostPathDirectoryOrCreate

	envVars := []corev1.EnvVar{
		{Name: "LOG_LEVEL", Value: "info"},
		{Name: "TIGERA_COMPLIANCE_JOB_NAMESPACE", Value: c.cfg.Namespace},
		{Name: "LINSEED_CLIENT_CERT", Value: certPath},
		{Name: "LINSEED_CLIENT_KEY", Value: keyPath},
		{Name: "LINSEED_TOKEN", Value: GetLinseedTokenPath(c.cfg.ManagementClusterConnection != nil)},
		{
			Name:  "LINSEED_URL",
			Value: relasticsearch.LinseedEndpoint(c.SupportedOSType(), c.cfg.ClusterDomain, LinseedNamespace(c.cfg.Tenant), c.cfg.ManagementClusterConnection != nil, false),
		},
	}
	if c.cfg.Tenant != nil {
		// Configure the tenant id in order to read /write linseed data using the correct tenant ID
		// Multi-tenant and single tenant with external elastic needs this variable set
		if c.cfg.ExternalElastic {
			envVars = append(envVars, corev1.EnvVar{Name: "TENANT_ID", Value: c.cfg.Tenant.Spec.ID})
		}
	}

	volumes := []corev1.Volume{
		{
			Name: "var-log-calico",
			VolumeSource: corev1.VolumeSource{
				HostPath: &corev1.HostPathVolumeSource{
					Path: "/var/log/calico",
					Type: &dirOrCreate,
				},
			},
		},
		c.cfg.ReporterKeyPair.Volume(),
		c.cfg.TrustedBundle.Volume(),
	}
	volumeMounts := append(
		c.cfg.TrustedBundle.VolumeMounts(c.SupportedOSType()),
		c.cfg.ReporterKeyPair.VolumeMount(c.SupportedOSType()),
		corev1.VolumeMount{MountPath: "/var/log/calico", Name: "var-log-calico"},
	)

	if c.cfg.ManagementClusterConnection != nil {
		// For managed clusters, we need to mount the token for Linseed access.
		volumes = append(volumes,
			corev1.Volume{
				Name: LinseedTokenVolumeName,
				VolumeSource: corev1.VolumeSource{
					Secret: &corev1.SecretVolumeSource{
						SecretName: fmt.Sprintf(LinseedTokenSecret, ComplianceReporterServiceAccount),
						Items:      []corev1.KeyToPath{{Key: LinseedTokenKey, Path: LinseedTokenSubPath}},
					},
				},
			})
		volumeMounts = append(volumeMounts,
			corev1.VolumeMount{
				Name:      LinseedTokenVolumeName,
				MountPath: LinseedVolumeMountPath,
			})
	}
	var initContainers []corev1.Container
	sc := securitycontext.NewRootContext(c.cfg.OpenShift)
	if c.cfg.ReporterKeyPair != nil && c.cfg.ReporterKeyPair.UseCertificateManagement() {
		initContainers = append(initContainers, c.cfg.ReporterKeyPair.InitContainer(c.cfg.Namespace, sc))
	}

	tolerations := append(c.cfg.Installation.ControlPlaneTolerations, rmeta.TolerateControlPlane...)
	if c.cfg.Installation.KubernetesProvider.IsGKE() {
		tolerations = append(tolerations, rmeta.TolerateGKEARM64NoSchedule)
	}

	podtemplate := &corev1.PodTemplate{
		TypeMeta: metav1.TypeMeta{Kind: "PodTemplate", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "tigera.io.report",
			Namespace: c.cfg.Namespace,
			Labels: map[string]string{
				"k8s-app": ComplianceReporterName,
			},
		},
		Template: corev1.PodTemplateSpec{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "tigera.io.report",
				Namespace: c.cfg.Namespace,
				Labels: map[string]string{
					"k8s-app": ComplianceReporterName,
				},
			},
			Spec: corev1.PodSpec{
				ServiceAccountName: ComplianceReporterServiceAccount,
				Tolerations:        tolerations,
				NodeSelector:       c.cfg.Installation.ControlPlaneNodeSelector,
				ImagePullSecrets:   secret.GetReferenceList(c.cfg.PullSecrets),
				InitContainers:     initContainers,
				Containers: []corev1.Container{
					{
						Name:    "reporter",
						Image:   c.calicoImage,
						Command: []string{components.CalicoBinaryPath, "component", "compliance-reporter"},
						Env:     envVars,
						LivenessProbe: &corev1.Probe{
							ProbeHandler: corev1.ProbeHandler{
								HTTPGet: &corev1.HTTPGetAction{
									Path: "/liveness",
									Port: intstr.FromInt(9099),
								},
							},
							PeriodSeconds:  300,
							TimeoutSeconds: 10,
						},

						// On OpenShift reporter needs privileged access to write compliance reports to host path volume
						SecurityContext: sc,
						VolumeMounts:    volumeMounts,
					},
				},
				Volumes: volumes,
			},
		},
	}

	if c.cfg.Compliance != nil {
		if overrides := c.cfg.Compliance.Spec.ComplianceReporterPodTemplate; overrides != nil {
			rcomponents.ApplyPodTemplateOverrides(podtemplate, overrides)
		}
	}

	return podtemplate
}

func (c *complianceComponent) complianceServerServiceAccount() *corev1.ServiceAccount {
	return &corev1.ServiceAccount{
		TypeMeta:   metav1.TypeMeta{Kind: "ServiceAccount", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{Name: ComplianceServerServiceAccount, Namespace: c.cfg.Namespace},
	}
}

func (c *complianceComponent) externalLinseedRoleBinding() *rbacv1.RoleBinding {
	// For managed clusters, we must create a role binding to allow Linseed to manage access token secrets
	// in our namespace.
	linseed := "tigera-linseed"
	return &rbacv1.RoleBinding{
		TypeMeta: metav1.TypeMeta{Kind: "RoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      linseed,
			Namespace: c.cfg.Namespace,
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

func (c *complianceComponent) complianceServerClusterRole() *rbacv1.ClusterRole {
	clusterRole := &rbacv1.ClusterRole{
		TypeMeta:   metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{Name: ComplianceServerServiceAccount},
		Rules: []rbacv1.PolicyRule{
			{
				APIGroups: []string{"projectcalico.org"},
				Resources: []string{"globalreporttypes", "globalreports"},
				Verbs:     []string{"get", "list", "watch"},
			},
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
				APIGroups: []string{"linseed.tigera.io"},
				Resources: []string{"compliancereports"},
				Verbs:     []string{"get"},
			},
		},
	}

	if c.cfg.OpenShift {
		clusterRole.Rules = append(clusterRole.Rules, rbacv1.PolicyRule{
			APIGroups:     []string{"security.openshift.io"},
			Resources:     []string{"securitycontextconstraints"},
			Verbs:         []string{"use"},
			ResourceNames: []string{securitycontextconstraints.NonRootV2},
		})
	}

	if c.cfg.Tenant.MultiTenant() {
		// These rules are used by tigera-compliance-server in a management cluster serving multiple tenants in order to appear to managed
		// clusters as the expected serviceaccount. They're only needed when there are multiple tenants sharing the same
		// management cluster.
		clusterRole.Rules = append(clusterRole.Rules, []rbacv1.PolicyRule{
			{
				APIGroups:     []string{""},
				Resources:     []string{"serviceaccounts"},
				Verbs:         []string{"impersonate"},
				ResourceNames: []string{ComplianceServerServiceAccount},
			},
			{
				APIGroups: []string{""},
				Resources: []string{"groups"},
				Verbs:     []string{"impersonate"},
				ResourceNames: []string{
					serviceaccount.AllServiceAccountsGroup,
					"system:authenticated",
					fmt.Sprintf("%s%s", serviceaccount.ServiceAccountGroupPrefix, ComplianceNamespace),
				},
			},
		}...)
	}

	return clusterRole
}

func (c *complianceComponent) complianceServerClusterRoleBinding() *rbacv1.ClusterRoleBinding {
	return rcomponents.ClusterRoleBinding(ComplianceServerServiceAccount, ComplianceServerServiceAccount, ComplianceServerServiceAccount, c.cfg.BindingNamespaces)
}

func (c *complianceComponent) complianceServerService() *corev1.Service {
	return &corev1.Service{
		TypeMeta:   metav1.TypeMeta{Kind: "Service", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{Name: "compliance", Namespace: c.cfg.Namespace},
		Spec: corev1.ServiceSpec{
			Ports: []corev1.ServicePort{
				{
					Name:       "compliance-api",
					Port:       443,
					Protocol:   corev1.ProtocolTCP,
					TargetPort: intstr.FromInt(complianceServerPort),
				},
			},
			Selector: map[string]string{"k8s-app": ComplianceServerName},
		},
	}
}

func (c *complianceComponent) complianceServerDeployment() *appsv1.Deployment {
	var keyPath, certPath string
	if c.cfg.ServerKeyPair != nil {
		// This should never be nil, but we check it anyway just to be safe.
		keyPath, certPath = c.cfg.ServerKeyPair.VolumeMountKeyFilePath(), c.cfg.ServerKeyPair.VolumeMountCertificateFilePath()
	}

	envVars := []corev1.EnvVar{
		{Name: "LOG_LEVEL", Value: "info"},
		{Name: "TIGERA_COMPLIANCE_JOB_NAMESPACE", Value: c.cfg.Namespace},
		{Name: "MULTI_CLUSTER_FORWARDING_CA", Value: certificatemanagement.TrustedCertBundleMountPath},
		{Name: "LINSEED_CLIENT_CERT", Value: certPath},
		{Name: "LINSEED_CLIENT_KEY", Value: keyPath},
		{Name: "LINSEED_TOKEN", Value: GetLinseedTokenPath(c.cfg.ManagementClusterConnection != nil)},
	}
	if c.cfg.Tenant != nil {
		// Configure the tenant id in order to read /write linseed data using the correct tenant ID
		// Multi-tenant and single tenant with external elastic needs this variable set
		if c.cfg.ExternalElastic {
			envVars = append(envVars, corev1.EnvVar{Name: "TENANT_ID", Value: c.cfg.Tenant.Spec.ID})
		}
		if c.cfg.Tenant.MultiTenant() {
			envVars = append(envVars, corev1.EnvVar{Name: "TENANT_NAMESPACE", Value: c.cfg.Tenant.Namespace})
			envVars = append(envVars, corev1.EnvVar{Name: "LINSEED_URL", Value: fmt.Sprintf("https://tigera-linseed.%s.svc", c.cfg.Tenant.Namespace)})
			envVars = append(envVars, corev1.EnvVar{Name: "MULTI_CLUSTER_FORWARDING_ENDPOINT", Value: ManagerService(c.cfg.Tenant)})
		}
	}

	if c.cfg.KeyValidatorConfig != nil {
		envVars = append(envVars, c.cfg.KeyValidatorConfig.RequiredEnv("TIGERA_COMPLIANCE_")...)
	}
	sc := securitycontext.NewNonRootContext()
	var initContainers []corev1.Container
	if c.cfg.ServerKeyPair.UseCertificateManagement() {
		initContainers = append(initContainers, c.cfg.ServerKeyPair.InitContainer(c.cfg.Namespace, sc))
	}

	tolerations := append(c.cfg.Installation.ControlPlaneTolerations, rmeta.TolerateControlPlane...)
	if c.cfg.Installation.KubernetesProvider.IsGKE() {
		tolerations = append(tolerations, rmeta.TolerateGKEARM64NoSchedule)
	}

	podTemplate := &corev1.PodTemplateSpec{
		ObjectMeta: metav1.ObjectMeta{
			Name:        ComplianceServerName,
			Namespace:   c.cfg.Namespace,
			Annotations: complianceAnnotations(c),
		},
		Spec: corev1.PodSpec{
			ServiceAccountName: ComplianceServerServiceAccount,
			Tolerations:        tolerations,
			NodeSelector:       c.cfg.Installation.ControlPlaneNodeSelector,
			ImagePullSecrets:   secret.GetReferenceList(c.cfg.PullSecrets),
			InitContainers:     initContainers,
			Containers: []corev1.Container{
				{
					Name:    ComplianceServerName,
					Image:   c.calicoImage,
					Command: []string{components.CalicoBinaryPath, "component", "compliance-server"},
					Env:     envVars,
					LivenessProbe: &corev1.Probe{
						ProbeHandler: corev1.ProbeHandler{
							HTTPGet: &corev1.HTTPGetAction{
								Path:   "/compliance/version",
								Port:   intstr.FromInt(complianceServerPort),
								Scheme: corev1.URISchemeHTTPS,
							},
						},
						FailureThreshold:    5,
						InitialDelaySeconds: 5,
					},
					ReadinessProbe: &corev1.Probe{
						ProbeHandler: corev1.ProbeHandler{
							HTTPGet: &corev1.HTTPGetAction{
								Path:   "/compliance/version",
								Port:   intstr.FromInt(complianceServerPort),
								Scheme: corev1.URISchemeHTTPS,
							},
						},
						FailureThreshold:    5,
						InitialDelaySeconds: 5,
					},
					Args: []string{
						fmt.Sprintf("-certpath=%s", c.cfg.ServerKeyPair.VolumeMountCertificateFilePath()),
						fmt.Sprintf("-keypath=%s", c.cfg.ServerKeyPair.VolumeMountKeyFilePath()),
					},
					SecurityContext: sc,
					VolumeMounts: append(
						c.cfg.TrustedBundle.VolumeMounts(c.SupportedOSType()),
						c.cfg.ServerKeyPair.VolumeMount(c.SupportedOSType()),
					),
				},
			},
			Volumes: []corev1.Volume{
				c.cfg.ServerKeyPair.Volume(),
				c.cfg.TrustedBundle.Volume(),
			},
		},
	}

	d := &appsv1.Deployment{
		TypeMeta: metav1.TypeMeta{Kind: "Deployment", APIVersion: "apps/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      ComplianceServerName,
			Namespace: c.cfg.Namespace,
		},
		Spec: appsv1.DeploymentSpec{
			Replicas: &complianceReplicas,
			Strategy: appsv1.DeploymentStrategy{
				Type: appsv1.RecreateDeploymentStrategyType,
			},
			Template: *podTemplate,
		},
	}

	if c.cfg.Compliance != nil {
		if overrides := c.cfg.Compliance.Spec.ComplianceServerDeployment; overrides != nil {
			rcomponents.ApplyDeploymentOverrides(d, overrides)
		}
	}
	return d
}

func complianceAnnotations(c *complianceComponent) map[string]string {
	annotations := c.cfg.TrustedBundle.HashAnnotations()
	if c.cfg.ServerKeyPair != nil {
		annotations[c.cfg.ServerKeyPair.HashAnnotationKey()] = c.cfg.ServerKeyPair.HashAnnotationValue()
	}
	return annotations
}

func (c *complianceComponent) complianceSnapshotterServiceAccount() *corev1.ServiceAccount {
	return &corev1.ServiceAccount{
		TypeMeta:   metav1.TypeMeta{Kind: "ServiceAccount", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{Name: ComplianceSnapshotterServiceAccount, Namespace: c.cfg.Namespace},
	}
}

func (c *complianceComponent) complianceSnapshotterClusterRole() *rbacv1.ClusterRole {
	var rules []rbacv1.PolicyRule
	if !c.cfg.Tenant.MultiTenant() {
		// We want to include this RBAC for zero and single tenant
		rules = []rbacv1.PolicyRule{
			{
				APIGroups: []string{"networking.k8s.io", "authentication.k8s.io", ""},
				Resources: []string{
					"networkpolicies", "nodes", "namespaces", "pods", "serviceaccounts",
					"endpoints", "services",
				},
				Verbs: []string{"get", "list"},
			},
			{
				APIGroups: []string{"projectcalico.org"},
				Resources: []string{
					"globalnetworkpolicies", "tier.globalnetworkpolicies",
					"stagedglobalnetworkpolicies", "tier.stagedglobalnetworkpolicies",
					"networkpolicies", "tier.networkpolicies",
					"stagednetworkpolicies", "tier.stagednetworkpolicies",
					"stagedkubernetesnetworkpolicies",
					"tiers", "hostendpoints",
					"globalnetworksets", "networksets",
				},
				Verbs: []string{"get", "list"},
			},
		}
	}

	// We need to allow access on Linseed API inside the management cluster
	// for all configurations or for standalone
	rules = append(rules, rbacv1.PolicyRule{
		APIGroups: []string{"linseed.tigera.io"},
		Resources: []string{"snapshots"},
		Verbs:     []string{"get", "create"},
	})

	if c.cfg.OpenShift {
		rules = append(rules, rbacv1.PolicyRule{
			APIGroups:     []string{"security.openshift.io"},
			Resources:     []string{"securitycontextconstraints"},
			Verbs:         []string{"use"},
			ResourceNames: []string{securitycontextconstraints.NonRootV2},
		})
	}
	return &rbacv1.ClusterRole{
		TypeMeta:   metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{Name: ComplianceSnapshotterServiceAccount},
		Rules:      rules,
	}
}

func (c *complianceComponent) complianceSnapshotterClusterRoleBinding() *rbacv1.ClusterRoleBinding {
	return rcomponents.ClusterRoleBinding(ComplianceSnapshotterServiceAccount, ComplianceSnapshotterServiceAccount, ComplianceSnapshotterServiceAccount, c.cfg.BindingNamespaces)
}

func (c *complianceComponent) complianceSnapshotterDeployment() *appsv1.Deployment {
	var keyPath, certPath string
	if c.cfg.SnapshotterKeyPair != nil {
		// This should never be nil, but we check it anyway just to be safe.
		keyPath, certPath = c.cfg.SnapshotterKeyPair.VolumeMountKeyFilePath(), c.cfg.SnapshotterKeyPair.VolumeMountCertificateFilePath()
	}

	envVars := []corev1.EnvVar{
		{Name: "LOG_LEVEL", Value: "info"},
		{Name: "TIGERA_COMPLIANCE_JOB_NAMESPACE", Value: c.cfg.Namespace},
		{Name: "TIGERA_COMPLIANCE_MAX_FAILED_JOBS_HISTORY", Value: "3"},
		{Name: "TIGERA_COMPLIANCE_SNAPSHOT_HOUR", Value: "0"},
		{Name: "LINSEED_CLIENT_CERT", Value: certPath},
		{Name: "LINSEED_CLIENT_KEY", Value: keyPath},
		{Name: "LINSEED_TOKEN", Value: GetLinseedTokenPath(c.cfg.ManagementClusterConnection != nil)},
		{
			Name:  "LINSEED_URL",
			Value: relasticsearch.LinseedEndpoint(c.SupportedOSType(), c.cfg.ClusterDomain, LinseedNamespace(c.cfg.Tenant), c.cfg.ManagementClusterConnection != nil, false),
		},
	}
	if c.cfg.Tenant != nil {
		// Configure the tenant id in order to read /write linseed data using the correct tenant ID
		// Multi-tenant and single tenant with external elastic needs this variable set
		if c.cfg.ExternalElastic {
			envVars = append(envVars, corev1.EnvVar{Name: "TENANT_ID", Value: c.cfg.Tenant.Spec.ID})
		}
	}

	volumes := []corev1.Volume{
		c.cfg.TrustedBundle.Volume(),
		c.cfg.SnapshotterKeyPair.Volume(),
	}
	volumeMounts := append(c.cfg.TrustedBundle.VolumeMounts(c.SupportedOSType()), c.cfg.SnapshotterKeyPair.VolumeMount(c.SupportedOSType()))
	if c.cfg.ManagementClusterConnection != nil {
		// For managed clusters, we need to mount the token for Linseed access.
		volumes = append(volumes,
			corev1.Volume{
				Name: LinseedTokenVolumeName,
				VolumeSource: corev1.VolumeSource{
					Secret: &corev1.SecretVolumeSource{
						SecretName: fmt.Sprintf(LinseedTokenSecret, ComplianceSnapshotterServiceAccount),
						Items:      []corev1.KeyToPath{{Key: LinseedTokenKey, Path: LinseedTokenSubPath}},
					},
				},
			})
		volumeMounts = append(volumeMounts,
			corev1.VolumeMount{
				Name:      LinseedTokenVolumeName,
				MountPath: LinseedVolumeMountPath,
			})
	}
	var initContainers []corev1.Container
	sc := securitycontext.NewNonRootContext()
	if c.cfg.SnapshotterKeyPair != nil && c.cfg.SnapshotterKeyPair.UseCertificateManagement() {
		initContainers = append(initContainers, c.cfg.SnapshotterKeyPair.InitContainer(c.cfg.Namespace, sc))
	}

	tolerations := append(c.cfg.Installation.ControlPlaneTolerations, rmeta.TolerateControlPlane...)
	if c.cfg.Installation.KubernetesProvider.IsGKE() {
		tolerations = append(tolerations, rmeta.TolerateGKEARM64NoSchedule)
	}

	podTemplate := &corev1.PodTemplateSpec{
		ObjectMeta: metav1.ObjectMeta{
			Name:      ComplianceSnapshotterName,
			Namespace: c.cfg.Namespace,
		},
		Spec: corev1.PodSpec{
			ServiceAccountName: ComplianceSnapshotterServiceAccount,
			Tolerations:        tolerations,
			NodeSelector:       c.cfg.Installation.ControlPlaneNodeSelector,
			ImagePullSecrets:   secret.GetReferenceList(c.cfg.PullSecrets),
			InitContainers:     initContainers,
			Containers: []corev1.Container{
				{
					Name:    ComplianceSnapshotterName,
					Image:   c.calicoImage,
					Command: []string{components.CalicoBinaryPath, "component", "compliance-snapshotter"},
					Env:     envVars,
					LivenessProbe: &corev1.Probe{
						ProbeHandler: corev1.ProbeHandler{
							HTTPGet: &corev1.HTTPGetAction{
								Path: "/liveness",
								Port: intstr.FromInt(9099),
							},
						},
					},
					SecurityContext: sc,
					VolumeMounts:    volumeMounts,
				},
			},
			Volumes: volumes,
		},
	}

	d := &appsv1.Deployment{
		TypeMeta: metav1.TypeMeta{Kind: "Deployment", APIVersion: "apps/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      ComplianceSnapshotterName,
			Namespace: c.cfg.Namespace,
		},
		Spec: appsv1.DeploymentSpec{
			Replicas: &complianceReplicas,
			Strategy: appsv1.DeploymentStrategy{
				Type: appsv1.RecreateDeploymentStrategyType,
			},
			Template: *podTemplate,
		},
	}

	if c.cfg.Compliance != nil {
		if overrides := c.cfg.Compliance.Spec.ComplianceSnapshotterDeployment; overrides != nil {
			rcomponents.ApplyDeploymentOverrides(d, overrides)
		}
	}
	return d
}

func (c *complianceComponent) complianceBenchmarkerServiceAccount() *corev1.ServiceAccount {
	return &corev1.ServiceAccount{
		TypeMeta:   metav1.TypeMeta{Kind: "ServiceAccount", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{Name: ComplianceBenchmarkerServiceAccount, Namespace: c.cfg.Namespace},
	}
}

func (c *complianceComponent) complianceBenchmarkerClusterRole() *rbacv1.ClusterRole {
	var rules []rbacv1.PolicyRule
	if !c.cfg.Tenant.MultiTenant() {
		// We want to include this RBAC for zero and single tenant
		rules = []rbacv1.PolicyRule{
			{
				APIGroups: []string{""},
				Resources: []string{"pods"},
				Verbs:     []string{"list"},
			},
			{
				APIGroups: []string{""},
				Resources: []string{"nodes"},
				Verbs:     []string{"get"},
			},
		}
	}

	// We need to allow access on Linseed API inside the management cluster
	// for all configurations or for standalone
	rules = append(rules, rbacv1.PolicyRule{
		APIGroups: []string{"linseed.tigera.io"},
		Resources: []string{"benchmarks"},
		Verbs:     []string{"get", "create"}})

	if c.cfg.OpenShift {
		rules = append(rules,
			rbacv1.PolicyRule{
				APIGroups:     []string{"security.openshift.io"},
				Resources:     []string{"securitycontextconstraints"},
				Verbs:         []string{"use"},
				ResourceNames: []string{securitycontextconstraints.HostAccess},
			},
		)
	}

	return &rbacv1.ClusterRole{
		TypeMeta:   metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{Name: ComplianceBenchmarkerServiceAccount},
		Rules:      rules,
	}
}

func (c *complianceComponent) complianceBenchmarkerClusterRoleBinding() *rbacv1.ClusterRoleBinding {
	return rcomponents.ClusterRoleBinding(ComplianceBenchmarkerServiceAccount, ComplianceBenchmarkerServiceAccount, ComplianceBenchmarkerServiceAccount, c.cfg.BindingNamespaces)
}

func (c *complianceComponent) complianceBenchmarkerDaemonSet() *appsv1.DaemonSet {
	var keyPath, certPath string
	if c.cfg.BenchmarkerKeyPair != nil {
		// This should never be nil, but we check it anyway just to be safe.
		keyPath, certPath = c.cfg.BenchmarkerKeyPair.VolumeMountKeyFilePath(), c.cfg.BenchmarkerKeyPair.VolumeMountCertificateFilePath()
	}

	envVars := []corev1.EnvVar{
		{Name: "LOG_LEVEL", Value: "info"},
		{Name: "NODENAME", ValueFrom: &corev1.EnvVarSource{FieldRef: &corev1.ObjectFieldSelector{FieldPath: "spec.nodeName"}}},
		{Name: "LINSEED_CLIENT_CERT", Value: certPath},
		{Name: "LINSEED_CLIENT_KEY", Value: keyPath},
		{Name: "LINSEED_TOKEN", Value: GetLinseedTokenPath(c.cfg.ManagementClusterConnection != nil)},
		{
			Name:  "LINSEED_URL",
			Value: relasticsearch.LinseedEndpoint(c.SupportedOSType(), c.cfg.ClusterDomain, LinseedNamespace(c.cfg.Tenant), c.cfg.ManagementClusterConnection != nil, false),
		},
	}

	if c.cfg.Tenant != nil {
		// Configure the tenant id in order to read /write linseed data using the correct tenant ID
		// Multi-tenant and single tenant with external elastic needs this variable set
		if c.cfg.ExternalElastic {
			envVars = append(envVars, corev1.EnvVar{Name: "TENANT_ID", Value: c.cfg.Tenant.Spec.ID})
		}
	}

	volMounts := []corev1.VolumeMount{
		{Name: "var-lib-etcd", MountPath: "/var/lib/etcd", ReadOnly: true},
		{Name: "var-lib-kubelet", MountPath: "/var/lib/kubelet", ReadOnly: true},
		{Name: "etc-systemd", MountPath: "/etc/systemd", ReadOnly: true},
		{Name: "etc-kubernetes", MountPath: "/etc/kubernetes", ReadOnly: true},
		{Name: "usr-bin", MountPath: "/usr/local/bin", ReadOnly: true},
	}
	volMounts = append(volMounts, c.cfg.TrustedBundle.VolumeMounts(c.SupportedOSType())...)
	volMounts = append(volMounts, c.cfg.BenchmarkerKeyPair.VolumeMount(c.SupportedOSType()))

	vols := []corev1.Volume{
		{
			Name:         "var-lib-etcd",
			VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/var/lib/etcd"}},
		},
		{
			Name:         "var-lib-kubelet",
			VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/var/lib/kubelet"}},
		},
		{
			Name:         "etc-systemd",
			VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/etc/systemd"}},
		},
		{
			Name:         "etc-kubernetes",
			VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/etc/kubernetes"}},
		},
		{
			Name:         "usr-bin",
			VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/usr/bin"}},
		},
		c.cfg.TrustedBundle.Volume(),
		c.cfg.BenchmarkerKeyPair.Volume(),
	}

	// benchmarker needs an extra host path volume mount for GKE for CIS benchmarks
	if c.cfg.Installation.KubernetesProvider.IsGKE() {
		volMounts = append(volMounts, corev1.VolumeMount{Name: "home-kubernetes", MountPath: "/home/kubernetes", ReadOnly: true})

		vols = append(vols, corev1.Volume{
			Name:         "home-kubernetes",
			VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/home/kubernetes"}},
		})
	}

	if c.cfg.ManagementClusterConnection != nil {
		// For managed clusters, we need to mount the token for Linseed access.
		vols = append(vols,
			corev1.Volume{
				Name: LinseedTokenVolumeName,
				VolumeSource: corev1.VolumeSource{
					Secret: &corev1.SecretVolumeSource{
						SecretName: fmt.Sprintf(LinseedTokenSecret, ComplianceBenchmarkerServiceAccount),
						Items:      []corev1.KeyToPath{{Key: LinseedTokenKey, Path: LinseedTokenSubPath}},
					},
				},
			})
		volMounts = append(volMounts,
			corev1.VolumeMount{
				Name:      LinseedTokenVolumeName,
				MountPath: LinseedVolumeMountPath,
			})
	}

	var initContainers []corev1.Container
	sc := securitycontext.NewRootContext(false)
	if c.cfg.BenchmarkerKeyPair.UseCertificateManagement() {
		initContainers = append(initContainers, c.cfg.BenchmarkerKeyPair.InitContainer(c.cfg.Namespace, sc))
	}
	podTemplate := &corev1.PodTemplateSpec{
		ObjectMeta: metav1.ObjectMeta{
			Name:      ComplianceBenchmarkerName,
			Namespace: c.cfg.Namespace,
		},
		Spec: corev1.PodSpec{
			ServiceAccountName: ComplianceBenchmarkerServiceAccount,
			HostPID:            true,
			Tolerations:        rmeta.TolerateAll,
			ImagePullSecrets:   secret.GetReferenceList(c.cfg.PullSecrets),
			InitContainers:     initContainers,
			Containers: []corev1.Container{
				{
					Name:            ComplianceBenchmarkerName,
					Image:           c.benchmarkerImage,
					Env:             envVars,
					SecurityContext: sc,
					VolumeMounts:    volMounts,
					LivenessProbe: &corev1.Probe{
						ProbeHandler: corev1.ProbeHandler{
							HTTPGet: &corev1.HTTPGetAction{
								Path: "/liveness",
								Port: intstr.FromInt(9099),
							},
						},
						PeriodSeconds:  300,
						TimeoutSeconds: 10,
					},
				},
			},
			Volumes: vols,
		},
	}

	ds := &appsv1.DaemonSet{
		TypeMeta: metav1.TypeMeta{Kind: "DaemonSet", APIVersion: "apps/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      ComplianceBenchmarkerName,
			Namespace: c.cfg.Namespace,
		},

		Spec: appsv1.DaemonSetSpec{
			Template: *podTemplate,
		},
	}

	if c.cfg.Compliance != nil {
		if overrides := c.cfg.Compliance.Spec.ComplianceBenchmarkerDaemonSet; overrides != nil {
			rcomponents.ApplyDaemonSetOverrides(ds, overrides)
		}
	}
	return ds
}

func (c *complianceComponent) complianceGlobalReportInventory() *v3.GlobalReportType {
	return &v3.GlobalReportType{
		TypeMeta: metav1.TypeMeta{Kind: "GlobalReportType", APIVersion: "projectcalico.org/v3"},
		ObjectMeta: metav1.ObjectMeta{
			Name: "inventory",
			Labels: map[string]string{
				"global-report-type": "inventory",
			},
		},
		Spec: v3.ReportTypeSpec{
			DownloadTemplates: []v3.ReportTemplate{
				{
					Name: "summary.csv",
					Template: `
      {{ $c := csv }}
      {{- $c := $c.AddColumn "startTime"                     "{{ dateRfc3339 .StartTime }}" }}
      {{- $c := $c.AddColumn "endTime"                       "{{ dateRfc3339 .EndTime }}" }}
      {{- $c := $c.AddColumn "endpointSelector"              "{{ if .ReportSpec.Endpoints }}{{ .ReportSpec.Endpoints.Selector }}{{ end }}" }}
      {{- $c := $c.AddColumn "namespaceNames"                "{{ if .ReportSpec.Endpoints }}{{ if .ReportSpec.Endpoints.Namespaces }}{{ join \";\" .ReportSpec.Endpoints.Namespaces.Names }}{{ end }}{{ end }}" }}
      {{- $c := $c.AddColumn "namespaceSelector"             "{{ if .ReportSpec.Endpoints }}{{ if .ReportSpec.Endpoints.Namespaces }}{{ .ReportSpec.Endpoints.Namespaces.Selector }}{{ end }}{{ end }}" }}
      {{- $c := $c.AddColumn "serviceAccountNames"           "{{ if .ReportSpec.Endpoints }}{{ if .ReportSpec.Endpoints.ServiceAccounts }}{{ join \";\" .ReportSpec.Endpoints.ServiceAccounts.Names }}{{ end }}{{ end }}" }}
      {{- $c := $c.AddColumn "serviceAccountSelectors"       "{{ if .ReportSpec.Endpoints }}{{ if .ReportSpec.Endpoints.ServiceAccounts }}{{ .ReportSpec.Endpoints.ServiceAccounts.Selector }}{{ end }}{{ end }}" }}
      {{- $c := $c.AddColumn "endpointsNumInScope"           "{{ .EndpointsSummary.NumTotal }}" }}
      {{- $c := $c.AddColumn "endpointsNumIngressProtected"  "{{ .EndpointsSummary.NumIngressProtected }}" }}
      {{- $c := $c.AddColumn "endpointsNumEgressProtected"   "{{ .EndpointsSummary.NumEgressProtected }}" }}
      {{- $c := $c.AddColumn "namespacesNumInScope"          "{{ .NamespacesSummary.NumTotal }}" }}
      {{- $c := $c.AddColumn "namespacesNumIngressProtected" "{{ .NamespacesSummary.NumIngressProtected }}" }}
      {{- $c := $c.AddColumn "namespacesNumEgressProtected"  "{{ .NamespacesSummary.NumEgressProtected }}" }}
      {{- $c := $c.AddColumn "serviceAccountsNumInScope"     "{{ .EndpointsSummary.NumServiceAccounts }}" }}
      {{- $c.Render . }}
`,
				},
				{
					Name: "endpoints.csv",
					Template: `
      {{ $c := csv }}
      {{- $c := $c.AddColumn "endpoint"         "{{ .Endpoint }}" }}
      {{- $c := $c.AddColumn "ingressProtected" "{{ .IngressProtected }}" }}
      {{- $c := $c.AddColumn "egressProtected"  "{{ .EgressProtected }}" }}
      {{- $c := $c.AddColumn "envoyEnabled"     "{{ .EnvoyEnabled }}" }}
      {{- $c := $c.AddColumn "appliedPolicies"  "{{ join \";\" .AppliedPolicies }}" }}
      {{- $c := $c.AddColumn "services"         "{{ join \";\" .Services }}" }}
      {{- $c.Render .Endpoints }}
`,
				},
				{
					Name: "namespaces.csv",
					Template: `
      {{ $c := csv }}
      {{- $c := $c.AddColumn "namespace"        "{{ .Namespace }}" }}
      {{- $c := $c.AddColumn "ingressProtected" "{{ .IngressProtected }}" }}
      {{- $c := $c.AddColumn "egressProtected"  "{{ .EgressProtected }}" }}
      {{- $c := $c.AddColumn "envoyEnabled"     "{{ .EnvoyEnabled }}" }}
      {{- $c.Render .Namespaces }}
`,
				},
				{
					Name: "services.csv",
					Template: `
      {{ $c := csv }}
      {{- $c := $c.AddColumn "service"          "{{ .Service }}" }}
      {{- $c := $c.AddColumn "ingressProtected" "{{ .IngressProtected }}" }}
      {{- $c := $c.AddColumn "envoyEnabled"     "{{ .EnvoyEnabled }}" }}
      {{- $c.Render .Services }}
`,
				},
			},
			IncludeEndpointData: true,
			UISummaryTemplate: v3.ReportTemplate{
				Name:     "ui-summary.json",
				Template: `{"heading":"Inscope vs Protected","type":"panel","widgets":[{"data":[{"label":"Protected ingress","value":{{ .EndpointsSummary.NumIngressProtected }}}],"heading":"Endpoints","summary":{"label":"Total","total":{{.EndpointsSummary.NumTotal }}},"type":"radialbarchart"},{"data":[{"label":"Protected ingress","value":{{ .NamespacesSummary.NumIngressProtected }}}],"heading":"Namespaces","summary":{"label":"Total","total":{{.NamespacesSummary.NumTotal }}},"type":"radialbarchart"},{"data":[{"label":"Protected egress","value":{{ .EndpointsSummary.NumEgressProtected }}}],"heading":"Endpoints","summary":{"label":"Total","total":{{.EndpointsSummary.NumTotal }}},"type":"radialbarchart"},{"data":[{"label":"Protected egress","value":{{ .NamespacesSummary.NumEgressProtected }}}],"heading":"Namespaces","summary":{"label":"Total","total":{{.NamespacesSummary.NumTotal }}},"type":"radialbarchart"}]}`,
			},
		},
	}
}

func (c *complianceComponent) complianceGlobalReportNetworkAccess() *v3.GlobalReportType {
	return &v3.GlobalReportType{
		TypeMeta: metav1.TypeMeta{Kind: "GlobalReportType", APIVersion: "projectcalico.org/v3"},
		ObjectMeta: metav1.ObjectMeta{
			Name: "network-access",
			Labels: map[string]string{
				"global-report-type": "network-access",
			},
		},
		Spec: v3.ReportTypeSpec{
			DownloadTemplates: []v3.ReportTemplate{
				{
					Name: "summary.csv",
					Template: `
      {{ $c := csv }}
      {{- $c := $c.AddColumn "startTime"                             "{{ dateRfc3339 .StartTime }}" }}
      {{- $c := $c.AddColumn "endTime"                               "{{ dateRfc3339 .EndTime }}" }}
      {{- $c := $c.AddColumn "endpointSelector"                      "{{ if .ReportSpec.Endpoints }}{{ .ReportSpec.Endpoints.Selector }}{{ end }}" }}
      {{- $c := $c.AddColumn "namespaceNames"                        "{{ if .ReportSpec.Endpoints }}{{ if .ReportSpec.Endpoints.Namespaces }}{{ join \";\" .ReportSpec.Endpoints.Namespaces.Names }}{{ end }}{{ end }}" }}
      {{- $c := $c.AddColumn "namespaceSelector"                     "{{ if .ReportSpec.Endpoints }}{{ if .ReportSpec.Endpoints.Namespaces }}{{ .ReportSpec.Endpoints.Namespaces.Selector }}{{ end }}{{ end }}" }}
      {{- $c := $c.AddColumn "serviceAccountNames"                   "{{ if .ReportSpec.Endpoints }}{{ if .ReportSpec.Endpoints.ServiceAccounts }}{{ join \";\" .ReportSpec.Endpoints.ServiceAccounts.Names }}{{ end }}{{ end }}" }}
      {{- $c := $c.AddColumn "serviceAccountSelectors"               "{{ if .ReportSpec.Endpoints }}{{ if .ReportSpec.Endpoints.ServiceAccounts }}{{ .ReportSpec.Endpoints.ServiceAccounts.Selector }}{{ end }}{{ end }}" }}
      {{- $c := $c.AddColumn "endpointsNumIngressProtected"          "{{ .EndpointsSummary.NumIngressProtected }}" }}
      {{- $c := $c.AddColumn "endpointsNumEgressProtected"           "{{ .EndpointsSummary.NumEgressProtected }}" }}
      {{- $c := $c.AddColumn "endpointsNumIngressUnprotected"        "{{ sub .EndpointsSummary.NumTotal .EndpointsSummary.NumIngressProtected }}" }}
      {{- $c := $c.AddColumn "endpointsNumEgressUnprotected"         "{{ sub .EndpointsSummary.NumTotal .EndpointsSummary.NumEgressProtected  }}" }}
      {{- $c := $c.AddColumn "endpointsNumIngressFromInternet"       "{{ .EndpointsSummary.NumIngressFromInternet }}" }}
      {{- $c := $c.AddColumn "endpointsNumEgressToInternet"          "{{ .EndpointsSummary.NumEgressToInternet }}" }}
      {{- $c := $c.AddColumn "endpointsNumIngressFromOtherNamespace" "{{ .EndpointsSummary.NumIngressFromOtherNamespace }}" }}
      {{- $c := $c.AddColumn "endpointsNumEgressToOtherNamespace"    "{{ .EndpointsSummary.NumEgressToOtherNamespace }}" }}
      {{- $c := $c.AddColumn "endpointsNumEnvoyEnabled"              "{{ .EndpointsSummary.NumEnvoyEnabled }}" }}
      {{- $c.Render . }}
`,
				},
				{
					Name: "endpoints.csv",
					Template: `
      {{ $c := csv }}
      {{- $c := $c.AddColumn "endpoint"                                  "{{ .Endpoint }}" }}
      {{- $c := $c.AddColumn "ingressProtected"                          "{{ .IngressProtected }}" }}
      {{- $c := $c.AddColumn "egressProtected"                           "{{ .EgressProtected }}" }}
      {{- $c := $c.AddColumn "ingressFromInternet"                       "{{ .IngressFromInternet }}" }}
      {{- $c := $c.AddColumn "egressToInternet"                          "{{ .EgressToInternet }}" }}
      {{- $c := $c.AddColumn "ingressFromOtherNamespace"                 "{{ .IngressFromOtherNamespace }}" }}
      {{- $c := $c.AddColumn "egressToOtherNamespace"                    "{{ .EgressToOtherNamespace }}" }}
      {{- $c := $c.AddColumn "envoyEnabled"                              "{{ .EnvoyEnabled }}" }}
      {{- $c := $c.AddColumn "appliedPolicies"                           "{{ join \";\" .AppliedPolicies }}" }}
      {{- $c := $c.AddColumn "trafficAggregationPrefix"                  "{{ flowsPrefix . }}" }}
      {{- $c := $c.AddColumn "endpointsGeneratingTrafficToThisEndpoint"  "{{ join \";\" (flowsIngress .) }}" }}
      {{- $c := $c.AddColumn "endpointsReceivingTrafficFromThisEndpoint" "{{ join \";\" (flowsEgress .) }}" }}
      {{- $c.Render .Endpoints }}
`,
				},
			},
			IncludeEndpointData:        true,
			IncludeEndpointFlowLogData: true,
			UISummaryTemplate: v3.ReportTemplate{
				Name: "ui-summary.json",
				Template: `
    {"heading":"Inscope vs Protected","type":"panel","widgets":[{"data":[{"label":"Protected ingress","value":{{ .EndpointsSummary.NumIngressProtected }}}],"heading":"Endpoints","summary":{"label":"Total","total":{{.EndpointsSummary.NumTotal }}},"type":"radialbarchart"},{"data":[{"label":"Protected ingress","value":{{ .NamespacesSummary.NumIngressProtected }}}],"heading":"Namespaces","summary":{"label":"Total","total":{{.NamespacesSummary.NumTotal }}},"type":"radialbarchart"},{"data":[{"label":"Protected egress","value":{{ .EndpointsSummary.NumEgressProtected }}}],"heading":"Endpoints","summary":{"label":"Total","total":{{.EndpointsSummary.NumTotal }}},"type":"radialbarchart"},{"data":[{"label":"Protected egress","value":{{ .NamespacesSummary.NumEgressProtected }}}],"heading":"Namespaces","summary":{"label":"Total","total":{{.NamespacesSummary.NumTotal }}},"type":"radialbarchart"}]}
`,
			},
		},
	}
}

func (c *complianceComponent) complianceGlobalReportPolicyAudit() *v3.GlobalReportType {
	return &v3.GlobalReportType{
		TypeMeta: metav1.TypeMeta{Kind: "GlobalReportType", APIVersion: "projectcalico.org/v3"},
		ObjectMeta: metav1.ObjectMeta{
			Name: "policy-audit",
			Labels: map[string]string{
				"global-report-type": "policy-audit",
			},
		},
		Spec: v3.ReportTypeSpec{
			AuditEventsSelection: &v3.AuditEventsSelection{
				Resources: []v3.AuditResource{
					{
						Resource: "globalnetworkpolicies",
					},
					{
						Resource: "networkpolicies",
					},
					{
						Resource: "stagedglobalnetworkpolicies",
					},
					{
						Resource: "stagednetworkpolicies",
					},
					{
						Resource: "stagedkubernetesnetworkpolicies",
					},
				},
			},
			DownloadTemplates: []v3.ReportTemplate{
				{
					Name: "summary.csv",
					Template: `
      {{ $c := csv }}
      {{- $c := $c.AddColumn "startTime"               "{{ dateRfc3339 .StartTime }}" }}
      {{- $c := $c.AddColumn "endTime"                 "{{ dateRfc3339 .EndTime }}" }}
      {{- $c := $c.AddColumn "endpointSelector"        "{{ if .ReportSpec.Endpoints }}{{ .ReportSpec.Endpoints.Selector }}{{ end }}" }}
      {{- $c := $c.AddColumn "namespaceNames"          "{{ if .ReportSpec.Endpoints }}{{ if .ReportSpec.Endpoints.Namespaces }}{{ join \";\" .ReportSpec.Endpoints.Namespaces.Names }}{{ end }}{{ end }}" }}
      {{- $c := $c.AddColumn "namespaceSelector"       "{{ if .ReportSpec.Endpoints }}{{ if .ReportSpec.Endpoints.Namespaces }}{{ .ReportSpec.Endpoints.Namespaces.Selector }}{{ end }}{{ end }}" }}
      {{- $c := $c.AddColumn "serviceAccountNames"     "{{ if .ReportSpec.Endpoints }}{{ if .ReportSpec.Endpoints.ServiceAccounts }}{{ join \";\" .ReportSpec.Endpoints.ServiceAccounts.Names }}{{ end }}{{ end }}" }}
      {{- $c := $c.AddColumn "serviceAccountSelectors" "{{ if .ReportSpec.Endpoints }}{{ if .ReportSpec.Endpoints.ServiceAccounts }}{{ .ReportSpec.Endpoints.ServiceAccounts.Selector }}{{ end }}{{ end }}" }}
      {{- $c := $c.AddColumn "numCreatedPolicies"      "{{ .AuditSummary.NumCreate }}" }}
      {{- $c := $c.AddColumn "numModifiedPolicies"     "{{ .AuditSummary.NumModify }}" }}
      {{- $c := $c.AddColumn "numDeletedPolicies"      "{{ .AuditSummary.NumDelete }}" }}
      {{- $c.Render . }}
`,
				},
				{
					Name:     "events.json",
					Template: "{{ toJson .AuditEvents }}",
				},
				{
					Name:     "events.yaml",
					Template: "{{ toYaml .AuditEvents }}",
				},
			},
			UISummaryTemplate: v3.ReportTemplate{
				Name: "ui-summary.json",
				Template: `
    {"heading":"Network Policy Configuration Changes","type":"panel","widgets":[{"data":[{"label":"Created","value":{{.AuditSummary.NumCreate }}}],"heading":"Network Policies","summary":{"label":"Total","total":{{.AuditSummary.NumTotal }}},"type":"radialbarchart"},{"data":[{"label":"Modified","value":{{.AuditSummary.NumModify }}}],"heading":"Network Policies","summary":{"label":"Total","total":{{.AuditSummary.NumTotal }}},"type":"radialbarchart"},{"data":[{"label":"Deleted","value":{{.AuditSummary.NumDelete }}}],"heading":"Network Policies","summary":{"label":"Total","total":{{.AuditSummary.NumTotal }}},"type":"radialbarchart"}]}
`,
			},
		},
	}
}

func (c *complianceComponent) complianceGlobalReportCISBenchmark() *v3.GlobalReportType {
	return &v3.GlobalReportType{
		TypeMeta: metav1.TypeMeta{Kind: "GlobalReportType", APIVersion: "projectcalico.org/v3"},
		ObjectMeta: metav1.ObjectMeta{
			Name: "cis-benchmark",
			Labels: map[string]string{
				"global-report-type": "cis-benchmark",
			},
		},
		Spec: v3.ReportTypeSpec{
			DownloadTemplates:       c.getCISDownloadReportTemplates(),
			IncludeCISBenchmarkData: true,
			UISummaryTemplate: v3.ReportTemplate{
				Name:     "ui-summary.json",
				Template: "{{ $n := len .CISBenchmark }}{\"heading\": \"Kubernetes CIS Benchmark\",\"type\": \"row\",\"widgets\": [{\"heading\": \"Node Failure Summary\",\"type\": \"cis-benchmark-nodes\",\"summary\": {\"label\": \"Total\",\"total\": {{ $n }}},\"data\": [{\"label\": \"HIGH\",\"value\": {{ .CISBenchmarkSummary.HighCount }},\"desc\": \"Nodes with {{ if .ReportSpec.CIS }}{{ if .ReportSpec.CIS.HighThreshold }}{{ if eq (int .ReportSpec.CIS.HighThreshold) 100 }}100%{{ else }}{{ .ReportSpec.CIS.HighThreshold }}% or more{{ end }}{{ else }}100%{{ end }}{{ else }}100%{{ end }} tests passing\"}, {\"label\": \"MED\",\"value\": {{ .CISBenchmarkSummary.MedCount }},\"desc\": \"Nodes with {{ if .ReportSpec.CIS }}{{ if .ReportSpec.CIS.MedThreshold }}{{ .ReportSpec.CIS.MedThreshold }}{{ else }}50{{ end }}{{ else }}50{{ end }}% or more tests passing\"}, {\"label\": \"LOW\",\"value\": {{ .CISBenchmarkSummary.LowCount }},\"desc\": \"Nodes with less than {{ if .ReportSpec.CIS }}{{ if .ReportSpec.CIS.MedThreshold }}{{ .ReportSpec.CIS.MedThreshold }}{{ else }}50{{ end }}{{ else }}50{{ end }}% tests passing\"}]}{{ if .CISBenchmark }}, {\"heading\": \"Top Failed Tests\",\"type\": \"cis-benchmark-tests\",\"topFailedTests\": {\"tests\": [{{ $tests := cisTopFailedTests . }}{{ $nTests := len $tests }}{{ range $i, $test := $tests }}{\"index\": \"{{ $test.TestNumber }}\",\"description\": \"{{ $test.TestDesc }}\",\"failedCount\": \"{{ $test.Count }}\"} {{ $i1 := add1 $i }}{{ if ne $i1 $nTests }}, {{ end }}{{ end }}]} }{{ end }}]}",
			},
		},
	}
}

func (c *complianceComponent) getCISDownloadReportTemplates() []v3.ReportTemplate {
	return []v3.ReportTemplate{
		{
			Name: "all-tests.csv",
			Template: `nodeName,testIndex,testDescription,status,scored,remediation
{{ range $i, $node := .CISBenchmark -}}
{{- range $j, $section := $node.Results -}}
{{- range $k, $result := $section.Results -}}
{{- $node.NodeName }},{{ $result.TestNumber }},{{ $result.TestDesc }},{{ $result.Status }},{{ $result.Scored }},"{{ $result.TestInfo }}"
{{ end }}
{{- end }}
{{- end }}`,
		},
		{
			Name: "failed-tests.csv",
			Template: `nodeName,testIndex,testDescription,status,scored,remediation
{{ range $i, $node := .CISBenchmark }}
{{- range $j, $section := $node.Results }}
{{- range $k, $result := $section.Results }}
{{- if eq $result.Status "FAIL" }}
{{- $node.NodeName }},{{ $result.TestNumber }},{{ $result.TestDesc }},{{ $result.Status }},{{ $result.Scored }},"{{ $result.TestInfo }}"
{{ end }}
{{- end }}
{{- end }}
{{- end }}`,
		},
		{
			Name: "node-summary.csv",
			Template: `node,version,status,testsPassing,testsFailing,testsUnknown,testsTotal
{{ range $_, $node := .CISBenchmark }}
{{- $node.NodeName }},{{ $node.KubernetesVersion }},{{ $node.Summary.Status }},{{ $node.Summary.TotalPass }},{{ $node.Summary.TotalFail }},{{ $node.Summary.TotalInfo }},{{ $node.Summary.Total }}
{{ end }}`,
		},
		{
			Name: "total-summary.csv",
			Template: `{{ $c := csv }}
{{- $c := $c.AddColumn "startTime"          "{{ dateRfc3339 .StartTime }}" }}
{{- $c := $c.AddColumn "endTime"            "{{ dateRfc3339 .EndTime }}" }}
{{- $c := $c.AddColumn "type"               "{{ .CISBenchmarkSummary.Type }}" }}
{{- $c := $c.AddColumn "hiPercentThreshold" "{{ if .ReportSpec.CIS }}{{ if .ReportSpec.CIS.HighThreshold  }}{{ .ReportSpec.CIS.HighThreshold }}{{ else }}100{{ end }}{{ else }}100{{ end }}" }}
{{- $c := $c.AddColumn "medPercentThreshold" "{{ if .ReportSpec.CIS }}{{ if .ReportSpec.CIS.MedThreshold  }}{{ .ReportSpec.CIS.MedThreshold }}{{ else }}50{{ end }}{{ else }}50{{ end }}" }}
{{- $c := $c.AddColumn "hiNodeCount"         "{{ .CISBenchmarkSummary.HighCount }}" }}
{{- $c := $c.AddColumn "medNodeCount"        "{{ .CISBenchmarkSummary.MedCount }}" }}
{{- $c := $c.AddColumn "lowNodeCount"        "{{ .CISBenchmarkSummary.LowCount }}" }}
{{- $c.Render . }}`,
		},
	}
}

// Allow internal communication from compliance-benchmarker, compliance-controller, compliance-snapshotter, compliance-reporter
// to apiserver, coredns, linseed, and elasticsearch.
func (c *complianceComponent) complianceAccessCalicoSystemNetworkPolicy() *v3.NetworkPolicy {
	egressRules := []v3.Rule{
		{
			Action:      v3.Allow,
			Protocol:    &networkpolicy.TCPProtocol,
			Destination: networkpolicy.KubeAPIServerEntityRule,
		},
	}

	egressRules = networkpolicy.AppendDNSEgressRules(egressRules, c.cfg.OpenShift)

	if c.cfg.ManagementClusterConnection == nil {
		egressRules = append(egressRules, v3.Rule{
			Action:      v3.Allow,
			Protocol:    &networkpolicy.TCPProtocol,
			Destination: networkpolicy.DefaultHelper().LinseedEntityRule(),
		})
	} else {
		egressRules = append(egressRules, v3.Rule{
			Action:      v3.Allow,
			Protocol:    &networkpolicy.TCPProtocol,
			Destination: GuardianEntityRule,
		})
	}

	return &v3.NetworkPolicy{
		TypeMeta: metav1.TypeMeta{Kind: "NetworkPolicy", APIVersion: "projectcalico.org/v3"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      ComplianceAccessPolicyName,
			Namespace: c.cfg.Namespace,
		},
		Spec: v3.NetworkPolicySpec{
			Order:    &networkpolicy.HighPrecedenceOrder,
			Tier:     networkpolicy.CalicoTierName,
			Selector: networkpolicy.KubernetesAppSelector(ComplianceBenchmarkerName, ComplianceControllerName, ComplianceSnapshotterName, ComplianceReporterName),
			Types:    []v3.PolicyType{v3.PolicyTypeEgress},
			Egress:   egressRules,
		},
	}
}

// Allow internal communication to compliance-server from Manager.
func (c *complianceComponent) complianceServerCalicoSystemNetworkPolicy() *v3.NetworkPolicy {
	networkpolicyHelper := networkpolicy.Helper(c.cfg.Tenant.MultiTenant(), c.cfg.Namespace)
	egressRules := []v3.Rule{
		{
			Action:      v3.Allow,
			Protocol:    &networkpolicy.TCPProtocol,
			Destination: networkpolicy.KubeAPIServerEntityRule,
		},
		{
			Action:      v3.Allow,
			Protocol:    &networkpolicy.TCPProtocol,
			Destination: networkpolicyHelper.LinseedEntityRule(),
		},
	}

	egressRules = networkpolicy.AppendDNSEgressRules(egressRules, c.cfg.OpenShift)

	// add oidc egress rule
	if c.cfg.KeyValidatorConfig != nil {
		if parsedURL, err := url.Parse(c.cfg.KeyValidatorConfig.Issuer()); err == nil {
			egressRules = append(egressRules, networkpolicy.GetOIDCEgressRule(parsedURL))
		}
	}

	egressRules = append(egressRules, []v3.Rule{
		{
			Action:      v3.Allow,
			Protocol:    &networkpolicy.TCPProtocol,
			Destination: DexEntityRule,
		},
		// compliance-server does RBAC checks for managed cluster compliance reports via guardian.
		{
			Action:      v3.Allow,
			Protocol:    &networkpolicy.TCPProtocol,
			Destination: networkpolicyHelper.ManagerEntityRule(),
		},
	}...)

	ingressRules := []v3.Rule{
		{
			Action:   v3.Allow,
			Protocol: &networkpolicy.TCPProtocol,
			Source:   networkpolicyHelper.ManagerSourceEntityRule(),
			Destination: v3.EntityRule{
				Ports: networkpolicy.Ports(complianceServerPort),
			},
		},
	}

	return &v3.NetworkPolicy{
		TypeMeta: metav1.TypeMeta{Kind: "NetworkPolicy", APIVersion: "projectcalico.org/v3"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      ComplianceServerPolicyName,
			Namespace: c.cfg.Namespace,
		},
		Spec: v3.NetworkPolicySpec{
			Order:    &networkpolicy.HighPrecedenceOrder,
			Tier:     networkpolicy.CalicoTierName,
			Selector: networkpolicy.KubernetesAppSelector(ComplianceServerName),
			Types:    []v3.PolicyType{v3.PolicyTypeIngress, v3.PolicyTypeEgress},
			Ingress:  ingressRules,
			Egress:   egressRules,
		},
	}
}

func (c *complianceComponent) multiTenantManagedClustersAccess() []client.Object {
	var objects []client.Object

	// In a single tenant setup we want to create a cluster role that binds using service account
	// tigera-compliance-server from tigera-compliance namespace. In a multi-tenant setup
	// Compliance server from the tenant's namespace impersonates service tigera-compliance-server
	// from tigera-compliance namespace
	objects = append(objects, &rbacv1.RoleBinding{
		TypeMeta:   metav1.TypeMeta{Kind: "RoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{Name: MultiTenantComplianceManagedClustersAccessRoleBindingName, Namespace: c.cfg.Namespace},
		RoleRef: rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "ClusterRole",
			Name:     MultiTenantManagedClustersAccessClusterRoleName,
		},
		Subjects: []rbacv1.Subject{
			// requests for compliance to managed clusters are done using service account tigera-compliance-server
			// from tigera-compliance namespace regardless of tenancy mode (single tenant or multi-tenant)
			{
				Kind:      "ServiceAccount",
				Name:      ComplianceServerServiceAccount,
				Namespace: ComplianceNamespace,
			},
		},
	})

	return objects
}
