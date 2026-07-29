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
	"strconv"
	"strings"
	"time"

	batchv1 "k8s.io/api/batch/v1"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apiserver/pkg/authentication/serviceaccount"
	"sigs.k8s.io/controller-runtime/pkg/client"

	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/components"
	rcomponents "github.com/tigera/operator/pkg/render/common/components"
	relasticsearch "github.com/tigera/operator/pkg/render/common/elasticsearch"
	rmeta "github.com/tigera/operator/pkg/render/common/meta"
	"github.com/tigera/operator/pkg/render/common/networkpolicy"
	"github.com/tigera/operator/pkg/render/common/securitycontext"
	"github.com/tigera/operator/pkg/render/common/securitycontextconstraints"
	"github.com/tigera/operator/pkg/tls/certificatemanagement"
	"github.com/tigera/operator/pkg/tls/certkeyusage"
)

const (
	IntrusionDetectionNamespace = "tigera-intrusion-detection"
	IntrusionDetectionName      = "intrusion-detection-controller"

	ElasticsearchIntrusionDetectionUserSecret    = "tigera-ee-intrusion-detection-elasticsearch-access"
	ElasticsearchIntrusionDetectionJobUserSecret = "tigera-ee-installer-elasticsearch-access"
	ElasticsearchPerformanceHotspotsUserSecret   = "tigera-ee-performance-hotspots-elasticsearch-access"

	IntrusionDetectionInstallerJobName                     = "intrusion-detection-es-job-installer"
	IntrusionDetectionControllerName                       = "intrusion-detection-controller"
	IntrusionDetectionControllerPolicyName                 = networkpolicy.CalicoComponentPolicyPrefix + IntrusionDetectionControllerName
	IntrusionDetectionInstallerPolicyName                  = networkpolicy.CalicoComponentPolicyPrefix + "intrusion-detection-elastic"
	MultiTenantManagedClustersAccessClusterRoleBindingName = "tigera-intrusion-detection-managed-cluster-access"
	IntrusionDetectionManagedClustersWatchRoleBindingName  = "tigera-intrusion-detection-managed-cluster-watch"

	ADAPIObjectName                 = "anomaly-detection-api"
	IntrusionDetectionTLSSecretName = "intrusion-detection-tls"
	DPITLSSecretName                = "deep-packet-inspection-tls"
	ADAPIPolicyName                 = networkpolicy.CalicoComponentPolicyPrefix + ADAPIObjectName

	ADPersistentVolumeClaimName = "tigera-anomaly-detection"
	ADJobPodTemplateBaseName    = "tigera.io.detectors"
	adDetectorPrefixName        = "tigera.io.detector."
	adDetectorName              = "anomaly-detectors"
	ADDetectorPolicyName        = networkpolicy.CalicoComponentPolicyPrefix + adDetectorName
)

// Register secret/certs that need Server and Client Key usage
var (
	intrusionDetectionNamespaceSelector = fmt.Sprintf("projectcalico.org/name == '%s'", IntrusionDetectionNamespace)
	IntrusionDetectionSourceEntityRule  = v3.EntityRule{
		NamespaceSelector: intrusionDetectionNamespaceSelector,
		Selector:          fmt.Sprintf("k8s-app == '%s'", IntrusionDetectionControllerName),
	}
)

var IntrusionDetectionInstallerSourceEntityRule = v3.EntityRule{
	NamespaceSelector: intrusionDetectionNamespaceSelector,
	Selector:          fmt.Sprintf("job-name == '%s'", IntrusionDetectionInstallerJobName),
}

// Register secret/certs that need Server and Client Key usage
func init() {
	certkeyusage.SetCertKeyUsage(DPITLSSecretName, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth})
}

func IntrusionDetection(cfg *IntrusionDetectionConfiguration) Component {
	return &intrusionDetectionComponent{
		cfg: cfg,
	}
}

// IntrusionDetectionConfiguration contains all the config information needed to render the component.
type IntrusionDetectionConfiguration struct {
	IntrusionDetection        *operatorv1.IntrusionDetection
	LogCollector              *operatorv1.LogCollector
	Installation              *operatorv1.InstallationSpec
	PullSecrets               []*corev1.Secret
	OpenShift                 bool
	ClusterDomain             string
	ESLicenseType             ElasticsearchLicenseType
	ManagedCluster            bool
	ManagementCluster         bool
	SyslogForwardingIsEnabled bool

	HasNoLicense                 bool
	TrustedCertBundle            certificatemanagement.TrustedBundleRO
	IntrusionDetectionCertSecret certificatemanagement.KeyPairInterface

	Namespace       string
	BindNamespaces  []string
	Tenant          *operatorv1.Tenant
	ExternalElastic bool
}

type intrusionDetectionComponent struct {
	cfg             *IntrusionDetectionConfiguration
	controllerImage string
	calicoImage     string
}

func (c *intrusionDetectionComponent) ResolveImages(is *operatorv1.ImageSet) error {
	reg := c.cfg.Installation.Registry
	path := c.cfg.Installation.ImagePath
	prefix := c.cfg.Installation.ImagePrefix
	var errMsgs []string
	var err error

	c.controllerImage, err = components.GetReference(components.ComponentIntrusionDetectionController, reg, path, prefix, is)
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

func (c *intrusionDetectionComponent) SupportedOSType() rmeta.OSType {
	return rmeta.OSTypeLinux
}

func (c *intrusionDetectionComponent) Objects() ([]client.Object, []client.Object) {
	objs := []client.Object{}

	if !c.cfg.Tenant.MultiTenant() {
		// GlobalAlertTemplates are not used in multi-tenant management clusters.
		objs = append(objs, c.globalAlertTemplates()...)
	}

	objs = append(objs,
		c.intrusionDetectionControllerCalicoSystemPolicy(),
		networkpolicy.CalicoSystemDefaultDeny(c.cfg.Namespace),
		c.intrusionDetectionServiceAccount(),
		c.intrusionDetectionClusterRole(),
		c.intrusionDetectionClusterRoleBinding(),
		c.intrusionDetectionRole(),
		c.intrusionDetectionRoleBinding(),
		c.intrusionDetectionDeployment(),
	)

	if c.cfg.ManagementCluster {
		// Only needed on management clusters.
		objs = append(objs, c.managedClustersWatchRoleBinding())
	}
	if c.cfg.Tenant.MultiTenant() {
		objs = append(objs, c.multiTenantManagedClustersAccess()...)
	}

	objsToDelete := []client.Object{
		// PSPs have been removed from the Kubernetes API since v1.25, so we can delete
		// any resources related to them that might still exist.
		c.intrusionDetectionPSPClusterRole(),
		c.intrusionDetectionPSPClusterRoleBinding(),
		// allow-tigera Tier was renamed to calico-system
		networkpolicy.DeprecatedAllowTigeraNetworkPolicyObject("intrusion-detection-controller", c.cfg.Namespace),
		networkpolicy.DeprecatedAllowTigeraNetworkPolicyObject("default-deny", c.cfg.Namespace),
		// Image Assurance was removed; clean up the resources that prior versions copied
		// into the intrusion-detection namespace.
		&corev1.Secret{
			TypeMeta:   metav1.TypeMeta{Kind: "Secret", APIVersion: "v1"},
			ObjectMeta: metav1.ObjectMeta{Name: "tigera-image-assurance-api-cert", Namespace: c.cfg.Namespace},
		},
		&corev1.ConfigMap{
			TypeMeta:   metav1.TypeMeta{Kind: "ConfigMap", APIVersion: "v1"},
			ObjectMeta: metav1.ObjectMeta{Name: "tigera-image-assurance-config", Namespace: c.cfg.Namespace},
		},
		&corev1.Secret{
			TypeMeta:   metav1.TypeMeta{Kind: "Secret", APIVersion: "v1"},
			ObjectMeta: metav1.ObjectMeta{Name: "image-assurance-api-token", Namespace: c.cfg.Namespace},
		},
	}

	if !c.cfg.ManagementCluster {
		// These aren't needed unless we're a management cluster. Delete
		// both variants in case a cluster switches from management to
		// standalone (or to clean up bindings rendered by older versions).
		objsToDelete = append(objsToDelete,
			&rbacv1.RoleBinding{
				TypeMeta:   metav1.TypeMeta{Kind: "RoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"},
				ObjectMeta: metav1.ObjectMeta{Name: IntrusionDetectionManagedClustersWatchRoleBindingName, Namespace: c.cfg.Namespace},
			},
			&rbacv1.ClusterRoleBinding{
				TypeMeta:   metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"},
				ObjectMeta: metav1.ObjectMeta{Name: IntrusionDetectionManagedClustersWatchRoleBindingName},
			},
		)
	}

	if !c.cfg.ManagedCluster && !c.cfg.Tenant.MultiTenant() {
		// Delete any anomaly detection components that might still exist.
		// These were removed in an earlier version of the operator.
		objsToDelete = append(objsToDelete, c.adComponentsToDelete()...)
	}

	if !c.cfg.ManagedCluster && !c.cfg.Tenant.MultiTenant() {
		// For now, we don't create the installer job in multi-tenant clusters.
		idsObjs := []client.Object{
			c.intrusionDetectionJobServiceAccount(),
			c.intrusionDetectionElasticsearchCalicoSystemPolicy(),
			c.intrusionDetectionElasticsearchJob(),
		}
		objsToDelete = append(objsToDelete, idsObjs...)
	}

	if c.cfg.ManagedCluster {
		// For managed clusters, we must create a role binding to allow Linseed to
		// manage access token secrets in our namespace.
		objs = append(objs, c.externalLinseedRoleBinding())
	} else {
		// We can delete the role binding for management and standalone clusters, since
		// for these cluster types normal serviceaccount tokens are used.
		objsToDelete = append(objsToDelete, c.externalLinseedRoleBinding())
	}

	if c.cfg.HasNoLicense {
		return nil, objs
	}
	return objs, objsToDelete
}

func (c *intrusionDetectionComponent) Ready() bool {
	return true
}

func (c *intrusionDetectionComponent) intrusionDetectionElasticsearchJob() *batchv1.Job {
	return &batchv1.Job{
		TypeMeta: metav1.TypeMeta{Kind: "Job", APIVersion: "batch/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      IntrusionDetectionInstallerJobName,
			Namespace: c.cfg.Namespace,
		},
	}
}

func (c *intrusionDetectionComponent) intrusionDetectionServiceAccount() *corev1.ServiceAccount {
	return &corev1.ServiceAccount{
		TypeMeta: metav1.TypeMeta{Kind: "ServiceAccount", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      IntrusionDetectionName,
			Namespace: c.cfg.Namespace,
		},
	}
}

func (c *intrusionDetectionComponent) intrusionDetectionJobServiceAccount() *corev1.ServiceAccount {
	return &corev1.ServiceAccount{
		TypeMeta: metav1.TypeMeta{Kind: "ServiceAccount", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      IntrusionDetectionInstallerJobName,
			Namespace: c.cfg.Namespace,
		},
	}
}

func (c *intrusionDetectionComponent) intrusionDetectionClusterRole() *rbacv1.ClusterRole {
	rules := []rbacv1.PolicyRule{
		{
			APIGroups: []string{
				"projectcalico.org",
			},
			Resources: []string{
				"globalalerts",
				"globalalerts/status",
				"globalthreatfeeds",
				"globalthreatfeeds/status",
				"globalnetworksets",
			},
			Verbs: []string{
				"get", "list", "watch", "create", "update", "patch", "delete",
			},
		},
		{
			APIGroups: []string{
				"projectcalico.org",
				"crd.projectcalico.org",
			},
			Resources: []string{
				"licensekeys",
			},
			Verbs: []string{
				"get", "watch",
			},
		},
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
			// Add write access to Linseed APIs.
			APIGroups: []string{"linseed.tigera.io"},
			Resources: []string{"events"},
			Verbs:     []string{"create"},
		},
		{
			// Add write/read/delete access to Linseed APIs.
			APIGroups: []string{"linseed.tigera.io"},
			Resources: []string{"threatfeeds_ipset", "threatfeeds_domainnameset"},
			Verbs:     []string{"create", "delete", "get"},
		},
		{
			// Add read access to Linseed APIs.
			APIGroups: []string{"linseed.tigera.io"},
			Resources: []string{
				"waflogs",
				"dnslogs",
				"l7logs",
				"flowlogs",
				"auditlogs",
				"events",
			},
			Verbs: []string{"get"},
		},
		{
			APIGroups: []string{""},
			Resources: []string{"secrets", "configmaps"},
			Verbs:     []string{"get", "list", "watch"},
		},
		{
			APIGroups: []string{"projectcalico.org", "crd.projectcalico.org"},
			Resources: []string{"securityeventwebhooks", "securityeventwebhooks/status"},
			Verbs:     []string{"get", "list", "watch", "update"},
		},
		{
			APIGroups: []string{"projectcalico.org", "crd.projectcalico.org"},
			Resources: []string{"alertexceptions"},
			Verbs:     []string{"get", "list"},
		},
	}

	if !c.cfg.ManagedCluster {
		managementRule := []rbacv1.PolicyRule{
			{
				APIGroups: []string{"authentication.k8s.io"},
				Resources: []string{"tokenreviews"},
				Verbs:     []string{"create"},
			},
			{
				APIGroups: []string{"batch"},
				Resources: []string{"cronjobs", "jobs"},
				Verbs: []string{
					"get", "list", "watch", "create", "update", "patch", "delete",
				},
			},
		}

		// We don't have AD CronJobs any more, but leaving this here in case it now applies
		// to more cases, as there's nothing actual specific to AD CronJobs in the following
		// rule definition.
		//
		// "Used when IDS Controller creates Cronjobs for AD as the IDS deployment
		// is the owner of the AD Cronjobs - Openshift blocks setting an
		// blockOwnerDeletion to true if an ownerReference refers to a resource
		// you can't set finalizers on"
		if c.cfg.OpenShift {
			managementRule = append(managementRule,
				rbacv1.PolicyRule{
					APIGroups: []string{"apps"},
					Resources: []string{"deployments/finalizers"},
					Verbs:     []string{"update"},
				})
		}

		rules = append(rules, managementRule...)
	}

	if c.cfg.Tenant.MultiTenant() {
		// These rules are used by Intrusion Detection Controller in a management cluster serving multiple tenants in order to appear to managed
		// clusters as the expected serviceaccount. They're only needed when there are multiple tenants sharing the same
		// management cluster.
		rules = append(rules, []rbacv1.PolicyRule{
			{
				APIGroups:     []string{""},
				Resources:     []string{"serviceaccounts"},
				Verbs:         []string{"impersonate"},
				ResourceNames: []string{IntrusionDetectionControllerName},
			},
			{
				APIGroups: []string{""},
				Resources: []string{"groups"},
				Verbs:     []string{"impersonate"},
				ResourceNames: []string{
					serviceaccount.AllServiceAccountsGroup,
					"system:authenticated",
					fmt.Sprintf("%s%s", serviceaccount.ServiceAccountGroupPrefix, IntrusionDetectionNamespace),
				},
			},
		}...)
	}

	if c.cfg.OpenShift {
		sccName := securitycontextconstraints.NonRootV2
		if c.cfg.SyslogForwardingIsEnabled {
			sccName = securitycontextconstraints.Privileged
		}
		rules = append(rules, rbacv1.PolicyRule{
			APIGroups:     []string{"security.openshift.io"},
			Resources:     []string{"securitycontextconstraints"},
			Verbs:         []string{"use"},
			ResourceNames: []string{sccName},
		})
	}

	return &rbacv1.ClusterRole{
		TypeMeta: metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name: IntrusionDetectionName,
		},
		Rules: rules,
	}
}

func (c *intrusionDetectionComponent) intrusionDetectionClusterRoleBinding() *rbacv1.ClusterRoleBinding {
	return rcomponents.ClusterRoleBinding(IntrusionDetectionName, IntrusionDetectionName, IntrusionDetectionName, c.cfg.BindNamespaces)
}

func (c *intrusionDetectionComponent) managedClustersWatchRoleBinding() client.Object {
	if c.cfg.Tenant.MultiTenant() {
		return rcomponents.RoleBinding(IntrusionDetectionManagedClustersWatchRoleBindingName, ManagedClustersWatchClusterRoleName, IntrusionDetectionName, c.cfg.Namespace)
	} else {
		return rcomponents.ClusterRoleBinding(IntrusionDetectionManagedClustersWatchRoleBindingName, ManagedClustersWatchClusterRoleName, IntrusionDetectionName, []string{c.cfg.Namespace})
	}
}

func (c *intrusionDetectionComponent) externalLinseedRoleBinding() *rbacv1.RoleBinding {
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

func (c *intrusionDetectionComponent) intrusionDetectionRole() *rbacv1.Role {
	return &rbacv1.Role{
		TypeMeta: metav1.TypeMeta{Kind: "Role", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      IntrusionDetectionName,
			Namespace: c.cfg.Namespace,
		},
		Rules: []rbacv1.PolicyRule{
			{
				APIGroups: []string{""},
				Resources: []string{"secrets"},
				Verbs:     []string{"get"},
			},
			{
				// Intrusion detection forwarder snapshots its state to a specific ConfigMap.
				APIGroups: []string{""},
				Resources: []string{"configmaps"},
				Verbs:     []string{"get", "create", "update"},
			},
		},
	}
}

func (c *intrusionDetectionComponent) intrusionDetectionRoleBinding() *rbacv1.RoleBinding {
	return &rbacv1.RoleBinding{
		TypeMeta: metav1.TypeMeta{Kind: "RoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      IntrusionDetectionName,
			Namespace: c.cfg.Namespace,
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "Role",
			Name:     IntrusionDetectionName,
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      "ServiceAccount",
				Name:      IntrusionDetectionName,
				Namespace: c.cfg.Namespace,
			},
		},
	}
}

func (c *intrusionDetectionComponent) multiTenantManagedClustersAccess() []client.Object {
	var objects []client.Object

	// In a single tenant setup we want to create a role that binds using service account
	// intrusion-detection-controller from tigera-intrusion-detection namespace. In a multi-tenant setup
	// IntrusionDetectionController from the tenant's namespace impersonates service intrusion-detection-controller
	// from tigera-intrusion-detection namespace
	objects = append(objects, &rbacv1.RoleBinding{
		TypeMeta:   metav1.TypeMeta{Kind: "RoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{Name: MultiTenantManagedClustersAccessClusterRoleBindingName, Namespace: c.cfg.Namespace},
		RoleRef: rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "ClusterRole",
			Name:     MultiTenantManagedClustersAccessClusterRoleName,
		},
		Subjects: []rbacv1.Subject{
			// requests for Linseed to managed clusters are done using service account tigera-linseed
			// from tigera-elasticsearch namespace regardless of tenancy mode (single tenant or multi-tenant)
			{
				Kind:      "ServiceAccount",
				Name:      IntrusionDetectionControllerName,
				Namespace: IntrusionDetectionNamespace,
			},
		},
	})

	return objects
}

func (c *intrusionDetectionComponent) intrusionDetectionDeployment() *appsv1.Deployment {
	var replicas int32 = 1

	d := &appsv1.Deployment{
		TypeMeta: metav1.TypeMeta{Kind: "Deployment", APIVersion: "apps/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      IntrusionDetectionName,
			Namespace: c.cfg.Namespace,
		},
		Spec: appsv1.DeploymentSpec{
			Replicas: &replicas,
			Template: *c.deploymentPodTemplate(),
		},
	}

	if c.cfg.IntrusionDetection != nil {
		if overrides := c.cfg.IntrusionDetection.Spec.IntrusionDetectionControllerDeployment; overrides != nil {
			rcomponents.ApplyDeploymentOverrides(d, overrides)
		}
	}
	return d
}

func (c *intrusionDetectionComponent) deploymentPodTemplate() *corev1.PodTemplateSpec {
	var ps []corev1.LocalObjectReference
	for _, x := range c.cfg.PullSecrets {
		ps = append(ps, corev1.LocalObjectReference{Name: x.Name})
	}

	volumes := []corev1.Volume{
		c.cfg.TrustedCertBundle.Volume(),
		c.cfg.IntrusionDetectionCertSecret.Volume(),
	}
	// If syslog forwarding is enabled then set the necessary hostpath volume to write
	// logs for Fluent Bit to access.
	if c.cfg.SyslogForwardingIsEnabled {
		dirOrCreate := corev1.HostPathDirectoryOrCreate
		volumes = append(volumes, corev1.Volume{
			Name: "var-log-calico",
			VolumeSource: corev1.VolumeSource{
				HostPath: &corev1.HostPathVolumeSource{
					Path: "/var/log/calico",
					Type: &dirOrCreate,
				},
			},
		})
	}

	if c.cfg.ManagedCluster {
		volumes = append(volumes,
			corev1.Volume{
				Name: LinseedTokenVolumeName,
				VolumeSource: corev1.VolumeSource{
					Secret: &corev1.SecretVolumeSource{
						SecretName: fmt.Sprintf(LinseedTokenSecret, IntrusionDetectionName),
						Items:      []corev1.KeyToPath{{Key: LinseedTokenKey, Path: LinseedTokenSubPath}},
					},
				},
			})
	}

	intrusionDetectionContainer := c.intrusionDetectionControllerContainer()

	if c.cfg.ManagedCluster {
		envVars := []corev1.EnvVar{
			{Name: "DISABLE_ALERTS", Value: "yes"},
		}
		intrusionDetectionContainer.Env = append(intrusionDetectionContainer.Env, envVars...)
	}
	var initContainers []corev1.Container
	if c.cfg.IntrusionDetectionCertSecret != nil && c.cfg.IntrusionDetectionCertSecret.UseCertificateManagement() {
		initContainers = append(initContainers, c.cfg.IntrusionDetectionCertSecret.InitContainer(c.cfg.Namespace, intrusionDetectionContainer.SecurityContext))
	}

	containers := []corev1.Container{
		intrusionDetectionContainer,
	}

	if !c.cfg.Tenant.MultiTenant() {
		containers = append(containers, c.webhooksControllerContainer())
	}

	tolerations := c.cfg.Installation.ControlPlaneTolerations
	if c.cfg.Installation.KubernetesProvider.IsGKE() {
		tolerations = append(tolerations, rmeta.TolerateGKEARM64NoSchedule)
	}

	return &corev1.PodTemplateSpec{
		ObjectMeta: metav1.ObjectMeta{
			Name:        IntrusionDetectionName,
			Namespace:   c.cfg.Namespace,
			Annotations: c.intrusionDetectionAnnotations(),
		},
		Spec: corev1.PodSpec{
			Tolerations:        tolerations,
			NodeSelector:       c.cfg.Installation.ControlPlaneNodeSelector,
			ServiceAccountName: IntrusionDetectionName,
			ImagePullSecrets:   ps,
			InitContainers:     initContainers,
			Containers:         containers,
			Volumes:            volumes,
		},
	}
}

func (c *intrusionDetectionComponent) webhooksControllerContainer() corev1.Container {
	envVars := []corev1.EnvVar{
		{
			Name:  "LINSEED_URL",
			Value: relasticsearch.LinseedEndpoint(c.SupportedOSType(), c.cfg.ClusterDomain, ElasticsearchNamespace, c.cfg.ManagedCluster, false),
		},
		{
			Name:  "LINSEED_CA",
			Value: c.cfg.TrustedCertBundle.MountPath(),
		},
		{
			Name:  "LINSEED_CLIENT_CERT",
			Value: c.cfg.IntrusionDetectionCertSecret.VolumeMountCertificateFilePath(),
		},
		{
			Name:  "LINSEED_CLIENT_KEY",
			Value: c.cfg.IntrusionDetectionCertSecret.VolumeMountKeyFilePath(),
		},
		{
			Name:  "LINSEED_TOKEN",
			Value: GetLinseedTokenPath(c.cfg.ManagedCluster),
		},
	}

	volumeMounts := c.cfg.TrustedCertBundle.VolumeMounts(c.SupportedOSType())
	volumeMounts = append(volumeMounts, c.cfg.IntrusionDetectionCertSecret.VolumeMount(c.SupportedOSType()))
	if c.cfg.ManagedCluster {
		volumeMounts = append(volumeMounts,
			corev1.VolumeMount{
				Name:      LinseedTokenVolumeName,
				MountPath: LinseedVolumeMountPath,
			})
	}

	return corev1.Container{
		Name:            "webhooks-processor",
		Image:           c.calicoImage,
		Command:         []string{components.CalicoBinaryPath, "component", "webhooks-processor"},
		Env:             envVars,
		SecurityContext: securitycontext.NewNonRootContext(),
		VolumeMounts:    volumeMounts,
	}
}

func (c *intrusionDetectionComponent) intrusionDetectionControllerContainer() corev1.Container {
	envs := []corev1.EnvVar{
		{
			Name:  "MULTI_CLUSTER_FORWARDING_CA",
			Value: c.cfg.TrustedCertBundle.MountPath(),
		},
		{
			Name:  "LINSEED_URL",
			Value: relasticsearch.LinseedEndpoint(c.SupportedOSType(), c.cfg.ClusterDomain, LinseedNamespace(c.cfg.Tenant), c.cfg.ManagedCluster, false),
		},
		{
			Name:  "LINSEED_CA",
			Value: c.cfg.TrustedCertBundle.MountPath(),
		},
		{
			Name:  "LINSEED_CLIENT_CERT",
			Value: c.cfg.IntrusionDetectionCertSecret.VolumeMountCertificateFilePath(),
		},
		{
			Name:  "LINSEED_CLIENT_KEY",
			Value: c.cfg.IntrusionDetectionCertSecret.VolumeMountKeyFilePath(),
		},
		{
			Name:  "LINSEED_TOKEN",
			Value: GetLinseedTokenPath(c.cfg.ManagedCluster),
		},
		{
			Name:  "MANAGEMENT_CLUSTER",
			Value: strconv.FormatBool(c.cfg.ManagementCluster),
		},
	}

	if c.cfg.Tenant != nil {
		// Configure the tenant id in order to read /write linseed data using the correct tenant ID
		// Multi-tenant and single tenant with external elastic needs this variable set
		if c.cfg.ExternalElastic {
			envs = append(envs, corev1.EnvVar{Name: "TENANT_ID", Value: c.cfg.Tenant.Spec.ID})
		}

		if c.cfg.Tenant.MultiTenant() {
			envs = append(envs, corev1.EnvVar{Name: "TENANT_NAMESPACE", Value: c.cfg.Tenant.Namespace})
			envs = append(envs, corev1.EnvVar{Name: "MULTI_CLUSTER_FORWARDING_ENDPOINT", Value: ManagerService(c.cfg.Tenant)})
		}
	}
	sc := securitycontext.NewNonRootContext()

	// If syslog forwarding is enabled then set the necessary ENV var and volume mount to
	// write logs for Fluent Bit.
	volumeMounts := c.cfg.TrustedCertBundle.VolumeMounts(c.SupportedOSType())
	volumeMounts = append(volumeMounts, c.cfg.IntrusionDetectionCertSecret.VolumeMount(c.SupportedOSType()))
	if c.cfg.SyslogForwardingIsEnabled {
		envs = append(envs,
			corev1.EnvVar{Name: "IDS_ENABLE_EVENT_FORWARDING", Value: "true"},
		)
		volumeMounts = append(volumeMounts, syslogEventsForwardingVolumeMount())
		// When syslog forwarding is enabled, IDS controller mounts host volume /var/log/calico
		// and writes events to it. This host path is owned by root user and group so we have to
		// use privileged UID/GID 0.
		// On OpenShift, if we need the volume mount to hostpath volume for syslog forwarding,
		// then IDS controller needs privileged access to write event logs to that volume
		sc = securitycontext.NewRootContext(c.cfg.OpenShift)
	}

	if c.cfg.ManagedCluster {
		volumeMounts = append(volumeMounts,
			corev1.VolumeMount{
				Name:      LinseedTokenVolumeName,
				MountPath: LinseedVolumeMountPath,
			})
	}

	return corev1.Container{
		Name:    "controller",
		Image:   c.controllerImage,
		Command: []string{components.CalicoBinaryPath, "component", "intrusion-detection-controller"},
		Env:     envs,
		LivenessProbe: &corev1.Probe{
			ProbeHandler: corev1.ProbeHandler{
				Exec: &corev1.ExecAction{
					Command: []string{
						components.CalicoBinaryPath,
						"health",
						"--port=50000",
						"--type=liveness",
					},
				},
			},
			InitialDelaySeconds: 5,
		},
		SecurityContext: sc,
		VolumeMounts:    volumeMounts,
	}
}

func syslogEventsForwardingVolumeMount() corev1.VolumeMount {
	return corev1.VolumeMount{
		Name:      "var-log-calico",
		MountPath: "/var/log/calico",
	}
}

func (c *intrusionDetectionComponent) globalAlertTemplates() []client.Object {
	globalAlertTemplates := []client.Object{
		&v3.GlobalAlertTemplate{
			TypeMeta: metav1.TypeMeta{
				Kind:       "GlobalAlertTemplate",
				APIVersion: "projectcalico.org/v3",
			},
			ObjectMeta: metav1.ObjectMeta{
				Name: "policy.pod",
			},
			Spec: v3.GlobalAlertSpec{
				Description: "Alerts on any changes to pods within the cluster",
				Summary:     "[audit] [privileged access] change detected for pod ${objectRef.namespace}/${objectRef.name}",
				Severity:    100,
				Period:      &metav1.Duration{Duration: 10 * time.Minute},
				Lookback:    &metav1.Duration{Duration: 10 * time.Minute},
				DataSet:     "audit",
				Query:       "(verb=create OR verb=update OR verb=delete OR verb=patch) AND 'objectRef.resource'=pods",
				AggregateBy: []string{"objectRef.name", "objectRef.namespace"},
				Metric:      "count",
				Condition:   "gt",
				Threshold:   0,
			},
		},
		&v3.GlobalAlertTemplate{
			TypeMeta: metav1.TypeMeta{
				Kind:       "GlobalAlertTemplate",
				APIVersion: "projectcalico.org/v3",
			},
			ObjectMeta: metav1.ObjectMeta{
				Name: "policy.globalnetworkpolicy",
			},
			Spec: v3.GlobalAlertSpec{
				Description: "Alerts on any changes to network policies",
				Summary:     "[audit] [privileged access] change detected for ${objectRef.resource} ${objectRef.name}",
				Severity:    100,
				Period:      &metav1.Duration{Duration: 10 * time.Minute},
				Lookback:    &metav1.Duration{Duration: 10 * time.Minute},
				DataSet:     "audit",
				Query:       "(verb=create OR verb=update OR verb=delete OR verb=patch) AND 'objectRef.resource'=globalnetworkpolicies",
				AggregateBy: []string{"objectRef.name", "objectRef.resource"},
				Metric:      "count",
				Condition:   "gt",
				Threshold:   0,
			},
		},
		&v3.GlobalAlertTemplate{
			TypeMeta: metav1.TypeMeta{
				Kind:       "GlobalAlertTemplate",
				APIVersion: "projectcalico.org/v3",
			},
			ObjectMeta: metav1.ObjectMeta{
				Name: "policy.globalnetworkset",
			},
			Spec: v3.GlobalAlertSpec{
				Description: "Alerts on any changes to global network sets",
				Summary:     "[audit] [privileged access] change detected for ${objectRef.resource} ${objectRef.name}",
				Severity:    100,
				Period:      &metav1.Duration{Duration: 10 * time.Minute},
				Lookback:    &metav1.Duration{Duration: 10 * time.Minute},
				DataSet:     "audit",
				Query:       "(verb=create OR verb=update OR verb=delete OR verb=patch) AND 'objectRef.resource'=globalnetworksets",
				AggregateBy: []string{"objectRef.resource", "objectRef.name"},
				Metric:      "count",
				Condition:   "gt",
				Threshold:   0,
			},
		},
		&v3.GlobalAlertTemplate{
			TypeMeta: metav1.TypeMeta{
				Kind:       "GlobalAlertTemplate",
				APIVersion: "projectcalico.org/v3",
			},
			ObjectMeta: metav1.ObjectMeta{
				Name: "policy.serviceaccount",
			},
			Spec: v3.GlobalAlertSpec{
				Description: "Alerts on any changes to service accounts within the cluster",
				Summary:     "[audit] [privileged access] change detected for serviceaccount ${objectRef.namespace}/${objectRef.name}",
				Severity:    100,
				Period:      &metav1.Duration{Duration: 10 * time.Minute},
				Lookback:    &metav1.Duration{Duration: 10 * time.Minute},
				DataSet:     "audit",
				Query:       "(verb=create OR verb=update OR verb=delete OR verb=patch) AND 'objectRef.resource'='serviceaccounts'",
				AggregateBy: []string{"objectRef.namespace", "objectRef.name"},
				Metric:      "count",
				Condition:   "gt",
				Threshold:   0,
			},
		},
		&v3.GlobalAlertTemplate{
			TypeMeta: metav1.TypeMeta{
				Kind:       "GlobalAlertTemplate",
				APIVersion: "projectcalico.org/v3",
			},
			ObjectMeta: metav1.ObjectMeta{
				Name: "network.cloudapi",
			},
			Spec: v3.GlobalAlertSpec{
				Description: "Alerts on access to cloud metadata APIs",
				Summary:     "[flows] [cloud API] cloud metadata API accessed by ${source_namespace}/${source_name_aggr}",
				Severity:    100,
				Period:      &metav1.Duration{Duration: 10 * time.Minute},
				Lookback:    &metav1.Duration{Duration: 10 * time.Minute},
				DataSet:     "flows",
				Query:       "(dest_name_aggr='metadata-api' OR dest_ip='169.254.169.254' OR dest_name_aggr='kse.kubernetes') AND proto='tcp' AND action='allow' AND reporter=src AND (source_namespace='default')",
				AggregateBy: []string{"source_namespace", "source_name_aggr"},
				Field:       "num_flows",
				Metric:      "sum",
				Condition:   "gt",
				Threshold:   0,
			},
		},
		&v3.GlobalAlertTemplate{
			TypeMeta: metav1.TypeMeta{
				Kind:       "GlobalAlertTemplate",
				APIVersion: "projectcalico.org/v3",
			},
			ObjectMeta: metav1.ObjectMeta{
				Name: "network.ssh",
			},
			Spec: v3.GlobalAlertSpec{
				Description: "Alerts on the use of ssh to and from a specific namespace (e.g. default)",
				Summary:     "[flows] ssh flow in default namespace detected from ${source_namespace}/${source_name_aggr}",
				Severity:    100,
				Period:      &metav1.Duration{Duration: 10 * time.Minute},
				Lookback:    &metav1.Duration{Duration: 10 * time.Minute},
				DataSet:     "flows",
				Query:       "proto='tcp' AND action='allow' AND dest_port='22' AND (source_namespace='default' OR dest_namespace='default') AND reporter=src",
				AggregateBy: []string{"source_namespace", "source_name_aggr"},
				Field:       "num_flows",
				Metric:      "sum",
				Condition:   "gt",
				Threshold:   0,
			},
		},
		&v3.GlobalAlertTemplate{
			TypeMeta: metav1.TypeMeta{
				Kind:       "GlobalAlertTemplate",
				APIVersion: "projectcalico.org/v3",
			},
			ObjectMeta: metav1.ObjectMeta{
				Name: "network.lateral.access",
			},
			Spec: v3.GlobalAlertSpec{
				Description: "Alerts when pods with a specific label (e.g. app=monitor) accessed by other workloads within the cluster",
				Summary:     "[flows] [lateral movement] ${source_namespace}/${source_name_aggr} with label app=monitor is accessed",
				Severity:    100,
				Period:      &metav1.Duration{Duration: 10 * time.Minute},
				Lookback:    &metav1.Duration{Duration: 10 * time.Minute},
				DataSet:     "flows",
				Query:       "'source_labels.labels'='app=monitor' AND proto=tcp AND action=allow AND reporter=dst",
				AggregateBy: []string{"source_namespace", "source_name_aggr"},
				Field:       "num_flows",
				Metric:      "sum",
				Condition:   "gt",
				Threshold:   0,
			},
		},
		&v3.GlobalAlertTemplate{
			TypeMeta: metav1.TypeMeta{
				Kind:       "GlobalAlertTemplate",
				APIVersion: "projectcalico.org/v3",
			},
			ObjectMeta: metav1.ObjectMeta{
				Name: "network.lateral.originate",
			},
			Spec: v3.GlobalAlertSpec{
				Description: "Alerts when pods with a specific label (e.g. app=monitor) initiate connections to other workloads within the cluster",
				Summary:     "[flows] [lateral movement] ${source_namespace}/${source_name_aggr} with label app=monitor initiated connection",
				Severity:    100,
				Period:      &metav1.Duration{Duration: 10 * time.Minute},
				Lookback:    &metav1.Duration{Duration: 10 * time.Minute},
				DataSet:     "flows",
				Query:       "'source_labels.labels'='app=monitor' AND proto=tcp AND action=allow AND reporter=src AND NOT dest_name_aggr='metadata-api' AND NOT dest_name_aggr='pub' AND NOT dest_name_aggr='kse.kubernetes'",
				AggregateBy: []string{"source_namespace", "source_name_aggr"},
				Field:       "num_flows",
				Metric:      "sum",
				Condition:   "gt",
				Threshold:   0,
			},
		},
		&v3.GlobalAlertTemplate{
			TypeMeta: metav1.TypeMeta{
				Kind:       "GlobalAlertTemplate",
				APIVersion: "projectcalico.org/v3",
			},
			ObjectMeta: metav1.ObjectMeta{
				Name: "dns.servfail",
			},
			Spec: v3.GlobalAlertSpec{
				Description: "Alerts when SERVFAIL response code is detected",
				Summary:     "[dns] SERVFAIL response detected for ${client_namespace}/${client_name_aggr}",
				Severity:    100,
				Period:      &metav1.Duration{Duration: 10 * time.Minute},
				Lookback:    &metav1.Duration{Duration: 10 * time.Minute},
				DataSet:     "dns",
				Query:       "rcode='SERVFAIL'",
				AggregateBy: []string{"client_namespace", "client_name_aggr", "qname"},
				Metric:      "count",
				Condition:   "gt",
				Threshold:   0,
			},
		},
		&v3.GlobalAlertTemplate{
			TypeMeta: metav1.TypeMeta{
				Kind:       "GlobalAlertTemplate",
				APIVersion: "projectcalico.org/v3",
			},
			ObjectMeta: metav1.ObjectMeta{
				Name: "dns.dos",
			},
			Spec: v3.GlobalAlertSpec{
				Description: "Alerts when DNS DOS attempt is detected",
				Summary:     "[dns] DOS attempt detected by ${client_namespace}/${client_name_aggr}",
				Severity:    100,
				Period:      &metav1.Duration{Duration: 10 * time.Minute},
				Lookback:    &metav1.Duration{Duration: 10 * time.Minute},
				DataSet:     "dns",
				Query:       "",
				AggregateBy: []string{"client_namespace", "client_name_aggr"},
				Metric:      "count",
				Condition:   "gt",
				Threshold:   50000,
			},
		},
	}

	return globalAlertTemplates
}

func (c *intrusionDetectionComponent) intrusionDetectionAnnotations() map[string]string {
	return c.cfg.TrustedCertBundle.HashAnnotations()
}

func (c *intrusionDetectionComponent) intrusionDetectionControllerCalicoSystemPolicy() *v3.NetworkPolicy {
	helper := networkpolicy.Helper(c.cfg.Tenant.MultiTenant(), c.cfg.Namespace)

	egressRules := []v3.Rule{
		// Block any link local IPs, e.g. cloud metadata, which are often targets of server-side request forgery (SSRF) attacks
		{
			Action:   v3.Deny,
			Protocol: &networkpolicy.TCPProtocol,
			Destination: v3.EntityRule{
				Nets: []string{"169.254.0.0/16"},
			},
		},
		{
			Action:   v3.Deny,
			Protocol: &networkpolicy.TCPProtocol,
			Destination: v3.EntityRule{
				Nets: []string{"fe80::/10"},
			},
		},
	}
	egressRules = networkpolicy.AppendDNSEgressRules(egressRules, c.cfg.OpenShift)
	if c.cfg.ManagedCluster {
		egressRules = append(egressRules, v3.Rule{
			Action:      v3.Allow,
			Protocol:    &networkpolicy.TCPProtocol,
			Destination: GuardianEntityRule,
		})
	} else {
		egressRules = append(egressRules, v3.Rule{
			Action:      v3.Allow,
			Protocol:    &networkpolicy.TCPProtocol,
			Destination: helper.LinseedEntityRule(),
		})
		if c.cfg.ManagementCluster {
			egressRules = append(egressRules, v3.Rule{
				Action:      v3.Allow,
				Protocol:    &networkpolicy.TCPProtocol,
				Destination: helper.ManagerEntityRule(),
			})
		}
	}
	egressRules = append(egressRules, []v3.Rule{
		{
			Action:      v3.Allow,
			Protocol:    &networkpolicy.TCPProtocol,
			Destination: networkpolicy.KubeAPIServerEntityRule,
		},
		{
			// Pass to subsequent tiers for further enforcement
			Action: v3.Pass,
		},
	}...)

	return &v3.NetworkPolicy{
		TypeMeta: metav1.TypeMeta{Kind: "NetworkPolicy", APIVersion: "projectcalico.org/v3"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      IntrusionDetectionControllerPolicyName,
			Namespace: c.cfg.Namespace,
		},
		Spec: v3.NetworkPolicySpec{
			Order:    &networkpolicy.HighPrecedenceOrder,
			Tier:     networkpolicy.CalicoTierName,
			Selector: networkpolicy.KubernetesAppSelector(IntrusionDetectionControllerName),
			Types:    []v3.PolicyType{v3.PolicyTypeIngress, v3.PolicyTypeEgress},
			Ingress: []v3.Rule{
				{
					// Intrusion detection controller doesn't listen on any external ports
					Action: v3.Deny,
				},
			},
			Egress: egressRules,
		},
	}
}

func (c *intrusionDetectionComponent) intrusionDetectionElasticsearchCalicoSystemPolicy() *v3.NetworkPolicy {
	return &v3.NetworkPolicy{
		TypeMeta: metav1.TypeMeta{Kind: "NetworkPolicy", APIVersion: "projectcalico.org/v3"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      IntrusionDetectionInstallerPolicyName,
			Namespace: c.cfg.Namespace,
		},
	}
}

// adComponentsToDelete returns a list of objects to delete. Anomaly detection used to be installed here,
// but has since been removed. This function is kept around to clean up any old objects that may be left.
func (c *intrusionDetectionComponent) adComponentsToDelete() []client.Object {
	objs := []client.Object{
		&corev1.ServiceAccount{
			TypeMeta: metav1.TypeMeta{Kind: "ServiceAccount", APIVersion: "v1"},
			ObjectMeta: metav1.ObjectMeta{
				Name:      ADAPIObjectName,
				Namespace: IntrusionDetectionNamespace,
			},
		},

		&rbacv1.ClusterRole{
			TypeMeta: metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"},
			ObjectMeta: metav1.ObjectMeta{
				Name: ADAPIObjectName,
			},
		},

		&rbacv1.ClusterRoleBinding{
			TypeMeta: metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"},
			ObjectMeta: metav1.ObjectMeta{
				Name: ADAPIObjectName,
			},
		},

		&corev1.Service{
			TypeMeta: metav1.TypeMeta{Kind: "Service", APIVersion: "v1"},
			ObjectMeta: metav1.ObjectMeta{
				Name:      ADAPIObjectName,
				Namespace: IntrusionDetectionNamespace,
			},
		},

		&corev1.PersistentVolumeClaim{
			TypeMeta: metav1.TypeMeta{
				Kind:       "PersistentVolumeClaim",
				APIVersion: "v1",
			},
			ObjectMeta: metav1.ObjectMeta{
				Name:      ADPersistentVolumeClaimName,
				Namespace: IntrusionDetectionNamespace,
			},
		},

		&appsv1.Deployment{
			TypeMeta: metav1.TypeMeta{Kind: "Deployment", APIVersion: "apps/v1"},
			ObjectMeta: metav1.ObjectMeta{
				Name:      ADAPIObjectName,
				Namespace: IntrusionDetectionNamespace,
			},
		},

		&corev1.ServiceAccount{
			TypeMeta: metav1.TypeMeta{Kind: "ServiceAccount", APIVersion: "v1"},
			ObjectMeta: metav1.ObjectMeta{
				Name:      adDetectorName,
				Namespace: IntrusionDetectionNamespace,
			},
		},

		&corev1.Secret{
			TypeMeta: metav1.TypeMeta{Kind: "Secret", APIVersion: "v1"},
			ObjectMeta: metav1.ObjectMeta{
				Name:      adDetectorName,
				Namespace: IntrusionDetectionNamespace,
			},
		},

		&rbacv1.Role{
			TypeMeta: metav1.TypeMeta{Kind: "Role", APIVersion: "rbac.authorization.k8s.io/v1"},
			ObjectMeta: metav1.ObjectMeta{
				Name:      adDetectorName,
				Namespace: IntrusionDetectionNamespace,
			},
		},

		&rbacv1.ClusterRole{
			TypeMeta: metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"},
			ObjectMeta: metav1.ObjectMeta{
				Name: adDetectorName,
			},
		},

		&rbacv1.RoleBinding{
			TypeMeta: metav1.TypeMeta{Kind: "RoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"},
			ObjectMeta: metav1.ObjectMeta{
				Name:      adDetectorName,
				Namespace: IntrusionDetectionNamespace,
			},
		},

		&rbacv1.ClusterRoleBinding{
			TypeMeta: metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"},
			ObjectMeta: metav1.ObjectMeta{
				Name: adDetectorName,
			},
		},

		&v3.NetworkPolicy{
			TypeMeta: metav1.TypeMeta{Kind: "NetworkPolicy", APIVersion: "projectcalico.org/v3"},
			ObjectMeta: metav1.ObjectMeta{
				Name:      ADAPIPolicyName,
				Namespace: IntrusionDetectionNamespace,
			},
		},

		&v3.NetworkPolicy{
			TypeMeta: metav1.TypeMeta{Kind: "NetworkPolicy", APIVersion: "projectcalico.org/v3"},
			ObjectMeta: metav1.ObjectMeta{
				Name:      ADDetectorPolicyName,
				Namespace: IntrusionDetectionNamespace,
			},
		},

		&corev1.PodTemplate{
			TypeMeta: metav1.TypeMeta{
				Kind:       "PodTemplate",
				APIVersion: "v1",
			},
			ObjectMeta: metav1.ObjectMeta{
				Namespace: IntrusionDetectionNamespace,
				Name:      ADJobPodTemplateBaseName + ".training",
			},
		},

		&corev1.PodTemplate{
			TypeMeta: metav1.TypeMeta{
				Kind:       "PodTemplate",
				APIVersion: "v1",
			},
			ObjectMeta: metav1.ObjectMeta{
				Namespace: IntrusionDetectionNamespace,
				Name:      ADJobPodTemplateBaseName + ".detection",
			},
		},
	}

	adAlgorithms := []string{
		"dga",
		"http-connection-spike",
		"http-response-codes",
		"http-verbs",
		"port-scan",
		"generic-dns",
		"generic-flows",
		"multivariable-flow",
		"generic-l7",
		"dns-latency",
		"dns-tunnel",
		"l7-bytes",
		"l7-latency",
		"bytes-in",
		"bytes-out",
		"process-bytes",
		"process-restarts",
	}

	for _, alg := range adAlgorithms {
		objs = append(objs,
			&v3.GlobalAlertTemplate{
				TypeMeta: metav1.TypeMeta{
					Kind:       "GlobalAlertTemplate",
					APIVersion: "projectcalico.org/v3",
				},
				ObjectMeta: metav1.ObjectMeta{
					Name: adDetectorPrefixName + alg,
				},
			},
			&v3.GlobalAlert{
				TypeMeta: metav1.TypeMeta{
					Kind:       "GlobalAlert",
					APIVersion: "projectcalico.org/v3",
				},
				ObjectMeta: metav1.ObjectMeta{
					Name: adDetectorPrefixName + alg,
				},
			},
		)
	}

	return objs
}

// instrusionDetectionPSPClusterRole returns metadata for the legacy PSP cluster role. This is no longer installed, and this function
// exists solely to remove it from the cluster if it exists.
func (c *intrusionDetectionComponent) intrusionDetectionPSPClusterRole() *rbacv1.ClusterRole {
	return &rbacv1.ClusterRole{
		TypeMeta:   metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{Name: "intrusion-detection-psp"},
	}
}

// intrusionDetectionPSPClusterRoleBinding returns metadata for the legacy PSP cluster role binding. This is no longer installed, and this function
// exists solely to remove it from the cluster if it exists.
func (c *intrusionDetectionComponent) intrusionDetectionPSPClusterRoleBinding() *rbacv1.ClusterRoleBinding {
	return &rbacv1.ClusterRoleBinding{
		TypeMeta:   metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{Name: "intrusion-detection-psp"},
	}
}
