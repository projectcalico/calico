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
	"slices"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	policyv1 "k8s.io/api/policy/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"sigs.k8s.io/controller-runtime/pkg/client"

	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/components"
	"github.com/tigera/operator/pkg/controller/k8sapi"
	"github.com/tigera/operator/pkg/controller/migration"
	rcomp "github.com/tigera/operator/pkg/render/common/components"
	rmeta "github.com/tigera/operator/pkg/render/common/meta"
	"github.com/tigera/operator/pkg/render/common/networkpolicy"
	"github.com/tigera/operator/pkg/render/common/securitycontext"
	"github.com/tigera/operator/pkg/render/common/securitycontextconstraints"
	"github.com/tigera/operator/pkg/tls/certificatemanagement"
)

const (
	TyphaServiceName              = "calico-typha"
	TyphaPortName                 = "calico-typha"
	TyphaK8sAppName               = "calico-typha"
	TyphaServiceAccountName       = "calico-typha"
	AppLabelName                  = "k8s-app"
	TyphaPort               int32 = 5473
	TyphaMetricsName              = "calico-typha-metrics"

	TyphaContainerName = "calico-typha"

	TyphaClusterRoleName = "calico-typha"

	TyphaNonClusterHostSuffix            = "-noncluster-host"
	TyphaNonClusterHostNetworkPolicyName = networkpolicy.CalicoComponentPolicyPrefix + "typha-noncluster-host-access"

	defaultTyphaTerminationGracePeriod = 300
	shutdownTimeoutEnvVar              = "TYPHA_SHUTDOWNTIMEOUTSECS"
)

var (
	TyphaTLSSecretName               = "typha-certs"
	TyphaTLSSecretNameNonClusterHost = TyphaTLSSecretName + TyphaNonClusterHostSuffix

	TyphaCAConfigMapName = "typha-ca"
	TyphaCABundleName    = "caBundle"
)

// TyphaConfiguration is the public API used to provide information to the render code to
// generate Kubernetes objects for installing calico/typha on a cluster.
type TyphaConfiguration struct {
	K8sServiceEp k8sapi.ServiceEndpoint

	// K8sServiceEpPodNetwork is used for pod-networked Typha (i.e. the non-cluster-host
	// deployment), where K8sServiceEp may be unreachable from pods.
	K8sServiceEpPodNetwork k8sapi.ServiceEndpoint

	Installation      *operatorv1.InstallationSpec
	TLS               *TyphaNodeTLS
	MigrateNamespaces bool
	ClusterDomain     string
	NonClusterHost    *operatorv1.NonClusterHost

	// The health port that Felix is bound to. We configure Typha to bind to the port
	// that is one less.
	FelixHealthPort int
}

// Typha creates the typha daemonset and other resources for the daemonset to operate normally.
func Typha(cfg *TyphaConfiguration) Component {
	return &typhaComponent{cfg: cfg}
}

type typhaComponent struct {
	// Given configuration.
	cfg *TyphaConfiguration

	// Generated internal config, built from the given configuration.
	calicoImage string
}

func (c *typhaComponent) ResolveImages(is *operatorv1.ImageSet) error {
	reg := c.cfg.Installation.Registry
	path := c.cfg.Installation.ImagePath
	prefix := c.cfg.Installation.ImagePrefix
	var err error
	c.calicoImage, err = components.GetReference(components.CombinedCalicoImage(c.cfg.Installation), reg, path, prefix, is)
	return err
}

func (c *typhaComponent) TyphaConfig() *TyphaConfiguration {
	return c.cfg
}

func (c *typhaComponent) SupportedOSType() rmeta.OSType {
	return rmeta.OSTypeLinux
}

func (c *typhaComponent) Objects() ([]client.Object, []client.Object) {
	pdb := c.typhaPodDisruptionBudget()
	if overrides := c.cfg.Installation.TyphaPodDisruptionBudget; overrides != nil {
		rcomp.ApplyPodDisruptionBudgetOverrides(pdb, overrides)
	}
	objs := []client.Object{
		c.typhaServiceAccount(),
		c.typhaRole(),
		c.typhaRoleBinding(),
		pdb,
	}
	objs = append(objs, c.typhaServices()...)

	// Add deployment last, as it may depend on the creation of previous objects in the list.
	objs = append(objs, c.typhaDeployment()...)
	if c.cfg.Installation.TyphaMetricsPort != nil {
		objs = append(objs, c.typhaPrometheusService())
	}

	return objs, nil
}

func NewTyphaNonClusterHostPolicy(cfg *TyphaConfiguration) Component {
	return NewPassthrough(
		[]client.Object{typhaNonClusterHostCalicoSystemPolicy(cfg)},
		[]client.Object{
			// allow-tigera Tier was renamed to calico-system
			networkpolicy.DeprecatedAllowTigeraNetworkPolicyObject("typha-noncluster-host-access", common.CalicoNamespace),
		},
	)
}

func (c *typhaComponent) typhaPodDisruptionBudget() *policyv1.PodDisruptionBudget {
	maxUnavailable := intstr.FromInt(1)
	return &policyv1.PodDisruptionBudget{
		TypeMeta: metav1.TypeMeta{Kind: "PodDisruptionBudget", APIVersion: "policy/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      common.TyphaDeploymentName,
			Namespace: common.CalicoNamespace,
		},
		Spec: policyv1.PodDisruptionBudgetSpec{
			MaxUnavailable: &maxUnavailable,
			Selector: &metav1.LabelSelector{
				MatchLabels: map[string]string{
					AppLabelName: TyphaK8sAppName,
				},
			},
		},
	}
}

func (c *typhaComponent) Ready() bool {
	return true
}

// typhaServiceAccount creates the typha's service account.
func (c *typhaComponent) typhaServiceAccount() *corev1.ServiceAccount {
	return &corev1.ServiceAccount{
		TypeMeta: metav1.TypeMeta{Kind: "ServiceAccount", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      TyphaServiceAccountName,
			Namespace: common.CalicoNamespace,
		},
	}
}

// typhaRoleBinding creates a clusterrolebinding giving the typha service account the required permissions to operate.
func (c *typhaComponent) typhaRoleBinding() *rbacv1.ClusterRoleBinding {
	return &rbacv1.ClusterRoleBinding{
		TypeMeta: metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:   "calico-typha",
			Labels: map[string]string{},
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "ClusterRole",
			Name:     "calico-typha",
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      "ServiceAccount",
				Name:      TyphaServiceAccountName,
				Namespace: common.CalicoNamespace,
			},
		},
	}
}

// typhaRole creates the clusterrole containing policy rules that allow the typha deployment to operate normally.
func (c *typhaComponent) typhaRole() *rbacv1.ClusterRole {
	role := &rbacv1.ClusterRole{
		TypeMeta: metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:   TyphaClusterRoleName,
			Labels: map[string]string{},
		},

		Rules: []rbacv1.PolicyRule{
			{
				// Calico uses endpoint slices for service-based network policy rules.
				APIGroups: []string{"discovery.k8s.io"},
				Resources: []string{"endpointslices"},
				Verbs:     []string{"list", "watch"},
			},
			{
				// The CNI plugin needs to get pods, nodes, namespaces.
				APIGroups: []string{""},
				Resources: []string{"pods", "nodes", "namespaces"},
				Verbs:     []string{"get"},
			},
			{
				// Used to discover Typha endpoints and service IPs for advertisement.
				APIGroups: []string{""},
				Resources: []string{"endpoints", "services"},
				Verbs:     []string{"watch", "list", "get"},
			},
			{
				// Some information is stored on the node status.
				APIGroups: []string{""},
				Resources: []string{"nodes/status"},
				Verbs:     []string{"patch", "update"},
			},
			{
				// For enforcing network policies.
				APIGroups: []string{"networking.k8s.io"},
				Resources: []string{"networkpolicies"},
				Verbs:     []string{"watch", "list"},
			},
			{
				// For enforcing k8s cluster network policies.
				APIGroups: []string{"policy.networking.k8s.io"},
				Resources: []string{
					"clusternetworkpolicies",
					"adminnetworkpolicies",
					"baselineadminnetworkpolicies",
				},
				Verbs: []string{"watch", "list"},
			},
			{
				// Metadata from these are used in conjunction with network policy.
				APIGroups: []string{""},
				Resources: []string{"pods", "namespaces", "serviceaccounts"},
				Verbs:     []string{"watch", "list"},
			},
			{
				// Calico patches the allocated IP onto the pod.
				APIGroups: []string{""},
				Resources: []string{"pods/status"},
				Verbs:     []string{"patch"},
			},
			{
				// For monitoring Calico-specific configuration.
				APIGroups: []string{"projectcalico.org", "crd.projectcalico.org"},
				Resources: []string{
					"bgpconfigurations",
					"bgppeers",
					"bgpfilters",
					"blockaffinities",
					"caliconodestatuses",
					"clusterinformations",
					"felixconfigurations",
					"globalnetworkpolicies",
					"stagedglobalnetworkpolicies",
					"networkpolicies",
					"stagedkubernetesnetworkpolicies",
					"stagednetworkpolicies",
					"globalnetworksets",
					"hostendpoints",
					"hostqospolicies",
					"ipamblocks",
					"ippools",
					"ipreservations",
					"networksets",
					"tiers",
				},
				Verbs: []string{"get", "list", "watch"},
			},
			{
				// For migration code in calico/node startup only. Remove when the migration
				// code is removed from node.
				APIGroups: []string{"projectcalico.org", "crd.projectcalico.org"},
				Resources: []string{
					"globalbgpconfigs",
					"globalfelixconfigs",
				},
				Verbs: []string{"get", "list", "watch"},
			},
			{
				// Calico creates some configuration on startup.
				APIGroups: []string{"projectcalico.org", "crd.projectcalico.org"},
				Resources: []string{
					"clusterinformations",
					"felixconfigurations",
					"ippools",
				},
				Verbs: []string{"create", "update"},
			},
			{
				// Calico creates some tiers on startup.
				APIGroups: []string{"projectcalico.org", "crd.projectcalico.org"},
				Resources: []string{
					"tiers",
				},
				Verbs: []string{"create"},
			},
			{
				// Calico monitors nodes for some networking configuration.
				APIGroups: []string{""},
				Resources: []string{"nodes"},
				Verbs:     []string{"get", "list", "watch"},
			},
			{
				// Most IPAM resources need full CRUD permissions so we can allocate and
				// release IP addresses for pods.
				APIGroups: []string{"projectcalico.org", "crd.projectcalico.org"},
				Resources: []string{
					"blockaffinities",
					"ipamblocks",
					"ipamhandles",
				},
				Verbs: []string{"get", "list", "create", "update", "delete"},
			},
			{
				// But, we only need to be able to query for IPAM config.
				APIGroups: []string{"projectcalico.org", "crd.projectcalico.org"},
				Resources: []string{"ipamconfigurations"},
				Verbs:     []string{"get"},
			},
			{
				// confd (and in some cases, felix) watches block affinities for route aggregation.
				APIGroups: []string{"projectcalico.org", "crd.projectcalico.org"},
				Resources: []string{"blockaffinities"},
				Verbs:     []string{"watch"},
			},
			{
				// For monitoring KubeVirt live migration.
				APIGroups: []string{"kubevirt.io"},
				Resources: []string{"virtualmachineinstancemigrations"},
				Verbs:     []string{"get", "list", "watch"},
			},
		},
	}
	if c.cfg.Installation.KubernetesProvider.IsOpenShift() {
		role.Rules = append(role.Rules, rbacv1.PolicyRule{
			APIGroups:     []string{"security.openshift.io"},
			Resources:     []string{"securitycontextconstraints"},
			Verbs:         []string{"use"},
			ResourceNames: []string{securitycontextconstraints.NonRootV2},
		})
	}
	return role
}

// typhaDeployment creates the typha deployment.
func (c *typhaComponent) typhaDeployment() []client.Object {
	// We set a fairly long grace period by default. Typha sheds load during the grace period rather than
	// disconnecting all clients at once.
	var terminationGracePeriod int64 = defaultTyphaTerminationGracePeriod
	var revisionHistoryLimit int32 = 2
	// Allowing 1 unavailable Typha by default ensures that we make progress in a cluster with constrained scheduling.
	maxUnavailable := intstr.FromInt(1)
	// Allowing 100% surge allows a complete replacement fleet of Typha instances to start during an upgrade. When
	// combined with Typha's graceful shutdown, we get nice emergent behavior:
	// - All up-level Typhas start if there's room available.
	// - Back-level Typhas shed load slowly over the termination grace period.
	// - Clients that are shed end up connecting to up-level Typhas (because all the back-level Typhas are marked
	//   as terminating once all the up-level Typhas are ready).  This tends to avoid bouncing a client multiple
	//   times during an upgrade.
	// - If there's any sort of version skew issue where a back-level client can't understand an up-level Typha,
	//   it'll go non-ready and Kubernetes will upgrade it.  This is rate limited by Typha's load-shedding rate,
	//   so we shouldn't get a "thundering herd".
	maxSurge := intstr.FromString("100%")

	typhaContainer := c.typhaContainer()

	annotations := c.cfg.TLS.TrustedBundle.HashAnnotations()
	annotations[c.cfg.TLS.TyphaSecret.HashAnnotationKey()] = c.cfg.TLS.TyphaSecret.HashAnnotationValue()
	var initContainers []corev1.Container
	if c.cfg.TLS.TyphaSecret.UseCertificateManagement() {
		initContainers = append(initContainers, c.cfg.TLS.TyphaSecret.InitContainer(common.CalicoNamespace, typhaContainer.SecurityContext))
	}

	// Include annotation for prometheus scraping configuration.
	if c.cfg.Installation.TyphaMetricsPort != nil {
		annotations["prometheus.io/scrape"] = "true"
		annotations["prometheus.io/port"] = fmt.Sprintf("%d", *c.cfg.Installation.TyphaMetricsPort)
	}

	// Allow tolerations to be overwritten by the end-user. By default Typha uses
	// the bootstrap toleration set: broad enough to schedule on otherwise tainted
	// nodes during install (before the CNI / cloud provider are ready), but narrow
	// enough that cordoned nodes are still avoided.
	tolerations := rmeta.TolerateBootstrap
	if len(c.cfg.Installation.ControlPlaneTolerations) != 0 {
		tolerations = c.cfg.Installation.ControlPlaneTolerations
	}
	if c.cfg.Installation.KubernetesProvider.IsGKE() {
		tolerations = append(tolerations, rmeta.TolerateGKEARM64NoSchedule)
	}

	deploy := &appsv1.Deployment{
		TypeMeta: metav1.TypeMeta{Kind: "Deployment", APIVersion: "apps/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      common.TyphaDeploymentName,
			Namespace: common.CalicoNamespace,
		},
		Spec: appsv1.DeploymentSpec{
			Strategy: appsv1.DeploymentStrategy{
				Type: appsv1.RollingUpdateDeploymentStrategyType,
				RollingUpdate: &appsv1.RollingUpdateDeployment{
					MaxUnavailable: &maxUnavailable,
					MaxSurge:       &maxSurge,
				},
			},
			RevisionHistoryLimit: &revisionHistoryLimit,
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Annotations: annotations,
				},
				Spec: corev1.PodSpec{
					Tolerations:                   tolerations,
					Affinity:                      c.affinity(),
					ImagePullSecrets:              c.cfg.Installation.ImagePullSecrets,
					ServiceAccountName:            TyphaServiceAccountName,
					TerminationGracePeriodSeconds: &terminationGracePeriod,
					HostNetwork:                   true,
					InitContainers:                initContainers,
					Containers:                    []corev1.Container{typhaContainer},
					Volumes:                       c.volumes(),
				},
			},
		},
	}
	SetClusterCriticalPod(&deploy.Spec.Template)
	if c.cfg.MigrateNamespaces {
		migration.SetTyphaAntiAffinity(deploy)
	}

	if overrides := c.cfg.Installation.TyphaDeployment; overrides != nil {
		rcomp.ApplyDeploymentOverrides(deploy, overrides)
	}

	// ApplyDeploymentOverrides patches some fields that have consistency requirements elsewhere in the spec.
	// fix up the other places.
	c.applyPostOverrideFixUps(deploy)

	if c.cfg.NonClusterHost != nil {
		// Create a separate deployment to handle non-cluster host requests.
		deployNonClusterHost := deploy.DeepCopy()
		deployNonClusterHost.Name += TyphaNonClusterHostSuffix
		// Replace Typha secret annotation for NonClusterHost deployment.
		delete(deployNonClusterHost.Spec.Template.Annotations, c.cfg.TLS.TyphaSecret.HashAnnotationKey())
		deployNonClusterHost.Spec.Template.Annotations[c.cfg.TLS.TyphaSecretNonClusterHost.HashAnnotationKey()] = c.cfg.TLS.TyphaSecretNonClusterHost.HashAnnotationValue()
		// Remove the affinity and use pod network
		deployNonClusterHost.Spec.Template.Spec.Affinity = nil
		deployNonClusterHost.Spec.Template.Spec.HostNetwork = false
		// Tune Typha container and volumes for NonClusterHost deployment.
		deployNonClusterHost.Spec.Template.Spec.Containers = []corev1.Container{c.typhaContainerNonClusterHost()}
		deployNonClusterHost.Spec.Template.Spec.Volumes = c.volumeNonClusterHost()
		return []client.Object{deploy, deployNonClusterHost}
	}

	return []client.Object{deploy}
}

func (c *typhaComponent) applyPostOverrideFixUps(d *appsv1.Deployment) {
	// The deployment overrides may update the termination grace period and typha needs to know what the grace
	// period is in order to calculate its shutdown disconnection rate.  Copy that over to an env var.
	terminationGracePeriod := *d.Spec.Template.Spec.TerminationGracePeriodSeconds
	for _, c := range d.Spec.Template.Spec.Containers {
		if c.Name != TyphaContainerName {
			continue
		}
		for i, e := range c.Env {
			if e.Name != shutdownTimeoutEnvVar {
				continue
			}
			c.Env[i].Value = fmt.Sprint(terminationGracePeriod)
			break
		}
		break
	}

	// If the termination grace period has been set to a very high value, make sure the Deployment's progress
	// deadline takes account of that.
	minProgressDeadline := int32(terminationGracePeriod * 120 / 100)
	if minProgressDeadline < 600 {
		// 600 is the Kubernetes default so let's not go below that.
		minProgressDeadline = 600
	}
	if d.Spec.ProgressDeadlineSeconds == nil || *d.Spec.ProgressDeadlineSeconds < minProgressDeadline {
		d.Spec.ProgressDeadlineSeconds = &minProgressDeadline
	}
}

// volumes creates the typha's volumes.
func (c *typhaComponent) volumes() []corev1.Volume {
	return []corev1.Volume{
		c.cfg.TLS.TrustedBundle.Volume(),
		c.cfg.TLS.TyphaSecret.Volume(),
	}
}

func (c *typhaComponent) volumeNonClusterHost() []corev1.Volume {
	return []corev1.Volume{
		c.cfg.TLS.TrustedBundle.Volume(),
		c.cfg.TLS.TyphaSecretNonClusterHost.Volume(),
	}
}

// typhaVolumeMounts creates the typha's volume mounts.
func (c *typhaComponent) typhaVolumeMounts() []corev1.VolumeMount {
	return append(
		c.cfg.TLS.TrustedBundle.VolumeMounts(c.SupportedOSType()),
		c.cfg.TLS.TyphaSecret.VolumeMount(c.SupportedOSType()),
	)
}

func (c *typhaComponent) typhaVolumeMountsNonClusterHost() []corev1.VolumeMount {
	return append(
		c.cfg.TLS.TrustedBundle.VolumeMounts(c.SupportedOSType()),
		c.cfg.TLS.TyphaSecretNonClusterHost.VolumeMount(c.SupportedOSType()),
	)
}

func (c *typhaComponent) typhaPorts() []corev1.ContainerPort {
	return []corev1.ContainerPort{
		{
			ContainerPort: TyphaPort,
			Name:          TyphaPortName,
			Protocol:      corev1.ProtocolTCP,
		},
	}
}

// typhaContainer creates the main typha container.
func (c *typhaComponent) typhaContainer() corev1.Container {
	lp, rp := c.livenessReadinessProbes("localhost")
	return corev1.Container{
		Name:            TyphaContainerName,
		Image:           c.calicoImage,
		Command:         []string{components.CalicoBinaryPath, "component", "typha"},
		Resources:       c.typhaResources(),
		Env:             c.typhaEnvVars(c.cfg.TLS.TyphaSecret),
		VolumeMounts:    c.typhaVolumeMounts(),
		Ports:           c.typhaPorts(),
		LivenessProbe:   lp,
		ReadinessProbe:  rp,
		SecurityContext: securitycontext.NewNonRootContext(),
	}
}

func (c *typhaComponent) typhaContainerNonClusterHost() corev1.Container {
	container := c.typhaContainer()
	container.Env = c.typhaEnvVarsNonClusterHost()
	container.VolumeMounts = c.typhaVolumeMountsNonClusterHost()
	container.LivenessProbe, container.ReadinessProbe = c.livenessReadinessProbes("")
	return container
}

// typhaResources creates the typha's resource requirements.
func (c *typhaComponent) typhaResources() corev1.ResourceRequirements {
	return rmeta.GetResourceRequirements(c.cfg.Installation, operatorv1.ComponentNameTypha)
}

// typhaEnvVars creates the typha's envvars.
func (c *typhaComponent) typhaEnvVars(typhaSecret certificatemanagement.KeyPairInterface) []corev1.EnvVar {
	typhaEnv := []corev1.EnvVar{
		{Name: "TYPHA_LOGSEVERITYSCREEN", Value: "info"},
		{Name: "TYPHA_LOGFILEPATH", Value: "none"},
		{Name: "TYPHA_LOGSEVERITYSYS", Value: "none"},
		{Name: "TYPHA_CONNECTIONREBALANCINGMODE", Value: "kubernetes"},
		{Name: "TYPHA_DATASTORETYPE", Value: "kubernetes"},
		{Name: "TYPHA_HEALTHENABLED", Value: "true"},
		{Name: "TYPHA_HEALTHPORT", Value: fmt.Sprintf("%d", typhaHealthPort(c.cfg))},
		{Name: "TYPHA_K8SNAMESPACE", Value: common.CalicoNamespace},
		{Name: "TYPHA_CAFILE", Value: c.cfg.TLS.TrustedBundle.MountPath()},
		{Name: "TYPHA_SERVERCERTFILE", Value: typhaSecret.VolumeMountCertificateFilePath()},
		{Name: "TYPHA_SERVERKEYFILE", Value: typhaSecret.VolumeMountKeyFilePath()},
		{Name: shutdownTimeoutEnvVar, Value: fmt.Sprint(defaultTyphaTerminationGracePeriod)}, // May get overridden later.
	}
	// We need at least the CN or URISAN set, we depend on the validation
	// done by the core_controller that the Secret will have one.
	if c.cfg.TLS.TyphaCommonName != "" {
		typhaEnv = append(typhaEnv, corev1.EnvVar{Name: "TYPHA_CLIENTCN", Value: c.cfg.TLS.NodeCommonName})
	}
	if c.cfg.TLS.TyphaURISAN != "" {
		typhaEnv = append(typhaEnv, corev1.EnvVar{Name: "TYPHA_CLIENTURISAN", Value: c.cfg.TLS.NodeURISAN})
	}

	switch c.cfg.Installation.CNI.Type {
	case operatorv1.PluginAmazonVPC:
		typhaEnv = append(typhaEnv, corev1.EnvVar{Name: "FELIX_INTERFACEPREFIX", Value: "eni"})
	case operatorv1.PluginGKE:
		typhaEnv = append(typhaEnv, corev1.EnvVar{Name: "FELIX_INTERFACEPREFIX", Value: "gke"})
	case operatorv1.PluginAzureVNET:
		typhaEnv = append(typhaEnv, corev1.EnvVar{Name: "FELIX_INTERFACEPREFIX", Value: "azv"})
	}

	// If host-local IPAM is in use, we need to configure typha to use the Kubernetes pod CIDR.
	cni := c.cfg.Installation.CNI
	if cni != nil && cni.IPAM != nil && cni.IPAM.Type == operatorv1.IPAMPluginHostLocal {
		typhaEnv = append(typhaEnv, corev1.EnvVar{
			Name:  "USE_POD_CIDR",
			Value: "true",
		})
	}

	typhaEnv = append(typhaEnv, c.cfg.K8sServiceEp.EnvVars()...)

	if c.cfg.Installation.TyphaMetricsPort != nil {
		// If a typha metrics port was given, then enable typha prometheus metrics and set the port.
		typhaEnv = append(typhaEnv,
			corev1.EnvVar{Name: "TYPHA_PROMETHEUSMETRICSENABLED", Value: "true"},
			corev1.EnvVar{Name: "TYPHA_PROMETHEUSMETRICSPORT", Value: fmt.Sprintf("%d", *c.cfg.Installation.TyphaMetricsPort)},
		)
	}

	return typhaEnv
}

func replaceOrAppendEnvVar(envVars []corev1.EnvVar, key, value string) []corev1.EnvVar {
	found := false
	for i := range envVars {
		if envVars[i].Name == key {
			envVars[i].Value = value
			found = true
		}
	}

	if !found && value != "" {
		envVars = append(envVars, corev1.EnvVar{Name: key, Value: value})
	}
	return envVars
}

func (c *typhaComponent) typhaEnvVarsNonClusterHost() []corev1.EnvVar {
	// Update Typha client common name or URISAN for non-cluster hosts.
	// At least one of TYPHA_CLIENTCN or TYPHA_CLIENTURISAN must be set.
	envVars := c.typhaEnvVars(c.cfg.TLS.TyphaSecretNonClusterHost)
	envVars = replaceOrAppendEnvVar(envVars, "TYPHA_CLIENTCN", c.cfg.TLS.NodeNonClusterHostCommonName)
	envVars = replaceOrAppendEnvVar(envVars, "TYPHA_CLIENTURISAN", c.cfg.TLS.NodeNonClusterHostURISAN)

	// NCH Typha runs pod-networked, so the host-network apiserver endpoint
	// (e.g. MKE's proxy.local) may not be reachable. Strip the inherited env
	// vars so we fall back to the default kubernetes Service that kubelet
	// injects into every pod, then re-add a pod-network endpoint if one was
	// configured explicitly.
	envVars = slices.DeleteFunc(envVars, func(e corev1.EnvVar) bool {
		return e.Name == "KUBERNETES_SERVICE_HOST" || e.Name == "KUBERNETES_SERVICE_PORT"
	})
	envVars = append(envVars, c.cfg.K8sServiceEpPodNetwork.EnvVars()...)

	// Tell the health aggregator to listen on all interfaces.
	envVars = append(envVars, corev1.EnvVar{Name: "TYPHA_HEALTHHOST", Value: "0.0.0.0"})
	return envVars
}

// typhaHealthPort returns the liveness and readiness port to use for typha.
func typhaHealthPort(cfg *TyphaConfiguration) int {
	// We use the felix health port, minus one, to determine the port to use for Typha.
	// This isn't ideal, but allows for some control of the typha port.
	return cfg.FelixHealthPort - 1
}

// livenessReadinessProbes creates the typha's liveness and readiness probes.
func (c *typhaComponent) livenessReadinessProbes(host string) (*corev1.Probe, *corev1.Probe) {
	port := intstr.FromInt(typhaHealthPort(c.cfg))
	lp := &corev1.Probe{
		ProbeHandler: corev1.ProbeHandler{
			HTTPGet: &corev1.HTTPGetAction{
				Host: host,
				Path: "/liveness",
				Port: port,
			},
		},
		TimeoutSeconds: 10,
	}
	rp := &corev1.Probe{
		ProbeHandler: corev1.ProbeHandler{
			HTTPGet: &corev1.HTTPGetAction{
				Host: host,
				Path: "/readiness",
				Port: port,
			},
		},
		TimeoutSeconds: 10,
	}
	return lp, rp
}

func (c *typhaComponent) typhaServices() []client.Object {
	svc := &corev1.Service{
		TypeMeta: metav1.TypeMeta{Kind: "Service", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      TyphaServiceName,
			Namespace: common.CalicoNamespace,
			Labels: map[string]string{
				AppLabelName: TyphaK8sAppName,
			},
		},
		Spec: corev1.ServiceSpec{
			Ports: []corev1.ServicePort{
				{
					Port:       TyphaPort,
					Protocol:   corev1.ProtocolTCP,
					TargetPort: intstr.FromString(TyphaPortName),
					Name:       TyphaPortName,
				},
			},
			Selector: map[string]string{
				AppLabelName: TyphaK8sAppName,
			},
		},
	}

	if c.cfg.NonClusterHost != nil {
		svcNonClusterHost := svc.DeepCopy()
		svcNonClusterHost.Name += TyphaNonClusterHostSuffix
		svcNonClusterHost.Labels[AppLabelName] += TyphaNonClusterHostSuffix
		svcNonClusterHost.Spec.Selector[AppLabelName] += TyphaNonClusterHostSuffix
		return []client.Object{svc, svcNonClusterHost}
	}
	return []client.Object{svc}
}

// affinity sets the user-specified typha affinity if specified.
func (c *typhaComponent) affinity() (aff *corev1.Affinity) {
	if c.cfg.Installation.TyphaAffinity != nil && c.cfg.Installation.TyphaAffinity.NodeAffinity != nil {
		// this ensures we return nil if no affinity is specified.
		if c.cfg.Installation.TyphaAffinity.NodeAffinity.RequiredDuringSchedulingIgnoredDuringExecution == nil && len(c.cfg.Installation.TyphaAffinity.NodeAffinity.PreferredDuringSchedulingIgnoredDuringExecution) == 0 {
			return nil
		}
		aff = &corev1.Affinity{
			NodeAffinity: &corev1.NodeAffinity{
				RequiredDuringSchedulingIgnoredDuringExecution:  c.cfg.Installation.TyphaAffinity.NodeAffinity.RequiredDuringSchedulingIgnoredDuringExecution,
				PreferredDuringSchedulingIgnoredDuringExecution: c.cfg.Installation.TyphaAffinity.NodeAffinity.PreferredDuringSchedulingIgnoredDuringExecution,
			},
		}

	}
	if aff == nil {
		aff = &corev1.Affinity{}
	}
	aff.PodAntiAffinity = &corev1.PodAntiAffinity{
		PreferredDuringSchedulingIgnoredDuringExecution: []corev1.WeightedPodAffinityTerm{
			{
				Weight: 1,
				PodAffinityTerm: corev1.PodAffinityTerm{
					LabelSelector: &metav1.LabelSelector{
						MatchExpressions: []metav1.LabelSelectorRequirement{
							{
								Key:      AppLabelName,
								Operator: metav1.LabelSelectorOpIn,
								Values:   []string{TyphaK8sAppName},
							},
						},
					},
					TopologyKey: "topology.kubernetes.io/zone",
				},
			},
		},
	}
	return aff
}

// typhaPrometheusService service for scraping typha metrics.
func (c *typhaComponent) typhaPrometheusService() *corev1.Service {
	port := c.cfg.Installation.TyphaMetricsPort
	return &corev1.Service{
		TypeMeta: metav1.TypeMeta{Kind: "Service", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      TyphaMetricsName,
			Namespace: common.CalicoNamespace,
			Labels: map[string]string{
				AppLabelName: TyphaMetricsName,
			},
		},
		Spec: corev1.ServiceSpec{
			Ports: []corev1.ServicePort{
				{
					Port:       *port,
					Protocol:   corev1.ProtocolTCP,
					TargetPort: intstr.FromInt(int(*port)),
					Name:       TyphaMetricsName,
				},
			},
			Selector: map[string]string{
				AppLabelName: TyphaK8sAppName,
			},
		},
	}
}

func typhaNonClusterHostCalicoSystemPolicy(cfg *TyphaConfiguration) *v3.NetworkPolicy {
	egressRules := []v3.Rule{}
	egressRules = networkpolicy.AppendDNSEgressRules(egressRules, cfg.Installation.KubernetesProvider.IsOpenShift())
	egressRules = append(egressRules, []v3.Rule{
		{
			Action:      v3.Allow,
			Protocol:    &networkpolicy.TCPProtocol,
			Destination: networkpolicy.KubeAPIServerEntityRule,
		},
	}...)

	ingressRules := []v3.Rule{
		{
			Action:   v3.Allow,
			Protocol: &networkpolicy.TCPProtocol,
			Destination: v3.EntityRule{
				Ports: networkpolicy.Ports(uint16(TyphaPort), uint16(typhaHealthPort(cfg))),
			},
		},
	}

	if r, err := cfg.K8sServiceEp.DestinationEntityRule(); r != nil && err == nil {
		egressRules = append(egressRules, v3.Rule{
			Action:      v3.Allow,
			Protocol:    &networkpolicy.TCPProtocol,
			Destination: *r,
		})
	}

	return &v3.NetworkPolicy{
		TypeMeta: metav1.TypeMeta{Kind: "NetworkPolicy", APIVersion: "projectcalico.org/v3"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      TyphaNonClusterHostNetworkPolicyName,
			Namespace: common.CalicoNamespace,
		},
		Spec: v3.NetworkPolicySpec{
			Order:    &networkpolicy.HighPrecedenceOrder,
			Tier:     networkpolicy.CalicoTierName,
			Selector: networkpolicy.KubernetesAppSelector(common.TyphaDeploymentName + TyphaNonClusterHostSuffix),
			Types:    []v3.PolicyType{v3.PolicyTypeEgress, v3.PolicyTypeIngress},
			Egress:   egressRules,
			Ingress:  ingressRules,
		},
	}
}
