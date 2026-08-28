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

package kubecontrollers

import (
	"fmt"
	"slices"
	"strconv"
	"strings"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"

	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/components"
	"github.com/tigera/operator/pkg/controller/k8sapi"
	"github.com/tigera/operator/pkg/render"
	rcomp "github.com/tigera/operator/pkg/render/common/components"
	rmeta "github.com/tigera/operator/pkg/render/common/meta"
	"github.com/tigera/operator/pkg/render/common/networkpolicy"
	"github.com/tigera/operator/pkg/render/common/secret"
	"github.com/tigera/operator/pkg/render/common/securitycontext"
	"github.com/tigera/operator/pkg/render/common/securitycontextconstraints"
	"github.com/tigera/operator/pkg/tls/certificatemanagement"
)

const (
	KubeController                  = "calico-kube-controllers"
	KubeControllerServiceAccount    = "calico-kube-controllers"
	KubeControllerRole              = "calico-kube-controllers"
	KubeControllerRoleBinding       = "calico-kube-controllers"
	KubeControllerMetrics           = "calico-kube-controllers-metrics"
	KubeControllerNetworkPolicyName = networkpolicy.CalicoComponentPolicyPrefix + "kube-controller-access"

	// ManagedClustersWatchRoleBindingName binds kube-controllers to the managed-cluster
	// watch ClusterRole. Used by both calico-kube-controllers (in a management cluster)
	// and the enterprise es-calico-kube-controllers, so the binding stays generic here.
	ManagedClustersWatchRoleBindingName = "es-calico-kube-controllers-managed-cluster-watch"

	KubeControllerPrometheusTLSSecret = "calico-kube-controllers-metrics-tls"

	// KubeControllersHealthPort is the port the kube-controllers HealthAggregator listens on when run from the
	// combined calico binary. The legacy per-component image uses file-based health checks instead.
	KubeControllersHealthPort = 9440
)

type KubeControllersConfiguration struct {
	K8sServiceEp           k8sapi.ServiceEndpoint
	K8sServiceEpPodNetwork k8sapi.ServiceEndpoint

	Installation   *operatorv1.InstallationSpec
	Authentication *operatorv1.Authentication

	// ManagedClusterWatchBinding binds kube-controllers to the managed-cluster watch
	// ClusterRole. The assemblers set it; multi-cluster management is not a core feature.
	ManagedClusterWatchBinding bool

	ClusterDomain string
	MetricsPort   int

	// For details on why this is needed see 'Node and Installation finalizer' in the core_controller.
	Terminating bool

	// Secrets - provided by the caller. Used to generate secrets in the destination
	// namespace to be returned by the rendered. Expected that the calling code
	// take care to pass the same secret on each reconcile where possible.
	KubeControllersGatewaySecret *corev1.Secret
	TrustedBundle                certificatemanagement.TrustedBundleRO

	// ImageOverrides lets a variant swap the kube-controllers image. The controller
	// wires in the operator's image overrides; nil resolves to the core image.
	// Image overrides what kube-controllers runs, or nil for the variant's calico image.
	Image *components.Component

	// Namespace to be installed into.
	Namespace string

	// List of namespaces that are running a kube-controllers instance that need a cluster role binding.
	BindingNamespaces []string

	// The fields below parameterize the generic kube-controllers component. The
	// variant assemblers (NewCalicoKubeControllers, the enterprise es builder)
	// fill them; the component renders them without any variant or component-name
	// branching.

	// Name is the deployment / pod / container name (and the value the metrics
	// Service selects on).
	Name string
	// ConfigName is the KUBE_CONTROLLERS_CONFIG_NAME the binary reconciles.
	ConfigName string
	// RoleName / RoleBindingName / MetricsName name the ClusterRole, its binding,
	// and the Prometheus metrics Service.
	RoleName        string
	RoleBindingName string
	MetricsName     string
	// EnabledControllers is the ENABLED_CONTROLLERS list. The deployment is only
	// rendered when it is non-empty.
	EnabledControllers []string
	// Rules are the ClusterRole policy rules.
	Rules []rbacv1.PolicyRule
	// NetworkPolicy, when set, is rendered into the install namespace (and the
	// deprecated allow-tigera policy named DeprecatedNetworkPolicyName is deleted).
	NetworkPolicy               *v3.NetworkPolicy
	DeprecatedNetworkPolicyName string
	// ExtraEnv is appended to the deployment's container env.
	ExtraEnv []corev1.EnvVar
	// DisableConfigAPI sets DISABLE_KUBE_CONTROLLERS_CONFIG_API.
	DisableConfigAPI bool
}

// The calico-kube-controllers components expose an extension point. The
// es-calico-kube-controllers deployment shares the underlying type but not these
// wrappers, so a variant never sees it.
type (
	CalicoComponent interface {
		render.Component
		KubeControllersConfig() *KubeControllersConfiguration
	}

	CalicoPolicyComponent interface {
		render.Component
		KubeControllersPolicyConfig() *KubeControllersConfiguration
	}
)

// calicoKubeControllers marks the calico-kube-controllers deployment as extendable.
type calicoKubeControllers struct {
	render.Component

	cfg *KubeControllersConfiguration
}

func (c calicoKubeControllers) KubeControllersConfig() *KubeControllersConfiguration {
	return c.cfg
}

// calicoKubeControllersPolicy marks the calico-kube-controllers network policy as
// extendable.
type calicoKubeControllersPolicy struct {
	render.Component

	cfg *KubeControllersConfiguration
}

func (c calicoKubeControllersPolicy) KubeControllersPolicyConfig() *KubeControllersConfiguration {
	return c.cfg
}

func NewCalicoKubeControllersPolicy(cfg *KubeControllersConfiguration, defaultDeny *v3.NetworkPolicy) render.Component {
	toCreate := []client.Object{kubeControllersCalicoSystemPolicy(cfg)}

	if defaultDeny != nil {
		toCreate = append(toCreate, defaultDeny)
	}

	return calicoKubeControllersPolicy{
		Component: render.NewPassthrough(
			toCreate,
			[]client.Object{
				// allow-tigera Tier was renamed to calico-system
				networkpolicy.DeprecatedAllowTigeraNetworkPolicyObject("kube-controller-access", cfg.Namespace),
				networkpolicy.DeprecatedAllowTigeraNetworkPolicyObject("default-deny", common.CalicoNamespace),
			},
		),
		cfg: cfg,
	}
}

// NewKubeControllers builds a kube-controllers component from a fully-populated
// configuration. Callers (NewCalicoKubeControllers, the enterprise es-kube-controllers
// builder) fill the generic Name/Rules/EnabledControllers/ExtraEnv/NetworkPolicy fields;
// the component renders them with no variant branching.
func NewKubeControllers(cfg *KubeControllersConfiguration) render.Component {
	return &kubeControllersComponent{cfg: cfg}
}

// NewCalicoKubeControllers builds the calico-kube-controllers component. The base is
// pure OSS; a variant layers its additions on through the installation extension.
func NewCalicoKubeControllers(cfg *KubeControllersConfiguration) render.Component {
	cfg.Name = KubeController
	cfg.ConfigName = "default"
	cfg.RoleName = KubeControllerRole
	cfg.RoleBindingName = KubeControllerRoleBinding
	cfg.MetricsName = KubeControllerMetrics

	cfg.Rules = KubeControllersRoleCommonRules(cfg)
	cfg.EnabledControllers = []string{"node", "loadbalancer"}

	return calicoKubeControllers{Component: NewKubeControllers(cfg), cfg: cfg}
}

type kubeControllersComponent struct {
	// cfg is caller-supplied configuration for building kube-controllers Kubernetes resources.
	cfg *KubeControllersConfiguration

	// Internal state generated by the given configuration.
	calicoImage string
}

func (c *kubeControllersComponent) ResolveImages(is *operatorv1.ImageSet) error {
	var err error
	if c.cfg.Image != nil {
		in := c.cfg.Installation
		c.calicoImage, err = components.GetReference(*c.cfg.Image, in.Registry, in.ImagePath, in.ImagePrefix, is)
		return err
	}
	c.calicoImage, err = components.ReferenceFor(components.ImageKeyCalico, c.cfg.Installation, is)
	return err
}

func (c *kubeControllersComponent) SupportedOSType() rmeta.OSType {
	return rmeta.OSTypeLinux
}

func (c *kubeControllersComponent) Objects() ([]client.Object, []client.Object) {
	objectsToCreate := []client.Object{}
	objectsToDelete := []client.Object{}

	if c.cfg.NetworkPolicy != nil {
		objectsToCreate = append(objectsToCreate, c.cfg.NetworkPolicy)
		if c.cfg.DeprecatedNetworkPolicyName != "" {
			// allow-tigera Tier was renamed to calico-system
			objectsToDelete = append(objectsToDelete,
				networkpolicy.DeprecatedAllowTigeraNetworkPolicyObject(c.cfg.DeprecatedNetworkPolicyName, c.cfg.Namespace),
			)
		}
	}

	objectsToCreate = append(objectsToCreate,
		c.controllersServiceAccount(),
		c.controllersClusterRole(),
		c.controllersClusterRoleBinding(),
	)
	objectsToCreate = append(objectsToCreate, c.managedClusterRoleBindings()...)

	if len(c.cfg.EnabledControllers) > 0 {
		// There's something to run, so create the deployment.
		objectsToCreate = append(objectsToCreate, c.controllersDeployment())
	} else {
		// No controllers are enabled, so delete the deployment.
		objectsToDelete = append(objectsToDelete, c.controllersDeployment())
	}

	if c.cfg.Installation.KubernetesProvider.IsOpenShift() {
		objectsToCreate = append(objectsToCreate, c.controllersOCPFederationRoleBinding())
	}
	if c.cfg.KubeControllersGatewaySecret != nil {
		objectsToCreate = append(objectsToCreate, secret.ToRuntimeObjects(
			secret.CopyToNamespace(c.cfg.Namespace, c.cfg.KubeControllersGatewaySecret)...)...)
	}

	if c.cfg.MetricsPort != 0 {
		objectsToCreate = append(objectsToCreate, c.prometheusService())
	} else {
		objectsToDelete = append(objectsToDelete, c.prometheusService())
	}

	if c.cfg.Terminating {
		objectsToDelete = append(objectsToDelete, objectsToCreate...)
		objectsToCreate = nil
	}

	return objectsToCreate, objectsToDelete
}

func (c *kubeControllersComponent) Ready() bool {
	return true
}

func KubeControllersRoleCommonRules(cfg *KubeControllersConfiguration) []rbacv1.PolicyRule {
	rules := []rbacv1.PolicyRule{
		{
			// Nodes are watched to monitor for deletions.
			APIGroups: []string{""},
			Resources: []string{"nodes", "endpoints", "services"},
			Verbs:     []string{"watch", "list", "get"},
		},
		{
			// Pods are watched to check for existence as part of IPAM GC.
			APIGroups: []string{""},
			Resources: []string{"pods"},
			Verbs:     []string{"get", "list", "watch"},
		},
		{
			APIGroups: []string{""},
			Resources: []string{"services", "services/status"},
			Verbs:     []string{"get", "list", "update", "watch"},
		},
		{
			// IPAM resources are manipulated in response to node and block updates, as well as periodic triggers.
			// The node controller watches IPReservations to report how much of each pool they cover.
			APIGroups: []string{"projectcalico.org", "crd.projectcalico.org"},
			Resources: []string{"ipreservations"},
			Verbs:     []string{"list", "watch"},
		},
		{
			APIGroups: []string{"projectcalico.org", "crd.projectcalico.org"},
			Resources: []string{"blockaffinities", "ipamblocks", "ipamhandles", "networksets", "ipamconfigurations", "ipamconfigs"},
			Verbs:     []string{"get", "list", "create", "update", "delete", "watch"},
		},
		{
			APIGroups: []string{"projectcalico.org", "crd.projectcalico.org"},
			Resources: []string{
				// Pools are watched by various controllers.
				// - IPAM garbage collection watches pools to know which blocks to GC.
				// - The pool controller adds / manages finalizers on IP pools.
				// - The pool controller updates status conditions on IP pools.
				"ippools",
				"ippools/status",
			},
			Verbs: []string{"list", "watch", "update"},
		},
		{
			// Needs access to update clusterinformations.
			APIGroups: []string{"projectcalico.org", "crd.projectcalico.org"},
			Resources: []string{"clusterinformations"},
			Verbs:     []string{"get", "create", "update", "list", "watch"},
		},
		{
			// Needs to manage hostendpoints.
			APIGroups: []string{"projectcalico.org", "crd.projectcalico.org"},
			Resources: []string{"hostendpoints"},
			Verbs:     []string{"get", "list", "create", "update", "delete", "watch"},
		},
		{
			// Needs to manipulate kubecontrollersconfiguration, which contains
			// its config.  It creates a default if none exists, and updates status
			// as well.
			APIGroups: []string{"projectcalico.org", "crd.projectcalico.org"},
			Resources: []string{"kubecontrollersconfigurations", "kubecontrollersconfigurations/status"},
			Verbs:     []string{"get", "create", "list", "update", "watch"},
		},
		{
			// calico-kube-controllers requires tiers create to create the default tiers,
			// and get permissions to access network policies in those tiers. It also
			// patches tiers to add and remove its finalizer.
			APIGroups: []string{"projectcalico.org", "crd.projectcalico.org"},
			Resources: []string{"tiers"},
			Verbs:     []string{"create", "update", "patch", "get", "list", "watch"},
		},
		{
			// Namespaces are watched for LoadBalancer IP allocation with namespace selector support
			APIGroups: []string{""},
			Resources: []string{"namespaces"},
			Verbs:     []string{"get", "list", "watch"},
		},
		{
			// The policy name migrator needs to check calico/node daemonset rollout status.
			APIGroups:     []string{"apps"},
			Resources:     []string{"daemonsets"},
			Verbs:         []string{"get"},
			ResourceNames: []string{"calico-node"},
		},
		{
			// The policy name migrator needs to be able to CRUD Calico NetworkPolicies.
			APIGroups: []string{"projectcalico.org", "crd.projectcalico.org"},
			Resources: []string{
				"networkpolicies",
				"globalnetworkpolicies",
				"stagednetworkpolicies",
				"stagedglobalnetworkpolicies",
			},
			Verbs: []string{"get", "list", "watch", "create", "update", "delete"},
		},
		{
			// The IPAM GC controller uses informers to list/watch KubeVirt VMs/VMIs for IP garbage collection.
			APIGroups: []string{"kubevirt.io"},
			Resources: []string{"virtualmachineinstances", "virtualmachines"},
			Verbs:     []string{"get", "list", "watch"},
		},
		{
			// The datastore migration controller watches DatastoreMigration CRs and updates their status.
			APIGroups: []string{"migration.projectcalico.org"},
			Resources: []string{"datastoremigrations", "datastoremigrations/status"},
			Verbs:     []string{"get", "list", "watch", "create", "update", "patch"},
		},
		{
			// The datastore migration controller needs to list/watch CRDs to determine
			// which API group is active.
			APIGroups: []string{"apiextensions.k8s.io"},
			Resources: []string{"customresourcedefinitions"},
			Verbs:     []string{"get", "list", "watch"},
		},
	}

	if cfg.Installation.KubernetesProvider.IsOpenShift() {
		rules = append(rules, rbacv1.PolicyRule{
			APIGroups:     []string{"security.openshift.io"},
			Resources:     []string{"securitycontextconstraints"},
			Verbs:         []string{"use"},
			ResourceNames: []string{securitycontextconstraints.NonRootV2},
		})
	}

	return rules
}

func (c *kubeControllersComponent) controllersServiceAccount() *corev1.ServiceAccount {
	return &corev1.ServiceAccount{
		TypeMeta: metav1.TypeMeta{Kind: "ServiceAccount", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      KubeControllerServiceAccount,
			Namespace: c.cfg.Namespace,
			Labels:    map[string]string{},
		},
	}
}

func (c *kubeControllersComponent) controllersClusterRole() *rbacv1.ClusterRole {
	role := &rbacv1.ClusterRole{
		TypeMeta: metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name: c.cfg.RoleName,
		},
		Rules: c.cfg.Rules,
	}

	return role
}

// controllersOCPFederationRoleBinding on Openshift, an admission controller will block requests unless this permission
// is active.
func (c *kubeControllersComponent) controllersOCPFederationRoleBinding() *rbacv1.ClusterRoleBinding {
	return &rbacv1.ClusterRoleBinding{
		TypeMeta: metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:   "calico-kube-controllers-endpoint-controller",
			Labels: map[string]string{},
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "ClusterRole",
			Name:     "system:controller:endpoint-controller",
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      "ServiceAccount",
				Name:      KubeControllerServiceAccount,
				Namespace: c.cfg.Namespace,
			},
		},
	}
}

func (c *kubeControllersComponent) controllersDeployment() *appsv1.Deployment {
	env := []corev1.EnvVar{
		{Name: "KUBE_CONTROLLERS_CONFIG_NAME", Value: c.cfg.ConfigName},
		{Name: "DATASTORE_TYPE", Value: "kubernetes"},
		{Name: "ENABLED_CONTROLLERS", Value: strings.Join(c.cfg.EnabledControllers, ",")},
		{Name: "DISABLE_KUBE_CONTROLLERS_CONFIG_API", Value: strconv.FormatBool(c.cfg.DisableConfigAPI)},
	}

	env = append(env, c.cfg.K8sServiceEpPodNetwork.EnvVars()...)
	env = append(env, c.cfg.ExtraEnv...)

	if c.cfg.TrustedBundle != nil {
		env = append(env,
			corev1.EnvVar{Name: "CA_CRT_PATH", Value: c.cfg.TrustedBundle.MountPath()},
		)
	}

	// UID 999 is used in kube-controller Dockerfile.
	sc := securitycontext.NewNonRootContext()
	sc.RunAsUser = ptr.To(int64(999))
	sc.RunAsGroup = ptr.To(int64(0))

	readinessProbe := &corev1.Probe{
		ProbeHandler: corev1.ProbeHandler{
			Exec: &corev1.ExecAction{
				Command: []string{components.CalicoBinaryPath, "health", fmt.Sprintf("--port=%d", KubeControllersHealthPort), "--type=readiness"},
			},
		},
		TimeoutSeconds: 10,
	}
	livenessProbe := &corev1.Probe{
		ProbeHandler: corev1.ProbeHandler{
			Exec: &corev1.ExecAction{
				Command: []string{components.CalicoBinaryPath, "health", fmt.Sprintf("--port=%d", KubeControllersHealthPort), "--type=liveness"},
			},
		},
		FailureThreshold:    6,
		InitialDelaySeconds: 10,
		TimeoutSeconds:      10,
	}
	containerCommand := []string{
		components.CalicoBinaryPath,
		"component",
		"kube-controllers",
		fmt.Sprintf("--health-port=%d", KubeControllersHealthPort),
	}

	container := corev1.Container{
		Name:            c.cfg.Name,
		Image:           c.calicoImage,
		Command:         containerCommand,
		Env:             env,
		Resources:       c.kubeControllersResources(),
		ReadinessProbe:  readinessProbe,
		LivenessProbe:   livenessProbe,
		SecurityContext: sc,
		VolumeMounts:    c.kubeControllersVolumeMounts(),
	}

	var initContainers []corev1.Container
	tolerations := appendUniqueTolerations(c.cfg.Installation.ControlPlaneTolerations, rmeta.TolerateCriticalAddonsAndControlPlane...)
	if c.cfg.Installation.KubernetesProvider.IsGKE() {
		tolerations = appendUniqueTolerations(tolerations, rmeta.TolerateGKEARM64NoSchedule)
	}
	podSpec := corev1.PodSpec{
		NodeSelector:       c.cfg.Installation.ControlPlaneNodeSelector,
		Tolerations:        tolerations,
		ImagePullSecrets:   c.cfg.Installation.ImagePullSecrets,
		ServiceAccountName: KubeControllerServiceAccount,
		InitContainers:     initContainers,
		Containers:         []corev1.Container{container},
		Volumes:            c.kubeControllersVolumes(),
	}

	var replicas int32 = 1

	d := appsv1.Deployment{
		TypeMeta: metav1.TypeMeta{Kind: "Deployment", APIVersion: "apps/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      c.cfg.Name,
			Namespace: c.cfg.Namespace,
		},
		Spec: appsv1.DeploymentSpec{
			Replicas: &replicas,
			Strategy: appsv1.DeploymentStrategy{
				Type: appsv1.RecreateDeploymentStrategyType,
			},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Name:        c.cfg.Name,
					Namespace:   c.cfg.Namespace,
					Annotations: c.annotations(),
				},
				Spec: podSpec,
			},
		},
	}

	render.SetClusterCriticalPod(&d.Spec.Template)

	if overrides := c.cfg.Installation.CalicoKubeControllersDeployment; overrides != nil {
		rcomp.ApplyDeploymentOverrides(&d, overrides)
	}
	return &d
}

func appendUniqueTolerations(tolerations []corev1.Toleration, toAppend ...corev1.Toleration) []corev1.Toleration {
	for _, toleration := range toAppend {
		if slices.Contains(tolerations, toleration) {
			continue
		}
		tolerations = append(tolerations, toleration)
	}
	return tolerations
}

func (c *kubeControllersComponent) controllersClusterRoleBinding() *rbacv1.ClusterRoleBinding {
	subjects := []rbacv1.Subject{}
	for _, ns := range c.cfg.BindingNamespaces {
		subjects = append(subjects, rbacv1.Subject{
			Kind:      "ServiceAccount",
			Name:      KubeControllerServiceAccount,
			Namespace: ns,
		})
	}
	return &rbacv1.ClusterRoleBinding{
		TypeMeta: metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:   c.cfg.RoleBindingName,
			Labels: map[string]string{},
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "ClusterRole",
			Name:     c.cfg.RoleName,
		},
		Subjects: subjects,
	}
}

func (c *kubeControllersComponent) managedClusterRoleBindings() []client.Object {
	if c.cfg.ManagedClusterWatchBinding {
		return []client.Object{
			rcomp.ClusterRoleBinding(ManagedClustersWatchRoleBindingName, render.ManagedClustersWatchClusterRoleName, KubeControllerServiceAccount, []string{c.cfg.Namespace}),
		}
	}
	return []client.Object{}
}

// prometheusService creates a Service which exposes an endpoint on kube-controllers for
// reporting Prometheus metrics.
func (c *kubeControllersComponent) prometheusService() *corev1.Service {
	return &corev1.Service{
		TypeMeta: metav1.TypeMeta{Kind: "Service", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      c.cfg.MetricsName,
			Namespace: c.cfg.Namespace,
			Annotations: map[string]string{
				"prometheus.io/scrape": "true",
				"prometheus.io/port":   fmt.Sprintf("%d", c.cfg.MetricsPort),
			},
			Labels: map[string]string{"k8s-app": c.cfg.Name},
		},
		Spec: corev1.ServiceSpec{
			Selector: map[string]string{"k8s-app": c.cfg.Name},
			// "Headless" service; prevent kube-proxy from rendering any rules for this service
			// (which is only intended for Prometheus to scrape).
			ClusterIP: "None",
			Ports: []corev1.ServicePort{
				{
					Name:       "metrics-port",
					Port:       int32(c.cfg.MetricsPort),
					TargetPort: intstr.FromInt(int(c.cfg.MetricsPort)),
					Protocol:   corev1.ProtocolTCP,
				},
			},
		},
	}
}

// kubeControllerResources creates the kube-controller's resource requirements.
func (c *kubeControllersComponent) kubeControllersResources() corev1.ResourceRequirements {
	return rmeta.GetResourceRequirements(c.cfg.Installation, operatorv1.ComponentNameKubeControllers)
}

func (c *kubeControllersComponent) annotations() map[string]string {
	var am map[string]string
	if c.cfg.TrustedBundle != nil {
		am = c.cfg.TrustedBundle.HashAnnotations()
	} else {
		am = make(map[string]string)
	}

	if c.cfg.KubeControllersGatewaySecret != nil {
		am[render.ElasticsearchUserHashAnnotation] = rmeta.AnnotationHash(c.cfg.KubeControllersGatewaySecret.Data)
	}
	return am
}

func (c *kubeControllersComponent) kubeControllersVolumeMounts() []corev1.VolumeMount {
	var mounts []corev1.VolumeMount
	if c.cfg.TrustedBundle != nil {
		mounts = append(mounts, c.cfg.TrustedBundle.VolumeMounts(c.SupportedOSType())...)
	}
	return mounts
}

func (c *kubeControllersComponent) kubeControllersVolumes() []corev1.Volume {
	var volumes []corev1.Volume
	if c.cfg.TrustedBundle != nil {
		volumes = append(volumes, c.cfg.TrustedBundle.Volume())
	}
	return volumes
}

func kubeControllersCalicoSystemPolicy(cfg *KubeControllersConfiguration) *v3.NetworkPolicy {
	egressRules := []v3.Rule{}
	egressRules = networkpolicy.AppendDNSEgressRules(egressRules, cfg.Installation.KubernetesProvider.IsOpenShift())
	egressRules = append(egressRules, []v3.Rule{
		{
			Action:   v3.Allow,
			Protocol: &networkpolicy.TCPProtocol,
			Destination: v3.EntityRule{
				Ports: networkpolicy.Ports(443, 6443, 12388),
			},
		},
	}...)

	ingressRules := []v3.Rule{}
	if cfg.MetricsPort != 0 {
		ingressRules = append(ingressRules, v3.Rule{
			Action:   v3.Allow,
			Protocol: &networkpolicy.TCPProtocol,
			Source:   networkpolicy.PrometheusSourceEntityRule,
			Destination: v3.EntityRule{
				Ports: networkpolicy.Ports(uint16(cfg.MetricsPort)),
			},
		})
	}

	if r, err := cfg.K8sServiceEp.DestinationEntityRule(cfg.ClusterDomain); r != nil && err == nil {
		egressRules = append(egressRules, v3.Rule{
			Action:      v3.Allow,
			Protocol:    &networkpolicy.TCPProtocol,
			Destination: *r,
		})
	}

	return &v3.NetworkPolicy{
		TypeMeta: metav1.TypeMeta{Kind: "NetworkPolicy", APIVersion: "projectcalico.org/v3"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      KubeControllerNetworkPolicyName,
			Namespace: cfg.Namespace,
		},
		Spec: v3.NetworkPolicySpec{
			Order:    &networkpolicy.HighPrecedenceOrder,
			Tier:     networkpolicy.CalicoTierName,
			Selector: networkpolicy.KubernetesAppSelector(KubeController),
			Types:    []v3.PolicyType{v3.PolicyTypeEgress, v3.PolicyTypeIngress},
			Egress:   egressRules,
			Ingress:  ingressRules,
		},
	}
}
