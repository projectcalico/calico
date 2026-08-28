// Copyright (c) 2021-2026 Tigera, Inc. All rights reserved.

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

package applicationlayer

import (
	"bytes"
	_ "embed"
	"fmt"
	"strconv"
	"strings"
	"text/template"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"sigs.k8s.io/controller-runtime/pkg/client"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/components"
	"github.com/tigera/operator/pkg/render"
	rcomponents "github.com/tigera/operator/pkg/render/common/components"
	rmeta "github.com/tigera/operator/pkg/render/common/meta"
	"github.com/tigera/operator/pkg/render/common/secret"
	"github.com/tigera/operator/pkg/render/common/securitycontext"
	"github.com/tigera/operator/pkg/render/common/securitycontextconstraints"
)

const (
	APLName                       = "application-layer"
	RoleName                      = "application-layer"
	ApplicationLayerDaemonsetName = "l7-log-collector"
	L7CollectorContainerName      = "l7-collector"
	L7CollectorSocksVolumeName    = "l7-collector-socks"
	ProxyContainerName            = "envoy-proxy"
	EnvoyLogsVolumeName           = "envoy-logs"
	EnvoyConfigMapName            = "envoy-config"
	EnvoyConfigMapKey             = "envoy-config.yaml"
	FelixSync                     = "felix-sync"
	DikastesSyncVolumeName        = "dikastes-sync"
	DikastesContainerName         = "dikastes"
	WAFConfigVolumeName           = "tigera-waf-config"
	WAFConfigVolumePath           = "/etc/waf"
	DefaultCoreRulesetVolumeName  = "coreruleset-default"
	DefaultCoreRulesetVolumePath  = "/etc/waf/coreruleset"
	WAFRulesetConfigMapName       = "tigera-waf-config"
	DefaultCoreRuleset            = "coreruleset-default"
	WAFConfigHashAnnotation       = "hash.operator.tigera.io/tigera-waf-config"
	CalicoLogsVolumeName          = "var-log-calico"
	CalicologsVolumePath          = "/var/log/calico"
)

func ApplicationLayer(
	config *Config,
) render.Component {
	return &component{
		config: config,
	}
}

type component struct {
	config *Config
}

// Config contains all the config information ApplicationLayer needs to render component.
type Config struct {
	// Required config.
	PullSecrets  []*corev1.Secret
	Installation *operatorv1.InstallationSpec
	OsType       rmeta.OSType

	// Optional config for WAF.
	PerHostWAFEnabled           bool
	WAFRulesetConfigMap         *corev1.ConfigMap
	DefaultCoreRulesetConfigMap *corev1.ConfigMap

	// Optional config for L7 logs.
	PerHostLogsEnabled     bool
	LogRequestsPerInterval *int64
	LogIntervalSeconds     *int64

	// Optional config for ALP
	PerHostALPEnabled bool

	// Optional config for SidecarInjection
	SidecarInjectionEnabled bool

	// Calculated internal fields.
	proxyImage            string
	calicoImage           string
	dikastesImage         string
	dikastesEnabled       bool
	perHostEnvoyEnabled   bool
	l7logcollectorEnabled bool
	envoyConfigMap        *corev1.ConfigMap

	// envoy user-configurable overrides
	UseRemoteAddressXFF bool
	NumTrustedHopsXFF   int32

	ApplicationLayer *operatorv1.ApplicationLayer
}

func (c *component) ResolveImages(is *operatorv1.ImageSet) error {
	reg := c.config.Installation.Registry
	path := c.config.Installation.ImagePath
	prefix := c.config.Installation.ImagePrefix

	if c.config.OsType != c.SupportedOSType() {
		return fmt.Errorf("layer 7 features are supported only on %s", c.SupportedOSType())
	}

	var err error
	var errMsgs []string

	c.config.proxyImage, err = components.GetReference(components.ComponentEnvoyProxy, reg, path, prefix, is)
	if err != nil {
		errMsgs = append(errMsgs, err.Error())
	}

	c.config.calicoImage, err = components.GetReference(components.ComponentTigeraCalico, reg, path, prefix, is)
	if err != nil {
		errMsgs = append(errMsgs, err.Error())
	}

	c.config.dikastesImage, err = components.GetReference(components.ComponentDikastes, reg, path, prefix, is)
	if err != nil {
		errMsgs = append(errMsgs, err.Error())
	}

	if len(errMsgs) != 0 {
		return fmt.Errorf("%s", strings.Join(errMsgs, ","))
	}

	return nil
}

func (c *component) SupportedOSType() rmeta.OSType {
	return rmeta.OSTypeLinux
}

func (c *component) Objects() ([]client.Object, []client.Object) {
	var objs []client.Object
	// If l7spec is provided render the required objects.
	objs = append(objs, c.serviceAccount())

	c.config.dikastesEnabled = c.config.PerHostWAFEnabled ||
		c.config.PerHostALPEnabled ||
		c.config.SidecarInjectionEnabled

	c.config.l7logcollectorEnabled = c.config.PerHostLogsEnabled ||
		c.config.SidecarInjectionEnabled

	c.config.perHostEnvoyEnabled = c.config.PerHostWAFEnabled ||
		c.config.PerHostALPEnabled ||
		c.config.PerHostLogsEnabled

	// If Web Application Firewall or Sidecar Injection is enabled, we need WAF ruleset ConfigMap present.
	if c.config.PerHostWAFEnabled || c.config.SidecarInjectionEnabled {
		// this ConfigMap is a copy of the provided configuration from the operator namespace into the calico-system namespace
		objs = append(objs, c.wafRulesetConfigMap())
		objs = append(objs, c.defaultCoreRulesetConfigMap())
	}

	// Envoy configuration
	if c.config.perHostEnvoyEnabled {
		c.config.envoyConfigMap = c.envoyL7ConfigMap()
		objs = append(objs, c.config.envoyConfigMap)
	}

	// Envoy, Dikastes & L7 log collector Daemonset
	// It always installed, even with sidecars enabled, the sidecars contain
	// only envoy proxy inside them, and if only sidcar is enabled the
	// daemonset will contain only Dikastes and L7 log collector to be
	// prepared to do some action depending on the envoy inside application
	// pod configuration.
	objs = append(objs, c.daemonset())

	if c.config.Installation.KubernetesProvider.IsDockerEE() {
		objs = append(objs, c.clusterAdminClusterRoleBinding())
	}

	if c.config.Installation.KubernetesProvider.IsOpenShift() {
		objs = append(objs, c.role(), c.roleBinding())
	}

	return objs, nil
}

func (c *component) Ready() bool {
	return true
}

// daemonset creates a daemonset for the L7 log collector component.
func (c *component) daemonset() *appsv1.DaemonSet {
	maxUnavailable := intstr.FromInt(1)

	annots := map[string]string{}

	if c.config.envoyConfigMap != nil {
		annots[EnvoyConfigMapName] = rmeta.AnnotationHash(c.config.envoyConfigMap)
	}

	if c.config.WAFRulesetConfigMap != nil {
		annots[WAFConfigHashAnnotation] = rmeta.AnnotationHash(c.config.WAFRulesetConfigMap.Data)
	}

	podTemplate := corev1.PodTemplateSpec{
		ObjectMeta: metav1.ObjectMeta{
			Annotations: annots,
		},
		Spec: corev1.PodSpec{
			HostIPC:            true,
			HostNetwork:        true,
			ServiceAccountName: APLName,
			DNSPolicy:          corev1.DNSClusterFirstWithHostNet,
			// Absence of l7 daemonset pod on a node will break the annotated services connectivity, so we tolerate all.
			Tolerations:      rmeta.TolerateAll,
			ImagePullSecrets: secret.GetReferenceList(c.config.PullSecrets),
			Containers:       c.containers(),
			Volumes:          c.volumes(),
		},
	}

	ds := &appsv1.DaemonSet{
		TypeMeta: metav1.TypeMeta{Kind: "DaemonSet", APIVersion: "apps/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      ApplicationLayerDaemonsetName,
			Namespace: common.CalicoNamespace,
		},
		Spec: appsv1.DaemonSetSpec{
			Template: podTemplate,
			UpdateStrategy: appsv1.DaemonSetUpdateStrategy{
				RollingUpdate: &appsv1.RollingUpdateDaemonSet{
					MaxUnavailable: &maxUnavailable,
				},
			},
		},
	}

	if c.config.ApplicationLayer != nil {
		if overrides := c.config.ApplicationLayer.Spec.L7LogCollectorDaemonSet; overrides != nil {
			rcomponents.ApplyDaemonSetOverrides(ds, overrides)
		}
	}
	return ds
}

func (c *component) containers() []corev1.Container {
	var containers []corev1.Container

	// Daemonset needs root and NET_ADMIN, NET_RAW permission to be able to use netfilter tproxy option.
	if c.config.perHostEnvoyEnabled {
		sc := securitycontext.NewRootContext(false)
		sc.Capabilities.Add = []corev1.Capability{
			"NET_ADMIN",
			"NET_RAW",
		}
		proxy := corev1.Container{
			Name:  ProxyContainerName,
			Image: c.config.proxyImage,
			Command: []string{
				"envoy", "-c", "/etc/envoy/envoy-config.yaml",
			},
			SecurityContext: sc,
			Env:             c.proxyEnv(),
			VolumeMounts:    c.proxyVolMounts(),
		}

		containers = append(containers, proxy)
	}

	if c.config.l7logcollectorEnabled {
		// Log collection specific container
		collector := corev1.Container{
			Name:            L7CollectorContainerName,
			Image:           c.config.calicoImage,
			Command:         []string{components.CalicoBinaryPath, "component", "l7-collector"},
			Env:             c.collectorEnv(),
			SecurityContext: securitycontext.NewRootContext(false),
			VolumeMounts:    c.collectorVolMounts(),
		}
		containers = append(containers, collector)
	}

	if c.config.dikastesEnabled {
		// Web Application Firewall (WAF) and ApplicationLayer Policies (ALP) specific container

		commandArgs := []string{
			components.CalicoBinaryPath, "component", "dikastes",
			"server",
			"--dial", "/var/run/felix/nodeagent/socket",
			"--listen", "/var/run/dikastes/dikastes.sock",
		}

		volMounts := []corev1.VolumeMount{
			{Name: FelixSync, MountPath: "/var/run/felix"},
			{Name: DikastesSyncVolumeName, MountPath: "/var/run/dikastes"},
		}

		if c.config.PerHostWAFEnabled || c.config.SidecarInjectionEnabled {
			commandArgs = append(
				commandArgs,
				"--waf-ruleset-root-dir", WAFConfigVolumePath,
				"--waf-ruleset-file", "tigera.conf",
			)
			if c.config.PerHostWAFEnabled {
				commandArgs = append(commandArgs, "--per-host-waf-enabled")
			}
			volMounts = append(
				volMounts,
				[]corev1.VolumeMount{
					{
						Name:      CalicoLogsVolumeName,
						MountPath: CalicologsVolumePath,
					},
					{
						Name:      WAFConfigVolumeName,
						MountPath: WAFConfigVolumePath,
						ReadOnly:  true,
					},
					{
						Name:      DefaultCoreRulesetVolumeName,
						MountPath: DefaultCoreRulesetVolumePath,
						ReadOnly:  true,
					},
				}...,
			)
		}

		if c.config.PerHostALPEnabled {
			commandArgs = append(commandArgs, "--per-host-alp-enabled")
		}

		dikastes := corev1.Container{
			Name:    DikastesContainerName,
			Image:   c.config.dikastesImage,
			Command: commandArgs,
			Env: []corev1.EnvVar{
				{Name: "LOG_LEVEL", Value: "Info"},
				{Name: "DIKASTES_SUBSCRIPTION_TYPE", Value: "per-host-policies"},
			},
			VolumeMounts:    volMounts,
			SecurityContext: securitycontext.NewRootContext(true),
		}
		containers = append(containers, dikastes)
	}

	return containers
}

func (c *component) proxyEnv() []corev1.EnvVar {
	return []corev1.EnvVar{
		// envoy needs to run as root to be able to use transparent flag (for tproxy)
		{Name: "ENVOY_UID", Value: "0"},
		{Name: "ENVOY_GID", Value: "0"},
		{Name: "TIGERA_TPROXY", Value: "Enabled"},
	}
}

func (c *component) collectorEnv() []corev1.EnvVar {
	envs := []corev1.EnvVar{
		{Name: "LOG_LEVEL", Value: "Info"},
		{Name: "FELIX_DIAL_TARGET", Value: "/var/run/felix/nodeagent/socket"},
	}

	// Set rate limiters if provided.
	if c.config.LogRequestsPerInterval != nil {
		envs = append(envs, corev1.EnvVar{
			Name:  "ENVOY_LOG_REQUESTS_PER_INTERVAL",
			Value: strconv.FormatInt(*c.config.LogRequestsPerInterval, 10),
		})
	}

	if c.config.LogIntervalSeconds != nil {
		envs = append(envs, corev1.EnvVar{
			Name:  "ENVOY_LOG_INTERVAL_SECONDS",
			Value: strconv.FormatInt(*c.config.LogIntervalSeconds, 10),
		})
	}

	return envs
}

func (c *component) volumes() []corev1.Volume {
	hostPathDirectoryOrCreate := corev1.HostPathDirectoryOrCreate
	volumes := []corev1.Volume{
		{
			Name: FelixSync,
			VolumeSource: corev1.VolumeSource{
				CSI: &corev1.CSIVolumeSource{
					Driver: "csi.tigera.io",
				},
			},
		},
		// This empty directory volume will be mounted at /tmp/ which will contain the access logs file generated by envoy.
		{
			Name: EnvoyLogsVolumeName,
			VolumeSource: corev1.VolumeSource{
				EmptyDir: &corev1.EmptyDirVolumeSource{},
			},
		},
	}

	if c.config.perHostEnvoyEnabled {
		volumes = append(volumes, corev1.Volume{
			Name: EnvoyConfigMapName,
			VolumeSource: corev1.VolumeSource{
				ConfigMap: &corev1.ConfigMapVolumeSource{
					LocalObjectReference: corev1.LocalObjectReference{Name: EnvoyConfigMapName},
				},
			},
		})
	}

	if c.config.l7logcollectorEnabled {
		volumes = append(volumes, corev1.Volume{
			Name: L7CollectorSocksVolumeName,
			VolumeSource: corev1.VolumeSource{
				HostPath: &corev1.HostPathVolumeSource{
					Path: "/var/run/l7-collector",
					Type: &hostPathDirectoryOrCreate,
				},
			},
		})
	}

	if c.config.dikastesEnabled {
		// Web Application Firewall + ApplicationLayer Policy specific volumes.

		// Needed for Dikastes' authz check server.
		volumes = append(volumes, corev1.Volume{
			Name: DikastesSyncVolumeName,
			VolumeSource: corev1.VolumeSource{
				HostPath: &corev1.HostPathVolumeSource{
					Path: "/var/run/dikastes",
					Type: &hostPathDirectoryOrCreate,
				},
			},
		})

		// Needed for Coraza library - contains rule set.
		if c.config.PerHostWAFEnabled || c.config.SidecarInjectionEnabled {
			// WAF logs need HostPath volume - logs to be consumed by fluent-bit.
			volumes = append(volumes, corev1.Volume{
				Name: CalicoLogsVolumeName,
				VolumeSource: corev1.VolumeSource{
					HostPath: &corev1.HostPathVolumeSource{
						Path: CalicologsVolumePath,
						Type: &hostPathDirectoryOrCreate,
					},
				},
			})

			// WAF ruleset volume
			volumes = append(volumes, corev1.Volume{
				Name: WAFConfigVolumeName,
				VolumeSource: corev1.VolumeSource{
					ConfigMap: &corev1.ConfigMapVolumeSource{
						LocalObjectReference: corev1.LocalObjectReference{
							Name: WAFRulesetConfigMapName,
						},
					},
				},
			})

			// Default coreruleset volume
			volumes = append(volumes, corev1.Volume{
				Name: DefaultCoreRulesetVolumeName,
				VolumeSource: corev1.VolumeSource{
					ConfigMap: &corev1.ConfigMapVolumeSource{
						LocalObjectReference: corev1.LocalObjectReference{
							Name: DefaultCoreRuleset,
						},
					},
				},
			})
		}
	}

	return volumes
}

func (c *component) proxyVolMounts() []corev1.VolumeMount {
	volumes := []corev1.VolumeMount{
		{Name: EnvoyConfigMapName, MountPath: "/etc/envoy"},
		{Name: EnvoyLogsVolumeName, MountPath: "/tmp/"},
	}

	if c.config.dikastesEnabled {
		volumes = append(volumes,
			corev1.VolumeMount{
				Name:      DikastesSyncVolumeName,
				MountPath: "/var/run/dikastes",
			},
		)
	}

	return volumes
}

func (c *component) collectorVolMounts() []corev1.VolumeMount {
	return []corev1.VolumeMount{
		{Name: EnvoyLogsVolumeName, MountPath: "/tmp/"},
		{Name: FelixSync, MountPath: "/var/run/felix"},
		{Name: L7CollectorSocksVolumeName, MountPath: "/var/run/l7-collector"},
	}
}

func (c *component) wafRulesetConfigMap() *corev1.ConfigMap {
	return &corev1.ConfigMap{
		TypeMeta: metav1.TypeMeta{Kind: "ConfigMap", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      WAFRulesetConfigMapName,
			Namespace: common.CalicoNamespace,
			Labels:    map[string]string{},
		},
		Data:       c.config.WAFRulesetConfigMap.Data,
		BinaryData: c.config.WAFRulesetConfigMap.BinaryData,
	}
}

func (c *component) defaultCoreRulesetConfigMap() *corev1.ConfigMap {
	return &corev1.ConfigMap{
		TypeMeta: metav1.TypeMeta{Kind: "ConfigMap", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      DefaultCoreRuleset,
			Namespace: common.CalicoNamespace,
			Labels:    map[string]string{},
		},
		Data:       c.config.DefaultCoreRulesetConfigMap.Data,
		BinaryData: c.config.DefaultCoreRulesetConfigMap.BinaryData,
	}
}

//go:embed envoy-config.yaml.template
var envoyConfigTemplate string

func (c *component) envoyL7ConfigMap() *corev1.ConfigMap {
	var config bytes.Buffer

	tpl, err := template.New("envoyConfigTemplate").Parse(envoyConfigTemplate)
	if err != nil {
		return nil
	}

	err = tpl.Execute(&config, c.config)
	if err != nil {
		return nil
	}

	return &corev1.ConfigMap{
		TypeMeta: metav1.TypeMeta{Kind: "ConfigMap", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      EnvoyConfigMapName,
			Namespace: common.CalicoNamespace,
			Labels:    map[string]string{},
		},
		Data: map[string]string{
			EnvoyConfigMapKey: config.String(),
		},
	}
}

// serviceAccount creates application layer service account.
func (c *component) serviceAccount() *corev1.ServiceAccount {
	return &corev1.ServiceAccount{
		TypeMeta:   metav1.TypeMeta{Kind: "ServiceAccount", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{Name: APLName, Namespace: common.CalicoNamespace},
	}
}

// In DockerEE (Mirantis) cluster-admin role is needed for envoy proxy to be able to use hostNetwork.
func (c *component) clusterAdminClusterRoleBinding() *rbacv1.ClusterRoleBinding {
	return &rbacv1.ClusterRoleBinding{
		TypeMeta: metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:   "application-layer-cluster-admin",
			Labels: map[string]string{},
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "ClusterRole",
			Name:     "cluster-admin",
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      "ServiceAccount",
				Name:      APLName,
				Namespace: common.CalicoNamespace,
			},
		},
	}
}

func (c *component) role() *rbacv1.Role {
	return &rbacv1.Role{
		TypeMeta: metav1.TypeMeta{Kind: "Role", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      RoleName,
			Namespace: common.CalicoNamespace,
		},
		Rules: []rbacv1.PolicyRule{
			{

				APIGroups:     []string{"security.openshift.io"},
				Resources:     []string{"securitycontextconstraints"},
				Verbs:         []string{"use"},
				ResourceNames: []string{securitycontextconstraints.Privileged},
			},
		},
	}
}

func (c *component) roleBinding() *rbacv1.RoleBinding {
	return &rbacv1.RoleBinding{
		TypeMeta: metav1.TypeMeta{Kind: "RoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      RoleName,
			Namespace: common.CalicoNamespace,
		},
		RoleRef: rbacv1.RoleRef{
			Kind:     "Role",
			Name:     RoleName,
			APIGroup: "rbac.authorization.k8s.io",
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      "ServiceAccount",
				Name:      APLName,
				Namespace: common.CalicoNamespace,
			},
		},
	}
}
