// Copyright (c) 2025-2026 Tigera, Inc. All rights reserved.

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

package goldmane

import (
	"encoding/json"
	"fmt"
	"path/filepath"

	"github.com/projectcalico/calico/operator/pkg/common"
	"github.com/projectcalico/calico/operator/pkg/components"
	"github.com/projectcalico/calico/operator/pkg/render"
	"github.com/projectcalico/calico/operator/pkg/render/common/networkpolicy"
	"github.com/projectcalico/calico/operator/pkg/render/common/securitycontext"
	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	netv1 "k8s.io/api/networking/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"

	operatorv1 "github.com/projectcalico/calico/operator/api/v1"
	rcomp "github.com/projectcalico/calico/operator/pkg/render/common/components"
	rmeta "github.com/projectcalico/calico/operator/pkg/render/common/meta"
	"github.com/projectcalico/calico/operator/pkg/render/common/secret"
	"github.com/projectcalico/calico/operator/pkg/tls/certificatemanagement"
)

// The names of the components related to the Guardian related rendered objects.
const (
	GoldmaneName               = "goldmane"
	GoldmaneNamespace          = common.CalicoNamespace
	GoldmaneServiceAccountName = GoldmaneName
	GoldmaneDeploymentName     = GoldmaneName
	GoldmaneRoleName           = GoldmaneName
	GoldmaneServicePort        = 7443
	GoldmaneContainerName      = "goldmane"
	GoldmanePolicyName         = networkpolicy.CalicoComponentPolicyPrefix + GoldmaneName

	GoldmaneKeyPairSecret = "goldmane-key-pair"
	GoldmaneServiceName   = "goldmane"

	GoldmaneConfigVolumeName   = "config"
	GoldmaneConfigFilePath     = "/config"
	GoldmaneConfigFileName     = "config.json"
	GoldmaneMetricsServiceName = "goldmane-metrics"
	GoldmaneHealthPort         = 8080
)

func Goldmane(cfg *Configuration) render.Component {
	c := &Component{cfg: cfg}

	return c
}

// Configuration contains all the config information needed to render the component.
type Configuration struct {
	PullSecrets                 []*corev1.Secret
	OpenShift                   bool
	Installation                *operatorv1.InstallationSpec
	TrustedCertBundle           certificatemanagement.TrustedBundleRO
	GoldmaneServerKeyPair       certificatemanagement.KeyPairInterface
	ManagementClusterConnection *operatorv1.ManagementClusterConnection
	ClusterDomain               string
	Goldmane                    *operatorv1.Goldmane
}

type Component struct {
	cfg *Configuration

	calicoImage string
}

func (c *Component) ResolveImages(is *operatorv1.ImageSet) error {

	var err error
	c.calicoImage, err = components.ReferenceFor(components.ImageKeyCalico, c.cfg.Installation, is)
	return err
}

func (c *Component) SupportedOSType() rmeta.OSType {
	return rmeta.OSTypeLinux
}

func (c *Component) Objects() ([]client.Object, []client.Object) {
	deployment := c.deployment()
	if overrides := c.cfg.Goldmane.Spec.GoldmaneDeployment; overrides != nil {
		rcomp.ApplyDeploymentOverrides(deployment, overrides)
	}

	objs := []client.Object{
		c.serviceAccount(),
		c.role(),
		c.roleBinding(),
		c.hotReloadConfigMap(),
		c.goldmaneService(),
		deployment,
		c.networkPolicy(),
	}

	// Conditionally create or delete the metrics service based on whether a metrics port is configured.
	if c.metricsPort() != 0 {
		objs = append(objs, c.metricsService())
	}

	objs = append(objs, secret.ToRuntimeObjects(secret.CopyToNamespace(GoldmaneNamespace, c.cfg.PullSecrets...)...)...)

	var objsToDelete []client.Object
	if c.metricsPort() == 0 {
		objsToDelete = append(objsToDelete, c.metricsService())
	}

	objsToDelete = append(objsToDelete, c.deprecatedObjects()...)

	return objs, objsToDelete
}

func (c *Component) Ready() bool {
	return true
}

func (c *Component) serviceAccount() *corev1.ServiceAccount {
	return &corev1.ServiceAccount{
		TypeMeta:   metav1.TypeMeta{Kind: "ServiceAccount", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{Name: GoldmaneServiceAccountName, Namespace: GoldmaneNamespace},
	}
}

// hotReloadConfigMap returns a ConfigMap containing configuration for Goldmane that does not require a restart of the pod.
// This is mounted as a file within the Pod, which can be dynamically reloaded when changed.
func (c *Component) hotReloadConfigMap() *corev1.ConfigMap {
	type configMapData struct {
		EmitFlows bool `json:"emitFlows"`
	}

	d, err := json.Marshal(configMapData{EmitFlows: c.cfg.ManagementClusterConnection != nil})
	if err != nil {
		panic(fmt.Sprintf("BUG: failed to marshal config map data: %s", err))
	}

	return &corev1.ConfigMap{
		TypeMeta:   metav1.TypeMeta{Kind: "ConfigMap", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{Name: GoldmaneName, Namespace: GoldmaneNamespace},
		Data: map[string]string{
			GoldmaneConfigFileName: string(d),
		},
	}
}

// metricsPort returns the configured metrics port, or 0 if metrics are disabled.
func (c *Component) metricsPort() int32 {
	if c.cfg.Goldmane != nil && c.cfg.Goldmane.Spec.MetricsPort != nil {
		return *c.cfg.Goldmane.Spec.MetricsPort
	}
	return 0
}

// metricsService creates a headless Service for Prometheus to scrape Goldmane metrics.
func (c *Component) metricsService() *corev1.Service {
	port := c.metricsPort()
	return &corev1.Service{
		TypeMeta: metav1.TypeMeta{Kind: "Service", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      GoldmaneMetricsServiceName,
			Namespace: GoldmaneNamespace,
			Annotations: map[string]string{
				"prometheus.io/scrape": "true",
				"prometheus.io/port":   fmt.Sprintf("%d", port),
			},
			Labels: map[string]string{"k8s-app": GoldmaneDeploymentName},
		},
		Spec: corev1.ServiceSpec{
			Selector:  map[string]string{"k8s-app": GoldmaneDeploymentName},
			ClusterIP: "None",
			Ports: []corev1.ServicePort{
				{
					Name:       "metrics-port",
					Port:       port,
					TargetPort: intstr.FromInt32(port),
					Protocol:   corev1.ProtocolTCP,
				},
			},
		},
	}
}

func (c *Component) goldmaneContainer() corev1.Container {
	guardianSvc := render.GuardianService(c.cfg.ClusterDomain)
	env := []corev1.EnvVar{
		{Name: "LOG_LEVEL", Value: "INFO"},
		{Name: "PORT", Value: fmt.Sprintf("%d", GoldmaneServicePort)},
		{Name: "SERVER_CERT_PATH", Value: c.cfg.GoldmaneServerKeyPair.VolumeMountCertificateFilePath()},
		{Name: "SERVER_KEY_PATH", Value: c.cfg.GoldmaneServerKeyPair.VolumeMountKeyFilePath()},
		{Name: "CA_CERT_PATH", Value: c.cfg.TrustedCertBundle.MountPath()},
		{Name: "PUSH_URL", Value: fmt.Sprintf("%s/api/v1/flows/bulk", guardianSvc)},
		{Name: "FILE_CONFIG_PATH", Value: filepath.Join(GoldmaneConfigFilePath, GoldmaneConfigFileName)},
		{Name: "HEALTH_ENABLED", Value: "true"},
	}
	if port := c.metricsPort(); port != 0 {
		env = append(env, corev1.EnvVar{Name: "PROMETHEUS_PORT", Value: fmt.Sprintf("%d", port)})
	}

	volumeMounts := []corev1.VolumeMount{c.cfg.GoldmaneServerKeyPair.VolumeMount(c.SupportedOSType())}
	volumeMounts = append(volumeMounts, c.cfg.TrustedCertBundle.VolumeMounts(c.SupportedOSType())...)
	volumeMounts = append(volumeMounts, corev1.VolumeMount{
		Name:      GoldmaneConfigVolumeName,
		ReadOnly:  true,
		MountPath: GoldmaneConfigFilePath,
	})

	return corev1.Container{
		Name:            GoldmaneContainerName,
		Image:           c.calicoImage,
		Command:         []string{components.CalicoBinaryPath, "component", "goldmane"},
		Env:             env,
		SecurityContext: securitycontext.NewNonRootContext(),
		ReadinessProbe: &corev1.Probe{
			ProbeHandler: corev1.ProbeHandler{Exec: &corev1.ExecAction{
				Command: []string{components.CalicoBinaryPath, "health", fmt.Sprintf("--port=%d", GoldmaneHealthPort), "--type=readiness"},
			}},
			PeriodSeconds: 10,
		},
		LivenessProbe: &corev1.Probe{
			ProbeHandler: corev1.ProbeHandler{Exec: &corev1.ExecAction{
				Command: []string{components.CalicoBinaryPath, "health", fmt.Sprintf("--port=%d", GoldmaneHealthPort), "--type=liveness"},
			}},
			PeriodSeconds: 10,
		},
		VolumeMounts: volumeMounts,
	}
}

func (c *Component) goldmaneService() *corev1.Service {
	return &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      GoldmaneServiceName,
			Namespace: GoldmaneNamespace,
		},
		Spec: corev1.ServiceSpec{
			Ports: []corev1.ServicePort{{Port: GoldmaneServicePort}},
			Selector: map[string]string{
				"k8s-app": GoldmaneDeploymentName,
			},
		},
	}
}

func (c *Component) deployment() *appsv1.Deployment {
	tolerations := append(c.cfg.Installation.ControlPlaneTolerations, rmeta.TolerateCriticalAddonsAndControlPlane...)
	if c.cfg.Installation.KubernetesProvider.IsGKE() {
		tolerations = append(tolerations, rmeta.TolerateGKEARM64NoSchedule)
	}

	ctrs := []corev1.Container{c.goldmaneContainer()}
	volumes := []corev1.Volume{
		c.cfg.GoldmaneServerKeyPair.Volume(),
		c.cfg.TrustedCertBundle.Volume(),
		{
			Name: GoldmaneConfigVolumeName,
			VolumeSource: corev1.VolumeSource{
				ConfigMap: &corev1.ConfigMapVolumeSource{
					LocalObjectReference: corev1.LocalObjectReference{Name: GoldmaneName},
				},
			},
		},
	}

	// Add an annotation for the key pair as it requires a server restart (may as well restart the pod). Don't add an
	// annotation for the mount CA since it's used for a client that can pick up the changes without a pod restart.
	annotations := map[string]string{
		c.cfg.GoldmaneServerKeyPair.HashAnnotationKey(): c.cfg.GoldmaneServerKeyPair.HashAnnotationValue(),
	}

	return &appsv1.Deployment{
		TypeMeta: metav1.TypeMeta{Kind: "Deployment", APIVersion: "apps/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:        GoldmaneDeploymentName,
			Namespace:   GoldmaneNamespace,
			Annotations: annotations,
		},
		Spec: appsv1.DeploymentSpec{
			Replicas: ptr.To(int32(1)),
			Strategy: appsv1.DeploymentStrategy{
				Type: appsv1.RecreateDeploymentStrategyType,
			},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Name: GoldmaneDeploymentName,
				},
				Spec: corev1.PodSpec{
					NodeSelector:       c.cfg.Installation.ControlPlaneNodeSelector,
					ServiceAccountName: GoldmaneServiceAccountName,
					Tolerations:        tolerations,
					ImagePullSecrets:   secret.GetReferenceList(c.cfg.PullSecrets),
					Containers:         ctrs,
					Volumes:            volumes,
				},
			},
		},
	}
}

func (c *Component) roleBinding() *rbacv1.RoleBinding {
	return &rbacv1.RoleBinding{
		TypeMeta: metav1.TypeMeta{Kind: "RoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      GoldmaneRoleName,
			Namespace: GoldmaneNamespace,
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "Role",
			Name:     GoldmaneRoleName,
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      "ServiceAccount",
				Name:      GoldmaneRoleName,
				Namespace: GoldmaneNamespace,
			},
		},
	}
}

func (c *Component) role() *rbacv1.Role {
	policyRules := []rbacv1.PolicyRule{
		{
			APIGroups: []string{""},
			Resources: []string{"configmaps"},
			Verbs:     []string{"get", "list", "watch", "create", "update", "patch"},
		},
	}

	return &rbacv1.Role{
		TypeMeta: metav1.TypeMeta{Kind: "Role", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      GoldmaneRoleName,
			Namespace: GoldmaneNamespace,
		},
		Rules: policyRules,
	}
}

func (c *Component) networkPolicy() *v3.NetworkPolicy {
	ingressRules := []v3.Rule{
		{
			Action:   v3.Allow,
			Protocol: &networkpolicy.TCPProtocol,
			Destination: v3.EntityRule{
				Ports: networkpolicy.Ports(GoldmaneServicePort),
			},
		},
	}
	if port := c.metricsPort(); port != 0 {
		ingressRules = append(ingressRules, v3.Rule{
			Action:   v3.Allow,
			Protocol: &networkpolicy.TCPProtocol,
			Destination: v3.EntityRule{
				Ports: networkpolicy.Ports(uint16(port)),
			},
		})
	}

	egressRules := networkpolicy.AppendDNSEgressRules([]v3.Rule{}, c.cfg.OpenShift)

	// Allow egress to the Kubernetes API server. Goldmane reads the
	// flow-emitter-state ConfigMap.
	egressRules = append(egressRules, v3.Rule{
		Action:      v3.Allow,
		Protocol:    &networkpolicy.TCPProtocol,
		Destination: networkpolicy.KubeAPIServerEntityRule,
	})

	// In a managed cluster Goldmane posts flows to Guardian, which tunnels them
	// to the management cluster.
	if c.cfg.ManagementClusterConnection != nil {
		egressRules = append(egressRules, v3.Rule{
			Action:      v3.Allow,
			Protocol:    &networkpolicy.TCPProtocol,
			Destination: render.GuardianEntityRule,
		})
	}

	return &v3.NetworkPolicy{
		TypeMeta:   metav1.TypeMeta{Kind: "NetworkPolicy", APIVersion: "projectcalico.org/v3"},
		ObjectMeta: metav1.ObjectMeta{Name: GoldmanePolicyName, Namespace: GoldmaneNamespace},
		Spec: v3.NetworkPolicySpec{
			Order:    &networkpolicy.HighPrecedenceOrder,
			Tier:     networkpolicy.CalicoTierName,
			Selector: networkpolicy.KubernetesAppSelector(GoldmaneDeploymentName),
			Types:    []v3.PolicyType{v3.PolicyTypeIngress, v3.PolicyTypeEgress},
			Ingress:  ingressRules,
			Egress:   egressRules,
		},
	}
}

// deprecatedObjects returns any objects that should be removed when Goldmane is enabled, but were used in
// previous versions of the operator.
func (c *Component) deprecatedObjects() []client.Object {
	return []client.Object{
		// Deprecates k8s NetworkPolicy because Calico components now also have Tiers component enabled.
		&netv1.NetworkPolicy{
			TypeMeta:   metav1.TypeMeta{Kind: "NetworkPolicy", APIVersion: "networking.k8s.io/v1"},
			ObjectMeta: metav1.ObjectMeta{Name: "goldmane", Namespace: GoldmaneNamespace},
		},
	}
}
