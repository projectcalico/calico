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

package whisker

import (
	_ "embed"
	"fmt"

	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	netv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"

	operatorv1 "github.com/projectcalico/calico/operator/api/v1"
	"github.com/projectcalico/calico/operator/pkg/common"
	"github.com/projectcalico/calico/operator/pkg/components"
	"github.com/projectcalico/calico/operator/pkg/render"
	rcomp "github.com/projectcalico/calico/operator/pkg/render/common/components"
	rmeta "github.com/projectcalico/calico/operator/pkg/render/common/meta"
	"github.com/projectcalico/calico/operator/pkg/render/common/networkpolicy"
	"github.com/projectcalico/calico/operator/pkg/render/common/secret"
	"github.com/projectcalico/calico/operator/pkg/render/common/securitycontext"
	"github.com/projectcalico/calico/operator/pkg/tls/certificatemanagement"
)

// The names of the components related to the Guardian related rendered objects.
const (
	WhiskerName               = "whisker"
	WhiskerNamespace          = common.CalicoNamespace
	WhiskerServiceAccountName = WhiskerName
	WhiskerDeploymentName     = WhiskerName
	WhiskerPolicyName         = networkpolicy.CalicoComponentPolicyPrefix + WhiskerName

	WhiskerContainerName        = "whisker"
	WhiskerBackendContainerName = "whisker-backend"

	WhiskerKeyPairSecret        = "whisker-key-pair"
	WhiskerBackendKeyPairSecret = "whisker-backend-key-pair"
	WhiskerServicePort          = 8443
	GoldmaneDeploymentName      = "goldmane"
	GoldmaneServicePort         = 7443
	GoldmaneNamespace           = common.CalicoNamespace

	configMapName    = "whisker-nginx-config"
	configVolumeName = "nginx-config"
	configMountPath  = "/etc/nginx/conf.d"
)

var (
	// Embed the nginx config files.
	//go:embed nginx-v4.conf
	NginxConfigV4 string

	//go:embed nginx.conf
	NginxConfigDual string
)

func Whisker(cfg *Configuration) render.Component {
	c := &Component{cfg: cfg}

	return c
}

// Configuration contains all the config information needed to render the component.
type Configuration struct {
	PullSecrets           []*corev1.Secret
	OpenShift             bool
	Installation          *operatorv1.InstallationSpec
	TrustedCertBundle     certificatemanagement.TrustedBundleRO
	WhiskerKeyPair        certificatemanagement.KeyPairInterface
	WhiskerBackendKeyPair certificatemanagement.KeyPairInterface
	Whisker               *operatorv1.Whisker
	ClusterID             string
	CalicoVersion         string
	ClusterType           string
	ClusterDomain         string
}

type Component struct {
	cfg *Configuration

	whiskerImage string
	calicoImage  string
}

func (c *Component) ResolveImages(is *operatorv1.ImageSet) error {
	reg := c.cfg.Installation.Registry
	path := c.cfg.Installation.ImagePath
	prefix := c.cfg.Installation.ImagePrefix

	var err error

	c.whiskerImage, err = components.GetReference(components.ComponentCalicoWhisker, reg, path, prefix, is)
	if err != nil {
		return err
	}
	c.calicoImage, err = components.ReferenceFor(components.ImageKeyCalico, c.cfg.Installation, is)
	return err
}

func (c *Component) SupportedOSType() rmeta.OSType {
	return rmeta.OSTypeLinux
}

func (c *Component) Objects() ([]client.Object, []client.Object) {
	deployment := c.deployment()
	if overrides := c.cfg.Whisker.Spec.WhiskerDeployment; overrides != nil {
		rcomp.ApplyDeploymentOverrides(deployment, overrides)
	}

	toCreate := []client.Object{
		c.serviceAccount(),
		c.nginxConfigMap(),
		deployment,
		c.whiskerService(),
		c.networkPolicy(),
	}

	toCreate = append(toCreate, secret.ToRuntimeObjects(secret.CopyToNamespace(WhiskerNamespace, c.cfg.PullSecrets...)...)...)

	toDelete := c.deprecatedObjects()

	return toCreate, toDelete
}

func (c *Component) Ready() bool {
	return true
}

func (c *Component) serviceAccount() *corev1.ServiceAccount {
	return &corev1.ServiceAccount{
		TypeMeta:   metav1.TypeMeta{Kind: "ServiceAccount", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{Name: WhiskerServiceAccountName, Namespace: WhiskerNamespace},
	}
}

func (c *Component) whiskerContainer() corev1.Container {
	return corev1.Container{
		Name:  WhiskerContainerName,
		Image: c.whiskerImage,
		Env: []corev1.EnvVar{
			{Name: "LOG_LEVEL", Value: "INFO"},
			{Name: "CALICO_VERSION", Value: c.cfg.CalicoVersion},
			{Name: "CLUSTER_ID", Value: c.cfg.ClusterID},
			{Name: "CLUSTER_TYPE", Value: c.cfg.ClusterType},
			{Name: "NOTIFICATIONS", Value: string(*c.cfg.Whisker.Spec.Notifications)},
		},
		SecurityContext: securitycontext.NewNonRootContext(),
		VolumeMounts: []corev1.VolumeMount{
			{
				Name:      configVolumeName,
				MountPath: configMountPath,
				ReadOnly:  true,
			},
			c.cfg.WhiskerKeyPair.VolumeMount(c.SupportedOSType()),
		},
	}
}

func (c *Component) whiskerService() *corev1.Service {
	return &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "whisker",
			Namespace: WhiskerNamespace,
		},
		Spec: corev1.ServiceSpec{
			Ports: []corev1.ServicePort{{Port: WhiskerServicePort}},
			Selector: map[string]string{
				"k8s-app": WhiskerDeploymentName,
			},
		},
	}
}

func (c *Component) whiskerBackendContainer() corev1.Container {
	return corev1.Container{
		Name:    WhiskerBackendContainerName,
		Image:   c.calicoImage,
		Command: []string{components.CalicoBinaryPath, "component", "whisker-backend"},
		Env: []corev1.EnvVar{
			{Name: "LOG_LEVEL", Value: "INFO"},
			{Name: "PORT", Value: "3002"},
			{Name: "GOLDMANE_HOST", Value: fmt.Sprintf("goldmane.%s.svc.%s:7443", GoldmaneNamespace, c.cfg.ClusterDomain)},
			{Name: "TLS_CERT_PATH", Value: c.cfg.WhiskerBackendKeyPair.VolumeMountCertificateFilePath()},
			{Name: "TLS_KEY_PATH", Value: c.cfg.WhiskerBackendKeyPair.VolumeMountKeyFilePath()},
			{Name: "SERVER_TLS_CERT_PATH", Value: c.cfg.WhiskerBackendKeyPair.VolumeMountCertificateFilePath()},
			{Name: "SERVER_TLS_KEY_PATH", Value: c.cfg.WhiskerBackendKeyPair.VolumeMountKeyFilePath()},
		},
		SecurityContext: securitycontext.NewNonRootContext(),
		VolumeMounts: append(
			c.cfg.TrustedCertBundle.VolumeMounts(c.SupportedOSType()),
			c.cfg.WhiskerBackendKeyPair.VolumeMount(c.SupportedOSType())),
	}
}

func (c *Component) deployment() *appsv1.Deployment {
	tolerations := append(c.cfg.Installation.ControlPlaneTolerations, rmeta.TolerateCriticalAddonsAndControlPlane...)
	if c.cfg.Installation.KubernetesProvider.IsGKE() {
		tolerations = append(tolerations, rmeta.TolerateGKEARM64NoSchedule)
	}

	ctrs := []corev1.Container{c.whiskerContainer(), c.whiskerBackendContainer()}

	volumes := []corev1.Volume{
		// Add the trusted cert bundle volume to the pod.
		c.cfg.TrustedCertBundle.Volume(),

		// Add the whisker TLS key pair volume (used by nginx for HTTPS).
		c.cfg.WhiskerKeyPair.Volume(),

		// Add the whisker backend key pair volume to the pod.
		c.cfg.WhiskerBackendKeyPair.Volume(),

		// Volume for nginx config from config map.
		{
			Name: configVolumeName,
			VolumeSource: corev1.VolumeSource{
				ConfigMap: &corev1.ConfigMapVolumeSource{
					LocalObjectReference: corev1.LocalObjectReference{Name: configMapName},
				},
			},
		},
	}

	// Both key pairs are served at process startup (nginx and the backend), so
	// rotate the pod when either changes. The trusted bundle is only used by a
	// client that picks up changes without a restart.
	annotations := map[string]string{
		c.cfg.WhiskerKeyPair.HashAnnotationKey():        c.cfg.WhiskerKeyPair.HashAnnotationValue(),
		c.cfg.WhiskerBackendKeyPair.HashAnnotationKey(): c.cfg.WhiskerBackendKeyPair.HashAnnotationValue(),
	}

	return &appsv1.Deployment{
		TypeMeta: metav1.TypeMeta{Kind: "Deployment", APIVersion: "apps/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      WhiskerDeploymentName,
			Namespace: WhiskerNamespace,
		},
		Spec: appsv1.DeploymentSpec{
			Replicas: ptr.To(int32(1)),
			Strategy: appsv1.DeploymentStrategy{
				Type: appsv1.RecreateDeploymentStrategyType,
			},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Name:        WhiskerDeploymentName,
					Annotations: annotations,
				},
				Spec: corev1.PodSpec{
					NodeSelector:       c.cfg.Installation.ControlPlaneNodeSelector,
					ServiceAccountName: WhiskerServiceAccountName,
					Tolerations:        tolerations,
					ImagePullSecrets:   secret.GetReferenceList(c.cfg.PullSecrets),
					Containers:         ctrs,
					Volumes:            volumes,
				},
			},
		},
	}
}

func (c *Component) networkPolicy() *v3.NetworkPolicy {
	egressRules := []v3.Rule{
		{
			Action:   v3.Allow,
			Protocol: &networkpolicy.TCPProtocol,
			Destination: v3.EntityRule{
				Selector: networkpolicy.KubernetesAppSelector(GoldmaneDeploymentName),
				Ports:    networkpolicy.Ports(GoldmaneServicePort),
			},
		},
	}
	egressRules = networkpolicy.AppendDNSEgressRules(egressRules, c.cfg.OpenShift)

	return &v3.NetworkPolicy{
		TypeMeta:   metav1.TypeMeta{Kind: "NetworkPolicy", APIVersion: "projectcalico.org/v3"},
		ObjectMeta: metav1.ObjectMeta{Name: WhiskerPolicyName, Namespace: WhiskerNamespace},
		Spec: v3.NetworkPolicySpec{
			Order:    &networkpolicy.HighPrecedenceOrder,
			Tier:     networkpolicy.CalicoTierName,
			Types:    []v3.PolicyType{v3.PolicyTypeIngress, v3.PolicyTypeEgress},
			Selector: networkpolicy.KubernetesAppSelector(WhiskerDeploymentName),
			Egress:   egressRules,
		},
	}
}

func (c *Component) nginxConfigMap() *corev1.ConfigMap {
	// Determine which config to use based on supported IP families.
	config := NginxConfigV4
	if c.cfg.Installation.CalicoNetwork != nil && c.cfg.Installation.CalicoNetwork.NodeAddressAutodetectionV6 != nil {
		config = NginxConfigDual
	}

	return &corev1.ConfigMap{
		TypeMeta: metav1.TypeMeta{Kind: "ConfigMap", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      configMapName,
			Namespace: WhiskerNamespace,
		},
		Data: map[string]string{
			"default.conf": config,
		},
	}
}

// deprecatedObjects returns any objects that should be removed when Whisker is enabled, but were used in
// previous versions of the operator.
func (c *Component) deprecatedObjects() []client.Object {
	return []client.Object{
		// Deprecates k8s NetworkPolicy because Calico components now also have Tiers component enabled.
		&netv1.NetworkPolicy{
			TypeMeta:   metav1.TypeMeta{Kind: "NetworkPolicy", APIVersion: "networking.k8s.io/v1"},
			ObjectMeta: metav1.ObjectMeta{Name: "whisker", Namespace: WhiskerNamespace},
		},
	}
}
