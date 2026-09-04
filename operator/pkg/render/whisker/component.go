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
	"maps"

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
	"github.com/projectcalico/calico/operator/pkg/render/common/authentication"
	rcomp "github.com/projectcalico/calico/operator/pkg/render/common/components"
	rmeta "github.com/projectcalico/calico/operator/pkg/render/common/meta"
	"github.com/projectcalico/calico/operator/pkg/render/common/networkpolicy"
	"github.com/projectcalico/calico/operator/pkg/render/common/secret"
	"github.com/projectcalico/calico/operator/pkg/render/common/securitycontext"
	"github.com/projectcalico/calico/operator/pkg/render/common/selector"
	rgateway "github.com/projectcalico/calico/operator/pkg/render/gateway"
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

	// GatewayResourcePrefix names the CIG resources exposing Whisker.
	GatewayResourcePrefix = "calico-whisker"
	GatewayTLSSecretName  = "calico-whisker-gateway-tls"

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

	// BackendOnly deploys whisker-backend alone, for a variant that serves the UI
	// from another component and wires the backend to its own flow source: no UI
	// container, nginx config, UI Service or UI key pair, and no Goldmane wiring.
	// The controller sets it from RenderData.
	BackendOnly bool

	// Disabled deploys nothing and removes whatever an earlier configuration
	// deployed, whichever shape it had. The key pairs are nil in this mode; the
	// controller removes those itself. Set from RenderData.
	Disabled bool

	// KeyValidatorConfig lets whisker-backend verify the user tokens its caller
	// forwards. Only its environment and annotations apply: the backend fetches
	// the provider's keys over the network, trusting the CA in the bundle, and
	// never reads the files a browser-facing server would mount. Set from
	// RenderData; nil when the caller forwards no tokens.
	KeyValidatorConfig authentication.KeyValidatorConfig

	// IngressGatewayNamespace, when non-empty, is the namespace of the CIG
	// Envoy proxy that fronts Whisker. The NetworkPolicy gains a scoped
	// ingress rule from those proxy pods; Whisker is deny-all otherwise.
	IngressGatewayNamespace string
}

// RenderData is what a variant's extension hands the whisker controller through
// render.Inputs.Extension. It lives in render so the controller can read it
// generically. Absent means the core path: whisker serves its own UI and reads
// flows from Goldmane.
type RenderData struct {
	// BackendOnly deploys whisker-backend alone. The variant serves the UI from
	// another component and wires the backend to its own flow source through its
	// modifier, so Goldmane is neither required nor trusted.
	BackendOnly bool

	// Disabled deploys nothing here and removes what an earlier reconcile
	// deployed. A variant sets it where another cluster serves these flow logs,
	// or where it does not support whisker at all.
	Disabled bool

	// KeyValidatorConfig lets whisker-backend verify the user tokens its caller
	// forwards. Nil when the caller forwards none.
	KeyValidatorConfig authentication.KeyValidatorConfig
}

// RenderDataFromInputs returns the RenderData a controller extension stashed in
// the render inputs, and whether it was present.
func RenderDataFromInputs(ri render.Inputs) (RenderData, bool) {
	data, ok := ri.Extension.(RenderData)
	return data, ok
}

type Component struct {
	cfg *Configuration

	whiskerImage string
	calicoImage  string
}

// Config returns the configuration the component renders from, for a variant's
// modifier.
func (c *Component) Config() *Configuration {
	return c.cfg
}

func (c *Component) ResolveImages(is *operatorv1.ImageSet) error {
	if c.cfg.Disabled {
		return nil
	}
	reg := c.cfg.Installation.Registry
	path := c.cfg.Installation.ImagePath
	prefix := c.cfg.Installation.ImagePrefix

	var err error

	if !c.cfg.BackendOnly {
		c.whiskerImage, err = components.GetReference(components.ComponentCalicoWhisker, reg, path, prefix, is)
		if err != nil {
			return err
		}
	}
	c.calicoImage, err = components.ReferenceFor(components.ImageKeyCalico, c.cfg.Installation, is)
	return err
}

func (c *Component) SupportedOSType() rmeta.OSType {
	return rmeta.OSTypeLinux
}

func (c *Component) Objects() ([]client.Object, []client.Object) {
	if c.cfg.Disabled {
		return nil, c.everything()
	}

	deployment := c.deployment()
	if overrides := c.cfg.Whisker.Spec.WhiskerDeployment; overrides != nil {
		rcomp.ApplyDeploymentOverrides(deployment, overrides)
	}

	toCreate := []client.Object{c.serviceAccount()}
	toDelete := c.deprecatedObjects()

	// The nginx config and Service front the UI. Without the UI they are removed:
	// the Whisker CR that owns them still exists, so GC would not.
	if c.cfg.BackendOnly {
		toCreate = append(toCreate, deployment, c.networkPolicy())
		toDelete = append(toDelete, c.nginxConfigMap(), c.whiskerService())
	} else {
		toCreate = append(toCreate, c.nginxConfigMap(), deployment, c.whiskerService(), c.networkPolicy())
	}

	toCreate = append(toCreate, secret.ToRuntimeObjects(secret.CopyToNamespace(WhiskerNamespace, c.cfg.PullSecrets...)...)...)

	return toCreate, toDelete
}

// everything is what any configuration of whisker may have deployed, named for
// deletion. The pull secret copies are not here: other components in the
// namespace share them.
func (c *Component) everything() []client.Object {
	return append(c.deprecatedObjects(),
		c.serviceAccount(),
		&appsv1.Deployment{
			TypeMeta:   metav1.TypeMeta{Kind: "Deployment", APIVersion: "apps/v1"},
			ObjectMeta: metav1.ObjectMeta{Name: WhiskerDeploymentName, Namespace: WhiskerNamespace},
		},
		c.nginxConfigMap(),
		c.whiskerService(),
		&v3.NetworkPolicy{
			TypeMeta:   metav1.TypeMeta{Kind: "NetworkPolicy", APIVersion: "projectcalico.org/v3"},
			ObjectMeta: metav1.ObjectMeta{Name: WhiskerPolicyName, Namespace: WhiskerNamespace},
		},
	)
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
	env := []corev1.EnvVar{
		{Name: "LOG_LEVEL", Value: "INFO"},
		{Name: "PORT", Value: "3002"},
	}
	if !c.cfg.BackendOnly {
		env = append(env, corev1.EnvVar{Name: "GOLDMANE_HOST", Value: fmt.Sprintf("goldmane.%s.svc.%s:7443", GoldmaneNamespace, c.cfg.ClusterDomain)})
	}
	env = append(env,
		corev1.EnvVar{Name: "TLS_CERT_PATH", Value: c.cfg.WhiskerBackendKeyPair.VolumeMountCertificateFilePath()},
		corev1.EnvVar{Name: "TLS_KEY_PATH", Value: c.cfg.WhiskerBackendKeyPair.VolumeMountKeyFilePath()},
		corev1.EnvVar{Name: "SERVER_TLS_CERT_PATH", Value: c.cfg.WhiskerBackendKeyPair.VolumeMountCertificateFilePath()},
		corev1.EnvVar{Name: "SERVER_TLS_KEY_PATH", Value: c.cfg.WhiskerBackendKeyPair.VolumeMountKeyFilePath()},
	)

	if c.cfg.KeyValidatorConfig != nil {
		env = append(env, c.cfg.KeyValidatorConfig.RequiredEnv("")...)
	}

	return corev1.Container{
		Name:            WhiskerBackendContainerName,
		Image:           c.calicoImage,
		Command:         []string{components.CalicoBinaryPath, "component", "whisker-backend"},
		Env:             env,
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

	ctrs := []corev1.Container{c.whiskerBackendContainer()}

	// The trusted cert bundle, then what each container serves from, in the order
	// the pod mounts them.
	volumes := []corev1.Volume{c.cfg.TrustedCertBundle.Volume()}
	if !c.cfg.BackendOnly {
		ctrs = append([]corev1.Container{c.whiskerContainer()}, ctrs...)
		// The whisker TLS key pair, used by nginx for HTTPS.
		volumes = append(volumes, c.cfg.WhiskerKeyPair.Volume())
	}
	volumes = append(volumes, c.cfg.WhiskerBackendKeyPair.Volume())
	if !c.cfg.BackendOnly {
		volumes = append(volumes, c.nginxConfigVolume())
	}

	// Key pairs are served at process startup, so rotate the pod when one
	// changes. Whisker's own Goldmane client reloads the trusted bundle as it
	// changes; another flow source's client may hold it for the life of the
	// process, so the backend-only pod is rolled when the bundle changes too.
	annotations := map[string]string{
		c.cfg.WhiskerBackendKeyPair.HashAnnotationKey(): c.cfg.WhiskerBackendKeyPair.HashAnnotationValue(),
	}
	if c.cfg.BackendOnly {
		maps.Copy(annotations, c.cfg.TrustedCertBundle.HashAnnotations())
	} else {
		annotations[c.cfg.WhiskerKeyPair.HashAnnotationKey()] = c.cfg.WhiskerKeyPair.HashAnnotationValue()
	}
	if c.cfg.KeyValidatorConfig != nil {
		maps.Copy(annotations, c.cfg.KeyValidatorConfig.RequiredAnnotations())
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
	var egressRules []v3.Rule
	if !c.cfg.BackendOnly {
		egressRules = append(egressRules, v3.Rule{
			Action:   v3.Allow,
			Protocol: &networkpolicy.TCPProtocol,
			Destination: v3.EntityRule{
				Selector: networkpolicy.KubernetesAppSelector(GoldmaneDeploymentName),
				Ports:    networkpolicy.Ports(GoldmaneServicePort),
			},
		})
	}
	egressRules = networkpolicy.AppendDNSEgressRules(egressRules, c.cfg.OpenShift)

	var ingressRules []v3.Rule
	if c.cfg.IngressGatewayNamespace != "" {
		// Envoy Gateway labels its proxy pods with the owning Gateway name.
		ingressRules = append(ingressRules, v3.Rule{
			Action:   v3.Allow,
			Protocol: &networkpolicy.TCPProtocol,
			Source: v3.EntityRule{
				NamespaceSelector: fmt.Sprintf("%s == '%s'", selector.CalicoNameLabel, c.cfg.IngressGatewayNamespace),
				Selector:          fmt.Sprintf("gateway.envoyproxy.io/owning-gateway-name == '%s'", rgateway.GatewayName(GatewayResourcePrefix)),
			},
			Destination: v3.EntityRule{
				Ports: networkpolicy.Ports(WhiskerServicePort),
			},
		})
	}

	return &v3.NetworkPolicy{
		TypeMeta:   metav1.TypeMeta{Kind: "NetworkPolicy", APIVersion: "projectcalico.org/v3"},
		ObjectMeta: metav1.ObjectMeta{Name: WhiskerPolicyName, Namespace: WhiskerNamespace},
		Spec: v3.NetworkPolicySpec{
			Order:    &networkpolicy.HighPrecedenceOrder,
			Tier:     networkpolicy.CalicoTierName,
			Types:    []v3.PolicyType{v3.PolicyTypeIngress, v3.PolicyTypeEgress},
			Selector: networkpolicy.KubernetesAppSelector(WhiskerDeploymentName),
			Ingress:  ingressRules,
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

func (c *Component) nginxConfigVolume() corev1.Volume {
	return corev1.Volume{
		Name: configVolumeName,
		VolumeSource: corev1.VolumeSource{
			ConfigMap: &corev1.ConfigMapVolumeSource{
				LocalObjectReference: corev1.LocalObjectReference{Name: configMapName},
			},
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
