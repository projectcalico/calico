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

package istio

import (
	"fmt"
	"strconv"
	"strings"

	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	"github.com/tigera/api/pkg/lib/numorstring"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	operatorv1 "github.com/projectcalico/calico/operator/api/v1"
	"github.com/projectcalico/calico/operator/pkg/common"
	"github.com/projectcalico/calico/operator/pkg/components"
	"github.com/projectcalico/calico/operator/pkg/render"
	rcomp "github.com/projectcalico/calico/operator/pkg/render/common/components"
	rmeta "github.com/projectcalico/calico/operator/pkg/render/common/meta"
	"github.com/projectcalico/calico/operator/pkg/render/common/networkpolicy"
	"github.com/projectcalico/calico/operator/pkg/render/common/secret"
)

type Configuration struct {
	Installation   *operatorv1.InstallationSpec
	PullSecrets    []*corev1.Secret
	Istio          *operatorv1.Istio
	IstioNamespace string
	Scheme         *runtime.Scheme
}

var _ render.Component = &IstioComponent{}

type IstioComponent struct {
	cfg                  *Configuration
	IstioPilotImage      string
	IstioInstallCNIImage string
	IstioZTunnelImage    string
	IstioProxyv2Image    string

	resources *IstioResources
}

type IstioComponentCRDs struct {
	resources *IstioResources
}

const (
	IstioNamespace                    = common.CalicoNamespace
	IstioReleaseName                  = "calico-istio"
	IstioIstiodDeploymentName         = "istiod"
	IstioCNIDaemonSetName             = "istio-cni-node"
	IstioZTunnelDaemonSetName         = "ztunnel"
	IstioSidecarInjectorConfigMapName = "istio-sidecar-injector"
	IstioOperatorAnnotationMode       = "operator.tigera.io/istioAmbientMode"
	IstioOperatorAnnotationDSCP       = "operator.tigera.io/istioDSCPMark"
	IstioFinalizer                    = "operator.tigera.io/calico-istio"
	IstioIstiodPolicyName             = networkpolicy.CalicoComponentPolicyPrefix + IstioIstiodDeploymentName
	IstioCNIPolicyName                = networkpolicy.CalicoComponentPolicyPrefix + IstioCNIDaemonSetName
	IstioZTunnelPolicyName            = networkpolicy.CalicoComponentPolicyPrefix + IstioZTunnelDaemonSetName
	IstioIstiodServiceName            = "istiod"

	istioFakeImageProxyv2 = "fake.io/fakeimg/proxyv2:faketag"
)

// Component names, which key the image overrides a variant resolves through.
const (
	ComponentNamePilot      = "istio-pilot"
	ComponentNameInstallCNI = "istio-install-cni"
	ComponentNameZTunnel    = "istio-ztunnel"
	ComponentNameProxyv2    = "istio-proxyv2"
)

// ConfiguredComponent is the istio component, exposed so a variant extension can
// reach the config it rendered from.
type ConfiguredComponent interface {
	render.Component
	GetConfig() *Configuration
}

func Istio(cfg *Configuration) (*IstioComponentCRDs, *IstioComponent, error) {
	// Produce Helm templates for Istio
	istioResOpts := &ResourceOpts{
		Namespace:                 IstioNamespace,
		ReleaseName:               IstioReleaseName,
		IstiodDeploymentName:      IstioIstiodDeploymentName,
		IstioCNIDaemonSetName:     IstioCNIDaemonSetName,
		IstioZTunnelDaemonSetName: IstioZTunnelDaemonSetName,

		// Helm chart opts
		BaseOpts: BaseOpts{
			Global: &GlobalConfig{
				IstioNamespace: IstioNamespace,
			},
		},
		IstiodOpts: IstiodOpts{
			Global: &GlobalConfig{
				IstioNamespace:         IstioNamespace,
				OperatorManageWebhooks: true,
				Proxy: &ProxyConfig{
					Image: istioFakeImageProxyv2,
				},
				ProxyInit: &ProxyInitConfig{
					Image: istioFakeImageProxyv2,
				},
			},
			Gateways: &GatewaysConfig{
				SeccompProfile: &corev1.SeccompProfile{
					Type: corev1.SeccompProfileTypeRuntimeDefault,
				},
			},
			Profile:                 "ambient",
			TrustedZtunnelNamespace: IstioNamespace,
		},
		IstioCNIOpts: IstioCNIOpts{
			Global: &GlobalConfig{
				IstioNamespace: IstioNamespace,
			},
			Ambient: &AmbientConfig{
				Enabled:                    true,
				ReconcileIptablesOnStartup: true,
			},
		},
		ZTunnelOpts: ZTunnelOpts{
			Global: &GlobalConfig{
				IstioNamespace: IstioNamespace,
			},
		},
	}
	// Pass imagePullSecrets to istiod so it injects them into waypoint pod specs.
	if len(cfg.PullSecrets) > 0 {
		secretNames := make([]string, 0, len(cfg.PullSecrets))
		for _, s := range cfg.PullSecrets {
			secretNames = append(secretNames, s.Name)
		}
		istioResOpts.IstiodOpts.Global.ImagePullSecrets = secretNames
	}

	// Set platform on all charts that have platform-specific behavior.
	// The embedded Helm charts use zzz_profile.yaml to load platform profiles
	// (e.g., profile-platform-openshift.yaml) which configure CNI paths, SCC
	// RBAC rules, SELinux options, and sidecar injection settings.
	if cfg.Installation.KubernetesProvider.IsGKE() {
		istioResOpts.IstioCNIOpts.Global.Platform = "gke"
		istioResOpts.IstiodOpts.Global.Platform = "gke"
		istioResOpts.ZTunnelOpts.Global.Platform = "gke"
	}
	if cfg.Installation.KubernetesProvider.IsOpenShift() {
		istioResOpts.IstioCNIOpts.Global.Platform = "openshift"
		istioResOpts.IstiodOpts.Global.Platform = "openshift"
		istioResOpts.ZTunnelOpts.Global.Platform = "openshift"
	}
	resources, err := istioResOpts.GetResources(cfg.Scheme)
	if err != nil {
		return nil, nil, err
	}

	crds := &IstioComponentCRDs{resources: resources}
	istio := &IstioComponent{cfg: cfg, resources: resources}
	return crds, istio, nil
}

func (c *IstioComponent) patchImages() (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("failed to patch Images with panic value: %v", r)
		}
	}()

	for i := range c.resources.IstiodDeployment.Spec.Template.Spec.Containers {
		container := &c.resources.IstiodDeployment.Spec.Template.Spec.Containers[i]
		if container.Name == "discovery" {
			container.Image = c.IstioPilotImage
		}
	}
	for i := range c.resources.CNIDaemonSet.Spec.Template.Spec.Containers {
		container := &c.resources.CNIDaemonSet.Spec.Template.Spec.Containers[i]
		if container.Name == "install-cni" {
			container.Image = c.IstioInstallCNIImage
		}
	}
	for i := range c.resources.ZTunnelDaemonSet.Spec.Template.Spec.Containers {
		container := &c.resources.ZTunnelDaemonSet.Spec.Template.Spec.Containers[i]
		if container.Name == "istio-proxy" {
			container.Image = c.IstioZTunnelImage
		}
	}
	mapData := c.resources.IstioSidecarInjectorConfigMap.Data
	for k, v := range mapData {
		mapData[k] = strings.ReplaceAll(v, istioFakeImageProxyv2, c.IstioProxyv2Image)
	}
	return nil
}

func (c *IstioComponent) ResolveImages(is *operatorv1.ImageSet) error {
	var err error

	in := c.cfg.Installation

	c.IstioPilotImage, err = components.ReferenceFor(components.ImageKeyIstioPilot, in, is)
	if err != nil {
		return err
	}
	c.IstioInstallCNIImage, err = components.ReferenceFor(components.ImageKeyIstioInstallCNI, in, is)
	if err != nil {
		return err
	}
	c.IstioZTunnelImage, err = components.ReferenceFor(components.ImageKeyIstioZTunnel, in, is)
	if err != nil {
		return err
	}
	c.IstioProxyv2Image, err = components.ReferenceFor(components.ImageKeyIstioProxyv2, in, is)
	if err != nil {
		return err
	}

	if err = c.patchImages(); err != nil {
		return err
	}

	return nil
}

// Objects implements the Component interface.
func (c *IstioComponent) Objects() ([]client.Object, []client.Object) {
	res := c.resources

	var objs, toDelete []client.Object
	objs = append(objs,
		c.istiodCalicoSystemPolicy(),
		c.istioCNICalicoSystemPolicy(),
		c.ztunnelCalicoSystemPolicy(),
	)
	// allow-tigera Tier was renamed to calico-system
	toDelete = append(toDelete,
		networkpolicy.DeprecatedAllowTigeraNetworkPolicyObject("istiod", IstioNamespace),
		networkpolicy.DeprecatedAllowTigeraNetworkPolicyObject("istio-cni-node", IstioNamespace),
		networkpolicy.DeprecatedAllowTigeraNetworkPolicyObject("ztunnel", IstioNamespace),
	)

	if overrides := c.cfg.Istio.Spec.IstiodDeployment; overrides != nil {
		rcomp.ApplyDeploymentOverrides(res.IstiodDeployment, overrides)
	}

	if overrides := c.cfg.Istio.Spec.IstioCNIDaemonset; overrides != nil {
		rcomp.ApplyDaemonSetOverrides(res.CNIDaemonSet, overrides)
	}

	if overrides := c.cfg.Istio.Spec.ZTunnelDaemonset; overrides != nil {
		rcomp.ApplyDaemonSetOverrides(res.ZTunnelDaemonSet, overrides)
	}

	// Set required configs
	for i := range res.ZTunnelDaemonSet.Spec.Template.Spec.Containers {
		cont := &res.ZTunnelDaemonSet.Spec.Template.Spec.Containers[i]
		if cont.Name == "istio-proxy" {
			cont.Env = append(cont.Env, corev1.EnvVar{
				Name:  "TRANSPARENT_NETWORK_POLICIES",
				Value: "true",
			})
			break
		}
	}
	for i := range res.CNIDaemonSet.Spec.Template.Spec.Containers {
		cont := &res.CNIDaemonSet.Spec.Template.Spec.Containers[i]
		if cont.Name == "install-cni" {
			cont.Env = append(cont.Env, corev1.EnvVar{
				Name:  "MAGIC_DSCP_MARK",
				Value: strconv.FormatInt(int64(c.cfg.Istio.Spec.DSCPMark.ToUint8()), 10),
			})
		}
	}

	// Set additional pull secrets
	res.IstiodDeployment.Spec.Template.Spec.ImagePullSecrets = append(
		res.IstiodDeployment.Spec.Template.Spec.ImagePullSecrets,
		secret.GetReferenceList(c.cfg.PullSecrets)...,
	)
	res.CNIDaemonSet.Spec.Template.Spec.ImagePullSecrets = append(
		res.CNIDaemonSet.Spec.Template.Spec.ImagePullSecrets,
		secret.GetReferenceList(c.cfg.PullSecrets)...,
	)
	res.ZTunnelDaemonSet.Spec.Template.Spec.ImagePullSecrets = append(
		res.ZTunnelDaemonSet.Spec.Template.Spec.ImagePullSecrets,
		secret.GetReferenceList(c.cfg.PullSecrets)...,
	)

	// Append Istio resources in order: Base, Istiod, CNI, ZTunnel
	// This mimics the order from the documentation
	objs = append(objs, res.Base...)
	objs = append(objs, res.Istiod...)
	objs = append(objs, res.CNI...)
	objs = append(objs, res.ZTunnel...)

	return objs, toDelete
}

// GetConfig implements ConfiguredComponent.
func (c *IstioComponent) GetConfig() *Configuration {
	return c.cfg
}

func (c *IstioComponent) Ready() bool {
	return true
}

func (c *IstioComponent) SupportedOSType() rmeta.OSType {
	return rmeta.OSTypeLinux
}

func (c *IstioComponent) istiodCalicoSystemPolicy() *v3.NetworkPolicy {
	egressRules := []v3.Rule{
		{
			Action:      v3.Allow,
			Protocol:    &networkpolicy.TCPProtocol,
			Destination: networkpolicy.KubeAPIServerEntityRule,
		},
	}

	// * Port 15012, gRPC, XDS and CA services (TLS and mTLS)
	//   ztunnel and waypoints connect to it to request certs and dataplane
	//   info.
	// * Port 15017, https, Webhook container port
	//   used for config validation.
	ingressRules := []v3.Rule{
		{
			Action:   v3.Allow,
			Protocol: &networkpolicy.TCPProtocol,
			Destination: v3.EntityRule{
				Ports: []numorstring.Port{
					numorstring.SinglePort(15012),
					numorstring.SinglePort(15017),
				},
			},
		},
	}

	return &v3.NetworkPolicy{
		TypeMeta: metav1.TypeMeta{Kind: "NetworkPolicy", APIVersion: "projectcalico.org/v3"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      IstioIstiodPolicyName,
			Namespace: c.cfg.IstioNamespace,
		},
		Spec: v3.NetworkPolicySpec{
			Tier:     networkpolicy.CalicoTierName,
			Selector: networkpolicy.KubernetesAppSelector(IstioIstiodDeploymentName),
			Types:    []v3.PolicyType{v3.PolicyTypeIngress, v3.PolicyTypeEgress},
			Ingress:  ingressRules,
			Egress:   egressRules,
		},
	}
}

func (c *IstioComponent) istioCNICalicoSystemPolicy() *v3.NetworkPolicy {
	egressRules := []v3.Rule{
		{
			Action:      v3.Allow,
			Protocol:    &networkpolicy.TCPProtocol,
			Destination: networkpolicy.KubeAPIServerEntityRule,
		},
	}

	return &v3.NetworkPolicy{
		TypeMeta: metav1.TypeMeta{Kind: "NetworkPolicy", APIVersion: "projectcalico.org/v3"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      IstioCNIPolicyName,
			Namespace: c.cfg.IstioNamespace,
		},
		Spec: v3.NetworkPolicySpec{
			Tier:     networkpolicy.CalicoTierName,
			Selector: networkpolicy.KubernetesAppSelector(IstioCNIDaemonSetName),
			Types:    []v3.PolicyType{v3.PolicyTypeIngress, v3.PolicyTypeEgress},
			Egress:   egressRules,
		},
	}
}

func (c *IstioComponent) ztunnelCalicoSystemPolicy() *v3.NetworkPolicy {
	egressRules := []v3.Rule{
		{
			Action:      v3.Allow,
			Protocol:    &networkpolicy.TCPProtocol,
			Destination: networkpolicy.CreateServiceSelectorEntityRule(c.cfg.IstioNamespace, IstioIstiodServiceName),
		},
	}
	egressRules = networkpolicy.AppendDNSEgressRules(egressRules, c.cfg.Installation.KubernetesProvider.IsOpenShift())

	return &v3.NetworkPolicy{
		TypeMeta: metav1.TypeMeta{Kind: "NetworkPolicy", APIVersion: "projectcalico.org/v3"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      IstioZTunnelPolicyName,
			Namespace: c.cfg.IstioNamespace,
		},
		Spec: v3.NetworkPolicySpec{
			Tier:     networkpolicy.CalicoTierName,
			Selector: networkpolicy.KubernetesAppSelector(IstioZTunnelDaemonSetName),
			Types:    []v3.PolicyType{v3.PolicyTypeIngress, v3.PolicyTypeEgress},
			Egress:   egressRules,
		},
	}
}

func (c *IstioComponentCRDs) Objects() ([]client.Object, []client.Object) {
	return c.resources.CRDs, nil
}

func (c *IstioComponentCRDs) Ready() bool {
	return true
}

func (c *IstioComponentCRDs) ResolveImages(is *operatorv1.ImageSet) error {
	return nil
}

func (c *IstioComponentCRDs) SupportedOSType() rmeta.OSType {
	return rmeta.OSTypeLinux
}
