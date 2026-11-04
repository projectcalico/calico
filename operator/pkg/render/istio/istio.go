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
	"crypto/x509"
	"fmt"
	"strconv"
	"strings"

	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	"github.com/projectcalico/api/pkg/lib/numorstring"
	appsv1 "k8s.io/api/apps/v1"
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
	ClusterID      string

	// Live is nil when nothing should wait for istiod, for example on a new
	// install.
	Live *LiveWorkloads

	// LocalCA is the CA istiod signs with in this render. Nil renders no cacerts
	// Secret, which leaves the one already in the cluster untouched.
	LocalCA *CA
	// CASource labels the rendered cacerts with where LocalCA came from.
	CASource CASource
	// Transition is the signer change in progress, nil outside one. Its roots
	// join root-cert.pem and the published roots, and its phase is recorded on
	// cacerts so the controller resumes it after a restart.
	Transition *SignerTransition
	// OwnRoots are the roots published for peers when LocalCA is nil; with a
	// LocalCA its own roots are published.
	OwnRoots []*x509.Certificate
	// CurrentCACerts is the cacerts Secret already in the cluster. When LocalCA is
	// nil it keeps the istiod roll hash stable.
	CurrentCACerts *corev1.Secret
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

	istiodContainerName   = "discovery"
	istioCNIContainerName = "install-cni"
	ztunnelContainerName  = "istio-proxy"
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

// legacyClusterID is the cluster ID the Istio charts default to.
const legacyClusterID = "Kubernetes"

func Istio(cfg *Configuration) (*IstioComponentCRDs, *IstioComponent, error) {
	if cfg.ClusterID == "" {
		return nil, nil, fmt.Errorf("istio cluster ID must not be empty")
	}
	multiCluster := &MultiClusterConfig{ClusterName: cfg.ClusterID}

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
				MultiCluster:   multiCluster,
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
				MultiCluster: multiCluster,
			},
			Gateways: &GatewaysConfig{
				SeccompProfile: &corev1.SeccompProfile{
					Type: corev1.SeccompProfileTypeRuntimeDefault,
				},
			},
			// root-cert.pem carries two roots during a signer transition; istiod
			// only accepts such a bundle as a multi-root mesh.
			Pilot:                   &PilotConfig{Env: map[string]string{"ISTIO_MULTIROOT_MESH": "true"}},
			Profile:                 "ambient",
			TrustedZtunnelNamespace: IstioNamespace,
			// Pods injected under the chart default cluster ID keep it until they
			// restart. Without the alias istiod rejects their certificate requests
			// and finds no services for them.
			ExtraContainerArgs: []string{fmt.Sprintf("--clusterAliases=%s=%s", legacyClusterID, cfg.ClusterID)},
		},
		IstioCNIOpts: IstioCNIOpts{
			Global: &GlobalConfig{
				IstioNamespace: IstioNamespace,
				MultiCluster:   multiCluster,
			},
			Ambient: &AmbientConfig{
				Enabled:                    true,
				ReconcileIptablesOnStartup: true,
			},
		},
		ZTunnelOpts: ZTunnelOpts{
			Global: &GlobalConfig{
				IstioNamespace: IstioNamespace,
				MultiCluster:   multiCluster,
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
	// The nested cni key is required: the chart copies the profile's cni.cniBinDir
	// over the top-level cniBinDir when it descopes legacy values.
	if binDir := cniBinDir(cfg.Installation); binDir != "" {
		istioResOpts.IstioCNIOpts.CNI = &CNIConfig{CNIBinDir: binDir}
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
		if container.Name == istiodContainerName {
			container.Image = c.IstioPilotImage
		}
	}
	for i := range c.resources.CNIDaemonSet.Spec.Template.Spec.Containers {
		container := &c.resources.CNIDaemonSet.Spec.Template.Spec.Containers[i]
		if container.Name == istioCNIContainerName {
			container.Image = c.IstioInstallCNIImage
		}
	}
	for i := range c.resources.ZTunnelDaemonSet.Spec.Template.Spec.Containers {
		container := &c.resources.ZTunnelDaemonSet.Spec.Template.Spec.Containers[i]
		if container.Name == ztunnelContainerName {
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
	return render.ObjectsWithOverrides(c)
}

var _ render.Overridable = (*IstioComponent)(nil)

func (c *IstioComponent) OverrideTargets() []rcomp.OverrideTarget {
	res := c.resources
	return []rcomp.OverrideTarget{
		rcomp.Target[*appsv1.Deployment](res.IstiodDeployment.Namespace, res.IstiodDeployment.Name, c.cfg.Istio.Spec.IstiodDeployment),
		rcomp.Target[*appsv1.DaemonSet](res.CNIDaemonSet.Namespace, res.CNIDaemonSet.Name, c.cfg.Istio.Spec.IstioCNIDaemonset),
		rcomp.Target[*appsv1.DaemonSet](res.ZTunnelDaemonSet.Namespace, res.ZTunnelDaemonSet.Name, c.cfg.Istio.Spec.ZTunnelDaemonset),
	}
}

func (c *IstioComponent) ObjectsBeforeOverrides() ([]client.Object, []client.Object) {
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

	// Set required configs
	for i := range res.ZTunnelDaemonSet.Spec.Template.Spec.Containers {
		cont := &res.ZTunnelDaemonSet.Spec.Template.Spec.Containers[i]
		if cont.Name == ztunnelContainerName {
			cont.Env = append(cont.Env, ztunnelEnv()...)
			break
		}
	}
	for i := range res.CNIDaemonSet.Spec.Template.Spec.Containers {
		cont := &res.CNIDaemonSet.Spec.Template.Spec.Containers[i]
		if cont.Name == istioCNIContainerName {
			cont.Env = append(cont.Env, corev1.EnvVar{
				Name:  "MAGIC_DSCP_MARK",
				Value: strconv.FormatInt(int64(c.cfg.Istio.Spec.DSCPMark.ToUint8()), 10),
			})
		}
	}

	// The Istio CR's resources field sits at pod level, so the shared override
	// path can't place it. Each workload has one main container to receive it.
	setContainerResources(&res.IstiodDeployment.Spec.Template.Spec, istiodContainerName, rcomp.GetResources(c.cfg.Istio.Spec.IstiodDeployment))
	setContainerResources(&res.CNIDaemonSet.Spec.Template.Spec, istioCNIContainerName, rcomp.GetResources(c.cfg.Istio.Spec.IstioCNIDaemonset))
	setContainerResources(&res.ZTunnelDaemonSet.Spec.Template.Spec, ztunnelContainerName, rcomp.GetResources(c.cfg.Istio.Spec.ZTunnelDaemonset))

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

	// cacerts is only ever replaced by a bundle that validated in full; without a
	// local CA the cluster's current Secret stays, and the hash it carries keeps
	// istiod from rolling.
	cacerts := c.cfg.CurrentCACerts
	if c.cfg.LocalCA != nil {
		cacerts = c.cacertsSecret()
		objs = append(objs, cacerts)
	}
	if cacerts != nil {
		template := &res.IstiodDeployment.Spec.Template
		if template.Annotations == nil {
			template.Annotations = map[string]string{}
		}
		template.Annotations[CACertsHashAnnotation] = rmeta.SecretsAnnotationHash(cacerts)
	}
	if roots := c.ownRoots(); len(roots) > 0 {
		objs = append(objs, c.trustAnchorsConfigMap(roots))
	}

	// Append Istio resources in order: Base, Istiod, CNI, ZTunnel
	// This mimics the order from the documentation
	objs = append(objs, res.Base...)
	objs = append(objs, res.Istiod...)
	objs = append(objs, c.dataPlaneObjects()...)

	return objs, toDelete
}

// ztunnelEnv is the environment the operator sets on ztunnel beyond the chart's.
func ztunnelEnv() []corev1.EnvVar {
	return []corev1.EnvVar{
		{Name: "TRANSPARENT_NETWORK_POLICIES", Value: "true"},
	}
}

// cacertsSecret renders the plug-in CA bundle istiod signs with. root-cert.pem
// holds every root this cluster trusts, the two signers' during a transition;
// the private key never leaves it. The transition annotations ride on the
// Secret and not in its data, so a phase that only starts a clock leaves the
// data hash, and with it istiod, alone.
func (c *IstioComponent) cacertsSecret() *corev1.Secret {
	ca := c.cfg.LocalCA
	source := c.cfg.CASource
	if source == "" {
		source = CASourceOperatorManaged
	}
	return &corev1.Secret{
		TypeMeta: metav1.TypeMeta{Kind: "Secret", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:        CACertsSecretName,
			Namespace:   c.cfg.IstioNamespace,
			Labels:      map[string]string{CACertsLabel: string(source)},
			Annotations: c.cfg.Transition.annotations(),
		},
		Type: corev1.SecretTypeOpaque,
		Data: map[string][]byte{
			CACertKey:    ca.CertPEM,
			CAKeyKey:     ca.KeyPEM,
			CertChainKey: EncodeCertificates(ca.Chain...),
			RootCertKey:  ComposeRootBundle(ca.Roots, c.cfg.Transition.roots()),
		},
	}
}

// IstiodRolledOut reports whether every istiod replica serves the given
// cacerts: the pod template carries its hash, the Deployment controller has
// observed that template, and the rollout is complete by the rule kubectl
// rollout status applies, with at least one replica available to answer
// ztunnel. A render is a request to roll; only this says the roll happened.
func IstiodRolledOut(d *appsv1.Deployment, cacerts *corev1.Secret) bool {
	if d == nil || cacerts == nil {
		return false
	}
	if d.Spec.Template.Annotations[CACertsHashAnnotation] != rmeta.SecretsAnnotationHash(cacerts) {
		return false
	}
	if d.Generation > d.Status.ObservedGeneration {
		return false
	}
	replicas := int32(1)
	if d.Spec.Replicas != nil {
		replicas = *d.Spec.Replicas
	}
	s := d.Status
	return s.UpdatedReplicas >= replicas &&
		s.Replicas == s.UpdatedReplicas &&
		s.AvailableReplicas >= s.UpdatedReplicas &&
		s.AvailableReplicas > 0
}

// ownRoots are the roots this cluster publishes: those its signing CA chains
// to and, during a transition, the other signer's, so other clusters accept
// certificates from both.
func (c *IstioComponent) ownRoots() []*x509.Certificate {
	if c.cfg.LocalCA != nil {
		return append(append([]*x509.Certificate{}, c.cfg.LocalCA.Roots...), c.cfg.Transition.roots()...)
	}
	return c.cfg.OwnRoots
}

func (c *IstioComponent) trustAnchorsConfigMap(roots []*x509.Certificate) *corev1.ConfigMap {
	return &corev1.ConfigMap{
		TypeMeta: metav1.TypeMeta{Kind: "ConfigMap", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      TrustAnchorsConfigMapName,
			Namespace: c.cfg.IstioNamespace,
		},
		Data: map[string]string{
			RootCertKey:    string(ComposeRootBundle(roots)),
			TrustDomainKey: DefaultTrustDomain,
		},
	}
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

// setContainerResources replaces the resources of the named container with r.
// A nil r leaves the Helm chart's defaults in place.
func setContainerResources(spec *corev1.PodSpec, name string, r *corev1.ResourceRequirements) {
	if r == nil {
		return
	}
	render.MustContainer(spec, name).Resources = *r
}

func cniBinDir(installation *operatorv1.InstallationSpec) string {
	if installation.CNI != nil && installation.CNI.BinDir != nil && *installation.CNI.BinDir != "" {
		return *installation.CNI.BinDir
	}
	if installation.KubernetesProvider.IsGKE() {
		return "/home/kubernetes/bin"
	}
	return ""
}
