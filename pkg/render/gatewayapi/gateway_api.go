// Copyright (c) 2024-2026 Tigera, Inc. All rights reserved.

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

package gatewayapi

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"fmt"
	"io"
	"slices"
	"strings"
	"sync"

	envoyapi "github.com/envoyproxy/gateway/api/v1alpha1"
	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/components"
	"github.com/tigera/operator/pkg/render"
	rcomp "github.com/tigera/operator/pkg/render/common/components"
	rmeta "github.com/tigera/operator/pkg/render/common/meta"
	"github.com/tigera/operator/pkg/render/common/networkpolicy"
	"github.com/tigera/operator/pkg/render/common/secret"
	"github.com/tigera/operator/pkg/tls/certificatemanagement"
	"helm.sh/helm/v3/pkg/action"
	"helm.sh/helm/v3/pkg/chart/loader"
	admissionregv1 "k8s.io/api/admissionregistration/v1"
	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apiextenv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	k8syaml "k8s.io/apimachinery/pkg/util/yaml"
	"k8s.io/utils/set"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	gapi "sigs.k8s.io/gateway-api/apis/v1"
	"sigs.k8s.io/yaml"
)

var (
	//go:embed gateway-helm.tgz
	gatewayHelmChart []byte

	log = logf.Log.WithName("gateway_api")
)

// Single envoy-gateway install in calico-system with deploy.type=GatewayNamespace,
// so proxies run in each Gateway's own namespace.
const (
	ReleaseName         = "tigera-gateway-api"
	ControllerName      = "gateway.envoyproxy.io/gatewayclass-controller"
	GatewayClassName    = "tigera-gateway-class"
	DeploymentNamespace = common.CalicoNamespace

	ControllerPolicyName       = networkpolicy.CalicoComponentPolicyPrefix + "envoy-gateway"
	EnvoyGatewayPolicySelector = "k8s-app == '" + GatewayControllerLabel + "' || k8s-app == '" + GatewayCertgenLabel + "'"
)

// Component names, which key the image overrides a variant resolves through.
const (
	ComponentNameEnvoyGateway   = "envoy-gateway"
	ComponentNameEnvoyProxy     = "envoy-proxy"
	ComponentNameEnvoyRatelimit = "envoy-ratelimit"
)

// gatewayAPIResources defines all of the resources that we expect to read from the rendered Envoy Gateway
// helm chart (as of the version indicated by `ENVOY_GATEWAY_VERSION` in `Makefile`).
type gatewayAPIResources struct {
	k8sCRDs                           []*apiextenv1.CustomResourceDefinition
	envoyCRDs                         []*apiextenv1.CustomResourceDefinition
	controllerServiceAccount          *corev1.ServiceAccount
	envoyGatewayConfigMap             *corev1.ConfigMap
	envoyGatewayConfig                *envoyapi.EnvoyGateway
	clusterRoles                      []*rbacv1.ClusterRole
	clusterRoleBindings               []*rbacv1.ClusterRoleBinding
	role                              *rbacv1.Role
	roleBinding                       *rbacv1.RoleBinding
	leaderElectionRole                *rbacv1.Role
	leaderElectionRoleBinding         *rbacv1.RoleBinding
	controllerService                 *corev1.Service
	controllerDeployment              *appsv1.Deployment
	certgenServiceAccount             *corev1.ServiceAccount
	certgenRole                       *rbacv1.Role
	certgenRoleBinding                *rbacv1.RoleBinding
	certgenJob                        *batchv1.Job
	mutatingWebhookConfigurations     []*admissionregv1.MutatingWebhookConfiguration
	validatingAdmissionPolicies       []*admissionregv1.ValidatingAdmissionPolicy
	validatingAdmissionPolicyBindings []*admissionregv1.ValidatingAdmissionPolicyBinding
}

const (
	GatewayAPIName                      = "calico-gateway-api"
	GatewayControllerLabel              = GatewayAPIName + "-controller"
	GatewayCertgenLabel                 = GatewayAPIName + "-certgen"
	EnvoyGatewayConfigName              = "envoy-gateway-config"
	EnvoyGatewayConfigKey               = "envoy-gateway.yaml"
	EnvoyGatewayDeploymentContainerName = "envoy-gateway"
	EnvoyGatewayJobContainerName        = "envoy-gateway-certgen"
	WAFFilterName                       = "waf-http-filter"
)

// helmOpts represents the helm values passed when rendering the Envoy Gateway chart.
type helmOpts struct {
	Config *helmConfig `json:"config,omitempty"`
}

type helmConfig struct {
	EnvoyGateway *helmEnvoyGateway `json:"envoyGateway,omitempty"`
}

type helmEnvoyGateway struct {
	Provider *helmProvider `json:"provider,omitempty"`
}

type helmProvider struct {
	Kubernetes *helmKubernetes `json:"kubernetes,omitempty"`
}

type helmKubernetes struct {
	Deploy *helmDeploy `json:"deploy,omitempty"`
}

type helmDeploy struct {
	Type string `json:"type,omitempty"`
}

func toMap(v any) (map[string]any, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	out := map[string]any{}
	if err := json.Unmarshal(b, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// Chart output is deterministic for our single render, so it's cached by
// sync.Once. Callers must deep-copy any object they intend to mutate.
var (
	chartOnce    sync.Once
	chartResults *gatewayAPIResources
	chartErr     error
)

func chartResourcesFor(scheme *runtime.Scheme) (*gatewayAPIResources, error) {
	chartOnce.Do(func() {
		chartResults, chartErr = renderChart(scheme)
	})
	return chartResults, chartErr
}

// renderChart renders the embedded Envoy Gateway helm chart.
func renderChart(scheme *runtime.Scheme) (*gatewayAPIResources, error) {
	chart, err := loader.LoadArchive(bytes.NewReader(gatewayHelmChart))
	if err != nil {
		return nil, fmt.Errorf("failed to load gateway-helm chart: %w", err)
	}

	actionConfig := new(action.Configuration)
	helmClient := action.NewInstall(actionConfig)
	helmClient.DryRun = true
	helmClient.ClientOnly = true
	helmClient.IncludeCRDs = true
	helmClient.Namespace = DeploymentNamespace
	helmClient.ReleaseName = ReleaseName

	opts := &helmOpts{
		Config: &helmConfig{EnvoyGateway: &helmEnvoyGateway{
			Provider: &helmProvider{
				Kubernetes: &helmKubernetes{
					Deploy: &helmDeploy{Type: "GatewayNamespace"},
				},
			},
		}},
	}

	values, err := toMap(opts)
	if err != nil {
		return nil, fmt.Errorf("failed to convert helm values: %w", err)
	}

	rel, err := helmClient.Run(chart, values)
	if err != nil {
		return nil, fmt.Errorf("failed to render gateway-helm chart: %w", err)
	}

	// Combine the main manifest with hook manifests (certgen, webhooks, etc.).
	var allManifests strings.Builder
	allManifests.WriteString(rel.Manifest)
	for _, hook := range rel.Hooks {
		allManifests.WriteString("\n---\n")
		allManifests.WriteString(hook.Manifest)
	}

	resources, err := parseManifest(scheme, allManifests.String())
	if err != nil {
		return nil, fmt.Errorf("failed to parse rendered manifest: %w", err)
	}
	return resources, nil
}

// parseManifest parses the rendered helm manifest into typed gatewayAPIResources.
func parseManifest(scheme *runtime.Scheme, manifest string) (*gatewayAPIResources, error) {
	codecs := serializer.NewCodecFactory(scheme)
	universalDeserializer := codecs.UniversalDeserializer()

	resources := &gatewayAPIResources{}
	decoder := k8syaml.NewYAMLOrJSONDecoder(bytes.NewReader([]byte(manifest)), 4096)

	for {
		var rawObj runtime.RawExtension
		if err := decoder.Decode(&rawObj); err != nil {
			if err == io.EOF {
				break
			}
			return nil, fmt.Errorf("error decoding manifest document: %w", err)
		}
		if len(rawObj.Raw) == 0 {
			continue
		}

		obj, _, err := universalDeserializer.Decode(rawObj.Raw, nil, nil)
		if err != nil {
			return nil, fmt.Errorf("error deserializing object: %w", err)
		}

		clientObj, ok := obj.(client.Object)
		if !ok {
			return nil, fmt.Errorf("object does not implement client.Object: %T", obj)
		}

		switch typedObj := clientObj.(type) {
		case *apiextenv1.CustomResourceDefinition:
			if strings.HasSuffix(typedObj.Name, ".gateway.networking.k8s.io") || strings.HasSuffix(typedObj.Name, ".gateway.networking.x-k8s.io") {
				resources.k8sCRDs = append(resources.k8sCRDs, typedObj)
			} else if strings.HasSuffix(typedObj.Name, ".gateway.envoyproxy.io") {
				resources.envoyCRDs = append(resources.envoyCRDs, typedObj)
			}
		case *corev1.ServiceAccount:
			if strings.HasSuffix(typedObj.Name, "certgen") {
				resources.certgenServiceAccount = typedObj
			} else {
				resources.controllerServiceAccount = typedObj
			}
		case *corev1.ConfigMap:
			if typedObj.Name == EnvoyGatewayConfigName {
				resources.envoyGatewayConfigMap = typedObj
				resources.envoyGatewayConfig = &envoyapi.EnvoyGateway{}
				if err := yaml.Unmarshal([]byte(typedObj.Data[EnvoyGatewayConfigKey]), resources.envoyGatewayConfig); err != nil {
					return nil, fmt.Errorf("can't unmarshal EnvoyGateway from ConfigMap: %w", err)
				}
			}
		case *rbacv1.ClusterRole:
			resources.clusterRoles = append(resources.clusterRoles, typedObj)
		case *rbacv1.ClusterRoleBinding:
			resources.clusterRoleBindings = append(resources.clusterRoleBindings, typedObj)
		case *rbacv1.Role:
			if strings.HasSuffix(typedObj.Name, "leader-election-role") {
				resources.leaderElectionRole = typedObj
			} else if strings.HasSuffix(typedObj.Name, "certgen") {
				resources.certgenRole = typedObj
			} else {
				resources.role = typedObj
			}
		case *rbacv1.RoleBinding:
			if strings.HasSuffix(typedObj.Name, "leader-election-rolebinding") {
				resources.leaderElectionRoleBinding = typedObj
			} else if strings.HasSuffix(typedObj.Name, "certgen") {
				resources.certgenRoleBinding = typedObj
			} else {
				resources.roleBinding = typedObj
			}
		case *corev1.Service:
			resources.controllerService = typedObj
		case *appsv1.Deployment:
			resources.controllerDeployment = typedObj
		case *batchv1.Job:
			resources.certgenJob = typedObj
		case *admissionregv1.MutatingWebhookConfiguration:
			resources.mutatingWebhookConfigurations = append(resources.mutatingWebhookConfigurations, typedObj)
		case *admissionregv1.ValidatingAdmissionPolicy:
			resources.validatingAdmissionPolicies = append(resources.validatingAdmissionPolicies, typedObj)
		case *admissionregv1.ValidatingAdmissionPolicyBinding:
			resources.validatingAdmissionPolicyBindings = append(resources.validatingAdmissionPolicyBindings, typedObj)
		case *corev1.Namespace:
			// The chart may render a namespace; we create our own in Objects(), so skip it.
		default:
			// Fail loudly so a chart bump that adds a new kind we don't handle
			// trips CI rather than silently dropping the object at runtime.
			return nil, fmt.Errorf("unhandled object kind %T in rendered gateway-helm manifest", typedObj)
		}
	}

	return resources, nil
}

func K8SGatewayAPICRDs(provider operatorv1.Provider, scheme *runtime.Scheme) (essentialCRDs, optionalCRDs []client.Object, err error) {
	resources, err := chartResourcesFor(scheme)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to render chart for CRDs: %w", err)
	}
	for _, crd := range resources.k8sCRDs {
		if provider.IsOpenShift() {
			// OpenShift 4.19+ restricts the Gateway CRDs that we can install, so report
			// that only some of them are essential.
			switch strings.TrimSuffix(crd.Name, ".gateway.networking.k8s.io") {
			case "gatewayclasses", "gateways", "httproutes", "referencegrants":
				essentialCRDs = append(essentialCRDs, crd.DeepCopyObject().(client.Object))
			default:
				optionalCRDs = append(optionalCRDs, crd.DeepCopyObject().(client.Object))
			}
		} else {
			// Other platforms do not restrict Gateway CRDs, so report them all as
			// essential.
			essentialCRDs = append(essentialCRDs, crd.DeepCopyObject().(client.Object))
		}
	}
	return
}

// GatewayAPICRDs returns the k8s GatewayAPI CRDs and the Envoy CRDs together,
// necessary for the deployment of Calico Gateway API.
func GatewayAPICRDs(provider operatorv1.Provider, scheme *runtime.Scheme) (essentialCRDs, optionalCRDs []client.Object, err error) {
	resources, err := chartResourcesFor(scheme)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to render chart for CRDs: %w", err)
	}
	essentialCRDs, optionalCRDs, err = K8SGatewayAPICRDs(provider, scheme)
	if err != nil {
		return nil, nil, err
	}
	for _, crd := range resources.envoyCRDs {
		essentialCRDs = append(essentialCRDs, crd.DeepCopyObject().(client.Object))
	}

	return essentialCRDs, optionalCRDs, nil
}

type GatewayAPIImplementationConfig struct {
	Scheme                 *runtime.Scheme
	Installation           *operatorv1.InstallationSpec
	GatewayAPI             *operatorv1.GatewayAPI
	PullSecrets            []*corev1.Secret
	CustomEnvoyGateway     *envoyapi.EnvoyGateway
	CustomEnvoyProxies     map[string]*envoyapi.EnvoyProxy
	CurrentGatewayClasses  set.Set[string]
	IncludeV3NetworkPolicy bool

	// GatewayNamespaces is the list of namespaces containing a Gateway managed by
	// this operator.
	GatewayNamespaces []string

	// TrustedBundle carries the public CA bundle (extracted from the operator's UBI
	// base image) plus Calico's internal CA. Mounted on the envoy-gateway controller
	// and on every provisioned envoy-proxy pod so outbound TLS (OCI wasm fetch,
	// JWT/OIDC providers, public upstreams, tracing exporters) can validate peers.
	TrustedBundle certificatemanagement.TrustedBundle
}

type gatewayAPIImplementationComponent struct {
	cfg                 *GatewayAPIImplementationConfig
	envoyGatewayImage   string
	envoyProxyImage     string
	envoyRatelimitImage string

	// Pre-rendered helm chart resources.
	chart *gatewayAPIResources
}

// ImplementationComponent is the gateway API implementation, exposed so a variant
// extension can reach the config it rendered from.
type ImplementationComponent interface {
	render.Component
	GetConfig() *GatewayAPIImplementationConfig
}

func GatewayAPIImplementationComponent(cfg *GatewayAPIImplementationConfig) (render.Component, error) {
	chart, err := chartResourcesFor(cfg.Scheme)
	if err != nil {
		return nil, fmt.Errorf("failed to render gateway-helm chart: %w", err)
	}
	return &gatewayAPIImplementationComponent{cfg: cfg, chart: chart}, nil
}

func (pr *gatewayAPIImplementationComponent) ResolveImages(is *operatorv1.ImageSet) error {
	in := pr.cfg.Installation

	var err error
	pr.envoyGatewayImage, err = components.ReferenceFor(components.ImageKeyEnvoyGateway, in, is)
	if err != nil {
		return err
	}
	pr.envoyProxyImage, err = components.ReferenceFor(components.ImageKeyEnvoyProxy, in, is)
	if err != nil {
		return err
	}
	pr.envoyRatelimitImage, err = components.ReferenceFor(components.ImageKeyEnvoyRatelimit, in, is)
	if err != nil {
		return err
	}
	return nil
}

func (pr *gatewayAPIImplementationComponent) SupportedOSType() rmeta.OSType {
	return rmeta.OSTypeLinux
}

func (pr *gatewayAPIImplementationComponent) Ready() bool {
	return true
}

func (pr *gatewayAPIImplementationComponent) Objects() ([]client.Object, []client.Object) {
	var objs, objsToDelete []client.Object
	openShift := pr.cfg.Installation.KubernetesProvider.IsOpenShift()

	// Allow policy for the controller in calico-system to punch through the core
	// Installation's default-deny.
	if pr.cfg.IncludeV3NetworkPolicy {
		objs = append(objs, gatewayAPIControllerPolicy(common.CalicoNamespace, openShift))
	}

	// Helm-rendered envoy-gateway controller in calico-system.
	objs = append(objs, pr.controllerObjects()...)

	// Render each GatewayClass declared on the CR. The controller patches in
	// the default [{Name: "tigera-gateway-class"}] when Spec.GatewayClasses is
	// nil, so this loop is the single source of truth for what gets emitted.
	for i := range pr.cfg.GatewayAPI.Spec.GatewayClasses {
		className := pr.cfg.GatewayAPI.Spec.GatewayClasses[i].Name
		proxy := pr.envoyProxyConfig(className, common.CalicoNamespace, pr.cfg.CustomEnvoyProxies[className], &(pr.cfg.GatewayAPI.Spec.GatewayClasses[i]))
		objs = append(objs, proxy, pr.gatewayClass(className, ControllerName, proxy))
		pr.cfg.CurrentGatewayClasses.Delete(className)
	}

	// Per-namespace resources (trust bundle, plus whatever the variant adds) are
	// controller-managed and Gateway-owned, so the GC cleans them up — not rendered here.

	objsToDelete = append(objsToDelete, pr.legacyTeardownObjects(objs)...)

	for _, gcName := range pr.cfg.CurrentGatewayClasses.UnsortedList() {
		log.V(1).Info("Will delete GatewayClass and EnvoyProxy", "name", gcName)
		objsToDelete = append(objsToDelete,
			&gapi.GatewayClass{
				TypeMeta:   metav1.TypeMeta{Kind: "GatewayClass", APIVersion: "gateway.networking.k8s.io/v1"},
				ObjectMeta: metav1.ObjectMeta{Name: gcName},
			},
			&envoyapi.EnvoyProxy{
				TypeMeta:   metav1.TypeMeta{Kind: "EnvoyProxy", APIVersion: "gateway.envoyproxy.io/v1alpha1"},
				ObjectMeta: metav1.ObjectMeta{Name: gcName, Namespace: common.CalicoNamespace},
			},
		)
	}

	log.V(1).Info("GatewayAPI rendering", "num_current", len(objs), "num_delete", len(objsToDelete))
	return objs, objsToDelete
}

// legacyTeardownObjects returns the operator-owned objects from the legacy
// tigera-gateway install. The Namespace itself is not queued — users may
// have placed their own resources in it. Objects already being created in
// tigera-gateway by the current render are excluded so we don't queue a
// delete for something we're also creating.
func (pr *gatewayAPIImplementationComponent) legacyTeardownObjects(creating []client.Object) []client.Object {
	const legacyNS = "tigera-gateway"
	const helmPrefix = "tigera-gateway-api-gateway-helm"

	key := func(o client.Object) string { return fmt.Sprintf("%T/%s", o, o.GetName()) }
	skip := set.New[string]()
	for _, o := range creating {
		if o.GetNamespace() == legacyNS {
			skip.Insert(key(o))
		}
	}
	// If a Gateway lives in tigera-gateway, the controller manages its per-namespace resources
	// (Gateway-owned) — don't queue those for legacy delete or we'd fight it every reconcile.
	if slices.Contains(pr.cfg.GatewayNamespaces, legacyNS) {
		skip.Insert(key(render.CreateOperatorSecretsRoleBinding(legacyNS)))
		for _, s := range secret.ToRuntimeObjects(secret.CopyToNamespace(legacyNS, pr.cfg.PullSecrets...)...) {
			skip.Insert(key(s))
		}
	}

	var objs []client.Object

	// Pull secrets first, while tigera-operator-secrets still grants the perm.
	objs = append(objs, secret.ToRuntimeObjects(secret.CopyToNamespace(legacyNS, pr.cfg.PullSecrets...)...)...)

	// Helm-rendered controller resources that lived in tigera-gateway.
	objs = append(objs,
		&corev1.ServiceAccount{
			TypeMeta:   metav1.TypeMeta{Kind: "ServiceAccount", APIVersion: "v1"},
			ObjectMeta: metav1.ObjectMeta{Name: "envoy-gateway", Namespace: legacyNS},
		},
		&corev1.ConfigMap{
			TypeMeta:   metav1.TypeMeta{Kind: "ConfigMap", APIVersion: "v1"},
			ObjectMeta: metav1.ObjectMeta{Name: EnvoyGatewayConfigName, Namespace: legacyNS},
		},
		&corev1.Service{
			TypeMeta:   metav1.TypeMeta{Kind: "Service", APIVersion: "v1"},
			ObjectMeta: metav1.ObjectMeta{Name: "envoy-gateway", Namespace: legacyNS},
		},
		&appsv1.Deployment{
			TypeMeta:   metav1.TypeMeta{Kind: "Deployment", APIVersion: "apps/v1"},
			ObjectMeta: metav1.ObjectMeta{Name: "envoy-gateway", Namespace: legacyNS},
		},
		&rbacv1.Role{
			TypeMeta:   metav1.TypeMeta{Kind: "Role", APIVersion: "rbac.authorization.k8s.io/v1"},
			ObjectMeta: metav1.ObjectMeta{Name: helmPrefix + "-infra-manager", Namespace: legacyNS},
		},
		&rbacv1.RoleBinding{
			TypeMeta:   metav1.TypeMeta{Kind: "RoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"},
			ObjectMeta: metav1.ObjectMeta{Name: helmPrefix + "-infra-manager", Namespace: legacyNS},
		},
		&rbacv1.Role{
			TypeMeta:   metav1.TypeMeta{Kind: "Role", APIVersion: "rbac.authorization.k8s.io/v1"},
			ObjectMeta: metav1.ObjectMeta{Name: helmPrefix + "-leader-election-role", Namespace: legacyNS},
		},
		&rbacv1.RoleBinding{
			TypeMeta:   metav1.TypeMeta{Kind: "RoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"},
			ObjectMeta: metav1.ObjectMeta{Name: helmPrefix + "-leader-election-rolebinding", Namespace: legacyNS},
		},
		&corev1.ServiceAccount{
			TypeMeta:   metav1.TypeMeta{Kind: "ServiceAccount", APIVersion: "v1"},
			ObjectMeta: metav1.ObjectMeta{Name: helmPrefix + "-certgen", Namespace: legacyNS},
		},
		&rbacv1.Role{
			TypeMeta:   metav1.TypeMeta{Kind: "Role", APIVersion: "rbac.authorization.k8s.io/v1"},
			ObjectMeta: metav1.ObjectMeta{Name: helmPrefix + "-certgen", Namespace: legacyNS},
		},
		&rbacv1.RoleBinding{
			TypeMeta:   metav1.TypeMeta{Kind: "RoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"},
			ObjectMeta: metav1.ObjectMeta{Name: helmPrefix + "-certgen", Namespace: legacyNS},
		},
		&batchv1.Job{
			TypeMeta:   metav1.TypeMeta{Kind: "Job", APIVersion: "batch/v1"},
			ObjectMeta: metav1.ObjectMeta{Name: helmPrefix + "-certgen", Namespace: legacyNS},
		},
	)

	// envoy-gateway certgen TLS Secrets — unowned, so nothing else GCs them.
	for _, name := range []string{"envoy", "envoy-gateway", "envoy-oidc-hmac", "envoy-rate-limit"} {
		objs = append(objs, &corev1.Secret{
			TypeMeta:   metav1.TypeMeta{Kind: "Secret", APIVersion: "v1"},
			ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: legacyNS},
		})
	}

	// tigera-operator-secrets RoleBinding last — must outlive the Secrets above.
	objs = append(objs, render.CreateOperatorSecretsRoleBinding(legacyNS))

	// Cluster-scoped legacy objects: topology MWC and the deprecated combined
	// waf-http-filter CR/CRB that pre-dated the cluster-scoped vs gateway-resources split.
	objs = append(objs,
		&admissionregv1.MutatingWebhookConfiguration{
			TypeMeta:   metav1.TypeMeta{Kind: "MutatingWebhookConfiguration", APIVersion: "admissionregistration.k8s.io/v1"},
			ObjectMeta: metav1.ObjectMeta{Name: "envoy-gateway-topology-injector.tigera-gateway"},
		},
		&rbacv1.ClusterRole{
			TypeMeta:   metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"},
			ObjectMeta: metav1.ObjectMeta{Name: WAFFilterName},
		},
		&rbacv1.ClusterRoleBinding{
			TypeMeta:   metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"},
			ObjectMeta: metav1.ObjectMeta{Name: WAFFilterName},
		},
	)

	if skip.Len() == 0 {
		return objs
	}
	filtered := make([]client.Object, 0, len(objs))
	for _, o := range objs {
		if skip.Has(key(o)) {
			continue
		}
		filtered = append(filtered, o)
	}
	return filtered
}

// controllerObjects returns the helm-rendered resources for the envoy-gateway
// install, with user customisations applied to the EnvoyGateway ConfigMap and
// the controller Deployment + certgen Job.
func (pr *gatewayAPIImplementationComponent) controllerObjects() []client.Object {
	resources := pr.chart
	var objs []client.Object

	// SA + cluster-scoped RBAC + webhooks + namespaced RBAC.
	objs = append(objs, resources.controllerServiceAccount.DeepCopyObject().(client.Object))
	for _, cr := range resources.clusterRoles {
		objs = append(objs, cr.DeepCopyObject().(client.Object))
	}
	for _, crb := range resources.clusterRoleBindings {
		objs = append(objs, crb.DeepCopyObject().(client.Object))
	}
	for _, mwc := range resources.mutatingWebhookConfigurations {
		objs = append(objs, mwc.DeepCopyObject().(client.Object))
	}
	for _, vap := range resources.validatingAdmissionPolicies {
		objs = append(objs, vap.DeepCopyObject().(client.Object))
	}
	for _, vapb := range resources.validatingAdmissionPolicyBindings {
		objs = append(objs, vapb.DeepCopyObject().(client.Object))
	}
	for _, resource := range []client.Object{
		resources.role,
		resources.roleBinding,
		resources.leaderElectionRole,
		resources.leaderElectionRoleBinding,
		resources.controllerService,
		resources.certgenServiceAccount,
		resources.certgenRole,
		resources.certgenRoleBinding,
	} {
		objs = append(objs, resource.DeepCopyObject().(client.Object))
	}

	// EnvoyGateway ConfigMap.
	var envoyGatewayConfig *envoyapi.EnvoyGateway
	if pr.cfg.CustomEnvoyGateway != nil {
		envoyGatewayConfig = pr.cfg.CustomEnvoyGateway
	} else {
		envoyGatewayConfig = resources.envoyGatewayConfig.DeepCopyObject().(*envoyapi.EnvoyGateway)
	}
	if envoyGatewayConfig.Provider == nil {
		envoyGatewayConfig.Provider = &envoyapi.EnvoyGatewayProvider{}
	}
	envoyGatewayConfig.Provider.Type = envoyapi.ProviderTypeKubernetes
	if envoyGatewayConfig.Provider.Kubernetes == nil {
		envoyGatewayConfig.Provider.Kubernetes = &envoyapi.EnvoyGatewayKubernetesProvider{}
	}
	if envoyGatewayConfig.Provider.Kubernetes.RateLimitDeployment == nil {
		envoyGatewayConfig.Provider.Kubernetes.RateLimitDeployment = &envoyapi.KubernetesDeploymentSpec{}
	}
	if envoyGatewayConfig.Provider.Kubernetes.RateLimitDeployment.Pod == nil {
		envoyGatewayConfig.Provider.Kubernetes.RateLimitDeployment.Pod = &envoyapi.KubernetesPodSpec{}
	}
	if envoyGatewayConfig.Provider.Kubernetes.RateLimitDeployment.Container == nil {
		envoyGatewayConfig.Provider.Kubernetes.RateLimitDeployment.Container = &envoyapi.KubernetesContainerSpec{}
	}
	if envoyGatewayConfig.Provider.Kubernetes.ShutdownManager == nil {
		envoyGatewayConfig.Provider.Kubernetes.ShutdownManager = &envoyapi.ShutdownManager{}
	}
	if envoyGatewayConfig.ExtensionAPIs == nil {
		envoyGatewayConfig.ExtensionAPIs = &envoyapi.ExtensionAPISettings{}
	}
	if envoyGatewayConfig.Gateway == nil {
		envoyGatewayConfig.Gateway = &envoyapi.Gateway{}
	}
	if envoyGatewayConfig.Gateway.ControllerName == "" {
		envoyGatewayConfig.Gateway.ControllerName = resources.envoyGatewayConfig.Gateway.ControllerName
	}
	envoyGatewayConfig.Provider.Kubernetes.RateLimitDeployment.Container.Image = &pr.envoyRatelimitImage
	envoyGatewayConfig.Provider.Kubernetes.ShutdownManager.Image = &pr.envoyGatewayImage
	envoyGatewayConfig.Provider.Kubernetes.RateLimitDeployment.Pod.ImagePullSecrets = secret.GetReferenceList(pr.cfg.PullSecrets)
	envoyGatewayConfig.ExtensionAPIs.EnableBackend = true
	envoyGatewayConfig.ExtensionAPIs.EnableEnvoyPatchPolicy = true

	envoyGatewayConfigMap := resources.envoyGatewayConfigMap.DeepCopyObject().(*corev1.ConfigMap)
	if bytes, err := yaml.Marshal(*envoyGatewayConfig); err == nil {
		envoyGatewayConfigMap.Data[EnvoyGatewayConfigKey] = string(bytes)
	} else {
		panic(fmt.Sprintf("couldn't marshal EnvoyGateway to YAML: %v", err))
	}
	objs = append(objs, envoyGatewayConfigMap)

	// Ship the operator's trust bundle (public CAs + Calico CA) into the gateway
	// namespace as a ConfigMap so it can be mounted on both the envoy-gateway
	// controller and every provisioned envoy-proxy pod.
	if pr.cfg.TrustedBundle != nil {
		objs = append(objs, pr.cfg.TrustedBundle.ConfigMap(DeploymentNamespace))
	}

	// Controller Deployment.
	controllerDeployment := resources.controllerDeployment.DeepCopyObject().(*appsv1.Deployment)
	controllerDeployment.Spec.Template.Spec.Containers[0].Image = pr.envoyGatewayImage
	controllerDeployment.Spec.Template.Spec.ImagePullSecrets = append(
		controllerDeployment.Spec.Template.Spec.ImagePullSecrets,
		secret.GetReferenceList(pr.cfg.PullSecrets)...)
	controllerDeployment.Spec.Template.Labels["k8s-app"] = GatewayControllerLabel

	// Mount the trust bundle on the envoy-gateway controller. The controller pulls
	// wasm OCI images and may call out to JWT/OIDC providers, both of which need
	// public CA roots to validate TLS.
	if pr.cfg.TrustedBundle != nil {
		controllerDeployment.Spec.Template.Spec.Volumes = append(
			controllerDeployment.Spec.Template.Spec.Volumes,
			pr.cfg.TrustedBundle.Volume(),
		)
		bundleMounts := pr.cfg.TrustedBundle.VolumeMounts(pr.SupportedOSType())
		for i := range controllerDeployment.Spec.Template.Spec.Containers {
			controllerDeployment.Spec.Template.Spec.Containers[i].VolumeMounts = append(
				controllerDeployment.Spec.Template.Spec.Containers[i].VolumeMounts,
				bundleMounts...,
			)
		}
		if controllerDeployment.Spec.Template.Annotations == nil {
			controllerDeployment.Spec.Template.Annotations = map[string]string{}
		}
		for k, v := range pr.cfg.TrustedBundle.HashAnnotations() {
			controllerDeployment.Spec.Template.Annotations[k] = v
		}
	}

	rcomp.ApplyDeploymentOverrides(controllerDeployment, pr.cfg.GatewayAPI.Spec.GatewayControllerDeployment)
	objs = append(objs, controllerDeployment)

	// Certgen Job.
	certgenJob := resources.certgenJob.DeepCopyObject().(*batchv1.Job)
	certgenJob.Spec.Template.Spec.Containers[0].Image = pr.envoyGatewayImage
	certgenJob.Spec.Template.Spec.ImagePullSecrets = append(
		certgenJob.Spec.Template.Spec.ImagePullSecrets,
		secret.GetReferenceList(pr.cfg.PullSecrets)...)
	if certgenJob.Spec.Template.Labels == nil {
		certgenJob.Spec.Template.Labels = map[string]string{}
	}
	certgenJob.Spec.Template.Labels["k8s-app"] = GatewayCertgenLabel
	rcomp.ApplyJobOverrides(certgenJob, pr.cfg.GatewayAPI.Spec.GatewayCertgenJob)
	objs = append(objs, certgenJob)

	return objs
}

func (pr *gatewayAPIImplementationComponent) envoyProxyConfig(className, ns string, envoyProxy *envoyapi.EnvoyProxy, classSpec *operatorv1.GatewayClassSpec) *envoyapi.EnvoyProxy {
	// Ensure the minimal structure that we need for basic correctness and for the following
	// customizations.  Note, we always create the running EnvoyProxy in our own namespace, even
	// if it's based on a custom resource from another namespace.
	if envoyProxy == nil {
		envoyProxy = &envoyapi.EnvoyProxy{}
	} else {
		// Copy over the important fields from the custom supplied, specifically avoiding
		// the fields that must NOT be set when first creating an object.
		envoyProxy = &envoyapi.EnvoyProxy{
			ObjectMeta: metav1.ObjectMeta{
				Name:        envoyProxy.Name,
				Labels:      envoyProxy.Labels,
				Annotations: envoyProxy.Annotations,
			},
			Spec: envoyProxy.Spec,
		}
	}
	if envoyProxy.Kind == "" {
		envoyProxy.Kind = "EnvoyProxy"
	}
	if envoyProxy.APIVersion == "" {
		envoyProxy.APIVersion = "gateway.envoyproxy.io/v1alpha1"
	}
	envoyProxy.Name = className
	envoyProxy.Namespace = ns
	if envoyProxy.Spec.Provider == nil {
		envoyProxy.Spec.Provider = &envoyapi.EnvoyProxyProvider{}
	}
	envoyProxy.Spec.Provider.Type = envoyapi.EnvoyProxyProviderTypeKubernetes
	if envoyProxy.Spec.Provider.Kubernetes == nil {
		envoyProxy.Spec.Provider.Kubernetes = &envoyapi.EnvoyProxyKubernetesProvider{}
	}

	// If the EnvoyProxy itself doesn't already indicate DaemonSet or Deployment, and our
	// customization structs indicate deploying as a DaemonSet, set that up.
	if envoyProxy.Spec.Provider.Kubernetes.EnvoyDaemonSet == nil && envoyProxy.Spec.Provider.Kubernetes.EnvoyDeployment == nil {
		if classSpec.GatewayKind != nil {
			if *classSpec.GatewayKind == operatorv1.GatewayKindDaemonSet {
				envoyProxy.Spec.Provider.Kubernetes.EnvoyDaemonSet = &envoyapi.KubernetesDaemonSetSpec{}
			}
		}
	}

	// Add EnvoyProxy config that will apply our image configuration, pull secrets and overrides
	// to gateway deployments.
	if envoyProxy.Spec.Provider.Kubernetes.EnvoyDaemonSet != nil {
		// Custom EnvoyProxy indicates deployment as a DaemonSet.
		if envoyProxy.Spec.Provider.Kubernetes.EnvoyDaemonSet.Pod == nil {
			envoyProxy.Spec.Provider.Kubernetes.EnvoyDaemonSet.Pod = &envoyapi.KubernetesPodSpec{}
		}
		envoyProxy.Spec.Provider.Kubernetes.EnvoyDaemonSet.Pod.ImagePullSecrets = secret.GetReferenceList(pr.cfg.PullSecrets)
		if envoyProxy.Spec.Provider.Kubernetes.EnvoyDaemonSet.Container == nil {
			envoyProxy.Spec.Provider.Kubernetes.EnvoyDaemonSet.Container = &envoyapi.KubernetesContainerSpec{}
		}
		envoyProxy.Spec.Provider.Kubernetes.EnvoyDaemonSet.Container.Image = &pr.envoyProxyImage
	} else {
		// Deployment as a Deployment.
		if envoyProxy.Spec.Provider.Kubernetes.EnvoyDeployment == nil {
			envoyProxy.Spec.Provider.Kubernetes.EnvoyDeployment = &envoyapi.KubernetesDeploymentSpec{}
		}
		if envoyProxy.Spec.Provider.Kubernetes.EnvoyDeployment.Pod == nil {
			envoyProxy.Spec.Provider.Kubernetes.EnvoyDeployment.Pod = &envoyapi.KubernetesPodSpec{}
		}
		envoyProxy.Spec.Provider.Kubernetes.EnvoyDeployment.Pod.ImagePullSecrets = secret.GetReferenceList(pr.cfg.PullSecrets)
		if envoyProxy.Spec.Provider.Kubernetes.EnvoyDeployment.Container == nil {
			envoyProxy.Spec.Provider.Kubernetes.EnvoyDeployment.Container = &envoyapi.KubernetesContainerSpec{}
		}
		envoyProxy.Spec.Provider.Kubernetes.EnvoyDeployment.Container.Image = &pr.envoyProxyImage
	}

	// Mount the operator's trust bundle on the data-plane envoy-proxy pod so that
	// outbound TLS (wasm OCI fetch, JWT/OIDC, HTTPS upstreams, tracing exporters)
	// can validate public CAs. The bundle is the same ConfigMap mounted on the
	// envoy-gateway controller, in the same namespace as the proxy.
	if pr.cfg.TrustedBundle != nil {
		bundleVolume := pr.cfg.TrustedBundle.Volume()
		bundleMounts := pr.cfg.TrustedBundle.VolumeMounts(pr.SupportedOSType())
		if envoyProxy.Spec.Provider.Kubernetes.EnvoyDaemonSet != nil {
			ds := envoyProxy.Spec.Provider.Kubernetes.EnvoyDaemonSet
			ds.Pod.Volumes = append(ds.Pod.Volumes, bundleVolume)
			ds.Container.VolumeMounts = append(ds.Container.VolumeMounts, bundleMounts...)
		} else {
			dep := envoyProxy.Spec.Provider.Kubernetes.EnvoyDeployment
			dep.Pod.Volumes = append(dep.Pod.Volumes, bundleVolume)
			dep.Container.VolumeMounts = append(dep.Container.VolumeMounts, bundleMounts...)
		}
	}

	// Apply overrides.
	if envoyProxy.Spec.Provider.Kubernetes.EnvoyDaemonSet != nil {
		rcomp.ApplyEnvoyProxyOverrides(envoyProxy, classSpec.GatewayDaemonSet)
	} else {
		rcomp.ApplyEnvoyProxyOverrides(envoyProxy, classSpec.GatewayDeployment)
	}
	applyEnvoyProxyServiceOverrides(envoyProxy, classSpec.GatewayService)

	return envoyProxy
}

func (pr *gatewayAPIImplementationComponent) gatewayClass(className, controllerName string, proxyConfig *envoyapi.EnvoyProxy) *gapi.GatewayClass {
	// Provision a GatewayClass that references the EnvoyProxy config and the controllerName
	// that the gateway controller expects. GatewayClass is cluster-scoped so namespace is informational.
	return &gapi.GatewayClass{
		TypeMeta: metav1.TypeMeta{Kind: "GatewayClass", APIVersion: "gateway.networking.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name: className,
		},
		Spec: gapi.GatewayClassSpec{
			ControllerName: gapi.GatewayController(controllerName),
			ParametersRef: &gapi.ParametersReference{
				Group:     gapi.Group(proxyConfig.GroupVersionKind().Group),
				Kind:      gapi.Kind(proxyConfig.Kind),
				Name:      proxyConfig.Name,
				Namespace: (*gapi.Namespace)(&proxyConfig.Namespace),
			},
		},
	}
}

type GatewayAPIImplementationConfigInterface interface {
	GetConfig() *GatewayAPIImplementationConfig
}

func (pr *gatewayAPIImplementationComponent) GetConfig() *GatewayAPIImplementationConfig {
	return pr.cfg
}

// applyEnvoyProxyServiceOverrides applies the overrides to the given EnvoyProxy.
// Note: overrides must not be nil pointer.
func applyEnvoyProxyServiceOverrides(ep *envoyapi.EnvoyProxy, overrides *operatorv1.GatewayService) {
	if overrides != nil {
		if ep.Spec.Provider.Kubernetes.EnvoyService == nil {
			ep.Spec.Provider.Kubernetes.EnvoyService = &envoyapi.KubernetesServiceSpec{}
		}
		if overrides.Metadata != nil {
			if len(overrides.Metadata.Labels) > 0 {
				ep.Spec.Provider.Kubernetes.EnvoyService.Labels = common.MapExistsOrInitialize(ep.Spec.Provider.Kubernetes.EnvoyService.Labels)
				common.MergeMaps(overrides.Metadata.Labels, ep.Spec.Provider.Kubernetes.EnvoyService.Labels)
			}
			if len(overrides.Metadata.Annotations) > 0 {
				ep.Spec.Provider.Kubernetes.EnvoyService.Annotations = common.MapExistsOrInitialize(ep.Spec.Provider.Kubernetes.EnvoyService.Annotations)
				common.MergeMaps(overrides.Metadata.Annotations, ep.Spec.Provider.Kubernetes.EnvoyService.Annotations)
			}
		}
		if overrides.Spec != nil {
			if overrides.Spec.LoadBalancerClass != nil {
				ep.Spec.Provider.Kubernetes.EnvoyService.LoadBalancerClass = overrides.Spec.LoadBalancerClass
			}
			if overrides.Spec.AllocateLoadBalancerNodePorts != nil {
				ep.Spec.Provider.Kubernetes.EnvoyService.AllocateLoadBalancerNodePorts = overrides.Spec.AllocateLoadBalancerNodePorts
			}
			if overrides.Spec.LoadBalancerSourceRanges != nil {
				ep.Spec.Provider.Kubernetes.EnvoyService.LoadBalancerSourceRanges = overrides.Spec.LoadBalancerSourceRanges
			}
			if overrides.Spec.LoadBalancerIP != nil {
				ep.Spec.Provider.Kubernetes.EnvoyService.LoadBalancerIP = overrides.Spec.LoadBalancerIP
			}
			if overrides.Spec.Patch != nil {
				ep.Spec.Provider.Kubernetes.EnvoyService.Patch = overrides.Spec.Patch
			}
		}
	}
}

const (
	wafFilterClusterScopedRoleName    = WAFFilterName + "-cluster-scoped"
	wafFilterGatewayResourcesRoleName = WAFFilterName + "-gateway-resources"
)

// WAFClusterScopedRole creates the ClusterRole granting access to cluster-scoped
// resources (license keys, token reviews) needed by every WAF HTTP Filter / L7 Log Collector.
func WAFClusterScopedRole() *rbacv1.ClusterRole {
	return &rbacv1.ClusterRole{
		TypeMeta: metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name: wafFilterClusterScopedRoleName,
		},
		Rules: []rbacv1.PolicyRule{
			{
				APIGroups: []string{"crd.projectcalico.org", "projectcalico.org"},
				Resources: []string{"licensekeys"},
				Verbs:     []string{"get", "watch"},
			},
			{
				APIGroups: []string{"authentication.k8s.io"},
				Resources: []string{"tokenreviews"},
				Verbs:     []string{"create"},
			},
		},
	}
}

// WAFGatewayResourcesRole grants read access to namespaced Gateway
// API resources (used by the L7 Log Collector), bound per-namespace via
// GatewayNamespaceRoleBinding so each proxy can only read its own namespace.
func WAFGatewayResourcesRole() *rbacv1.ClusterRole {
	return &rbacv1.ClusterRole{
		TypeMeta: metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name: wafFilterGatewayResourcesRoleName,
		},
		Rules: []rbacv1.PolicyRule{
			{
				APIGroups: []string{"gateway.networking.k8s.io"},
				Resources: []string{"gateways", "httproutes", "grpcroutes"},
				Verbs:     []string{"get", "list", "watch"},
			},
		},
	}
}

// GatewayNamespaceServiceAccount returns the waf-http-filter ServiceAccount for a Gateway namespace.
func GatewayNamespaceServiceAccount(namespace string) *corev1.ServiceAccount {
	return &corev1.ServiceAccount{
		TypeMeta: metav1.TypeMeta{Kind: "ServiceAccount", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      WAFFilterName,
			Namespace: namespace,
		},
	}
}

// GatewayNamespacesCRBName is the name of the shared ClusterRoleBinding that binds the
// waf-http-filter ClusterRole to ServiceAccounts in all Gateway namespaces.
const GatewayNamespacesCRBName = WAFFilterName + "-gateway-namespaces"

// GatewayNamespacesCRB binds the cluster-scoped WAF ClusterRole to the
// waf-http-filter SA in each Gateway namespace via a single shared CRB.
// Gateway API resource access is scoped per namespace via GatewayNamespaceRoleBinding.
func GatewayNamespacesCRB(namespaces []string) *rbacv1.ClusterRoleBinding {
	subjects := make([]rbacv1.Subject, 0, len(namespaces))
	for _, ns := range namespaces {
		subjects = append(subjects, rbacv1.Subject{
			Kind:      "ServiceAccount",
			Name:      WAFFilterName,
			Namespace: ns,
		})
	}
	return &rbacv1.ClusterRoleBinding{
		TypeMeta: metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name: GatewayNamespacesCRBName,
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "ClusterRole",
			Name:     wafFilterClusterScopedRoleName,
		},
		Subjects: subjects,
	}
}

// GatewayNamespaceRoleBinding returns the waf-http-filter-gateway-resources RoleBinding for a Gateway namespace.
func GatewayNamespaceRoleBinding(namespace string) *rbacv1.RoleBinding {
	return &rbacv1.RoleBinding{
		TypeMeta: metav1.TypeMeta{Kind: "RoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      wafFilterGatewayResourcesRoleName,
			Namespace: namespace,
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "ClusterRole",
			Name:     wafFilterGatewayResourcesRoleName,
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      "ServiceAccount",
				Name:      WAFFilterName,
				Namespace: namespace,
			},
		},
	}
}

// gatewayAPIControllerPolicy allows the controller + certgen to reach kube-apiserver and DNS.
func gatewayAPIControllerPolicy(namespace string, openShift bool) *v3.NetworkPolicy {
	egress := networkpolicy.AppendDNSEgressRules(nil, openShift)
	egress = append(egress,
		v3.Rule{
			Action:      v3.Allow,
			Protocol:    &networkpolicy.TCPProtocol,
			Destination: networkpolicy.KubeAPIServerEntityRule,
		},
		v3.Rule{Action: v3.Pass},
	)

	return &v3.NetworkPolicy{
		TypeMeta: metav1.TypeMeta{Kind: "NetworkPolicy", APIVersion: "projectcalico.org/v3"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      ControllerPolicyName,
			Namespace: namespace,
		},
		Spec: v3.NetworkPolicySpec{
			Order:    &networkpolicy.HighPrecedenceOrder,
			Tier:     networkpolicy.CalicoTierName,
			Selector: EnvoyGatewayPolicySelector,
			Types:    []v3.PolicyType{v3.PolicyTypeIngress, v3.PolicyTypeEgress},
			// 9443: webhook. 18000-18002: xDS. 19001: metrics.
			Ingress: []v3.Rule{
				{
					Action:   v3.Allow,
					Protocol: &networkpolicy.TCPProtocol,
					Source:   v3.EntityRule{Nets: []string{"0.0.0.0/0"}},
					Destination: v3.EntityRule{
						Ports: networkpolicy.Ports(9443, 18000, 18001, 18002, 19001),
					},
				},
				{
					Action:   v3.Allow,
					Protocol: &networkpolicy.TCPProtocol,
					Source:   v3.EntityRule{Nets: []string{"::/0"}},
					Destination: v3.EntityRule{
						Ports: networkpolicy.Ports(9443, 18000, 18001, 18002, 19001),
					},
				},
			},
			Egress: egress,
		},
	}
}
