// Copyright (c) 2026 Tigera, Inc. All rights reserved.

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

package apiserver

import (
	"context"
	"fmt"
	"net/url"
	"reflect"
	"slices"
	"strings"

	admregv1 "k8s.io/api/admissionregistration/v1"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"

	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	"github.com/tigera/api/pkg/lib/numorstring"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/components"
	"github.com/tigera/operator/pkg/controller"
	"github.com/tigera/operator/pkg/controller/utils"
	"github.com/tigera/operator/pkg/controller/utils/imageset"
	"github.com/tigera/operator/pkg/ctrlruntime"
	"github.com/tigera/operator/pkg/dns"
	eoptions "github.com/tigera/operator/pkg/enterprise/options"
	"github.com/tigera/operator/pkg/extensions"
	"github.com/tigera/operator/pkg/render"
	"github.com/tigera/operator/pkg/render/common/authentication"
	rcomp "github.com/tigera/operator/pkg/render/common/components"
	relasticsearch "github.com/tigera/operator/pkg/render/common/elasticsearch"
	rmeta "github.com/tigera/operator/pkg/render/common/meta"
	"github.com/tigera/operator/pkg/render/common/networkpolicy"
	"github.com/tigera/operator/pkg/render/common/rbacmanagement"
	"github.com/tigera/operator/pkg/render/common/securitycontext"
	"github.com/tigera/operator/pkg/render/monitor"
	"github.com/tigera/operator/pkg/tls/certificatemanagement"
)

const (
	auditLogsVolumeName   = "calico-audit-logs"
	auditPolicyVolumeName = "calico-audit-policy"

	// linseedAccessClusterRoleName is the Enterprise, multi-tenant-only ClusterRole granting
	// each tenant's calico-apiserver identity read access to Linseed policy activity data.
	linseedAccessClusterRoleName = "calico-apiserver-linseed-access"
)

// apiServerRenderData is the controller-produced data the API server hook hands to its
// modifiers through Inputs.Extension. It carries the enterprise inputs the base
// render no longer knows about: the management cluster / managed cluster CRs, the
// ApplicationLayer (which drives the L7 sidecar), the cert-management-only query server
// keypair, the OIDC key validator config, and the resolved L7 sidecar images.
type apiServerRenderData struct {
	managementCluster           *operatorv1.ManagementCluster
	managementClusterConnection *operatorv1.ManagementClusterConnection
	applicationLayer            *operatorv1.ApplicationLayer
	queryServerTLS              certificatemanagement.KeyPairInterface
	keyValidatorConfig          authentication.KeyValidatorConfig
	l7EnvoyImage                string
	dikastesImage               string
	cloud                       bool

	// calicoImage is the image the query server and L7 admission controller containers
	// run. The base render resolves it too, but a modifier runs with no ImageSet.
	calicoImage string

	// rbacManagementEnabled mirrors the rbac-ui-config gate. ui-apis writes role bindings
	// impersonating the caller, so tigera-network-admin needs the verbs itself.
	rbacManagementEnabled bool

	// bindingNamespaces is the set of tenant namespaces whose calico-apiserver ServiceAccount
	// should be granted Linseed access. Empty for zero/single-tenant clusters; every tenant
	// namespace for multi-tenant management clusters.
	bindingNamespaces []string
}

// apiServerData pulls the API server hook's render data back out of the render inputs,
// returning the zero value when none is set.
func apiServerData(ri render.Inputs) apiServerRenderData {
	return render.ExtractExtensionData[apiServerRenderData](ri)
}

// apiServer carries the rendered API server configuration, the resolved image, and the
// controller-produced render data so the enterprise builders can construct the
// Enterprise-only objects and deployment additions.
type apiServer struct {
	cfg         *render.APIServerConfiguration
	calicoImage string
	data        apiServerRenderData
}

// Extension is the Calico Enterprise behavior for the API server controller.
type Extension struct {
	variant operatorv1.ProductVariant
	opts    eoptions.Options
}

var _ extensions.APIServerExtension = &Extension{}

// New returns the API server extension for the variant the operator resolved.
func New(variant operatorv1.ProductVariant, opts eoptions.Options) *Extension {
	return &Extension{variant: variant, opts: opts}
}

// Modify dispatches over the components the API server controller renders.
func (e *Extension) Modify(c render.Component, ri render.Inputs) render.Component {
	switch t := c.(type) {
	case render.APIServerComponent:
		return extensions.Decorate(c, ri, e.variant, func(create, del []client.Object) ([]client.Object, []client.Object) {
			return modifyAPIServer(ri, t.APIServerConfig(), create, del)
		})
	case render.APIServerPolicyComponent:
		return extensions.Decorate(c, ri, e.variant, func(create, del []client.Object) ([]client.Object, []client.Object) {
			return modifyAPIServerPolicy(ri, t.APIServerPolicyConfig(), create, del)
		})
	default:
		return c
	}
}

func (c *apiServer) isSidecarInjectionEnabled() bool {
	al := c.data.applicationLayer
	return al != nil &&
		al.Spec.SidecarInjection != nil &&
		*al.Spec.SidecarInjection == operatorv1.SidecarEnabled
}

// Watches registers the enterprise resources the API server controller reconciles on.
func (e *Extension) Watches(c ctrlruntime.Controller) error {
	for _, obj := range []client.Object{
		&operatorv1.ApplicationLayer{ObjectMeta: metav1.ObjectMeta{Name: utils.DefaultEnterpriseInstanceKey.Name}},
		&operatorv1.ManagementCluster{},
		&operatorv1.ManagementClusterConnection{},
		&operatorv1.Authentication{},
	} {
		if err := c.WatchObject(obj, &handler.EnqueueRequestForObject{}); err != nil {
			return err
		}
	}
	// The switch gating the RBAC management UI rules.
	if err := utils.AddConfigMapWatch(c, rbacmanagement.ConfigMapName, common.CalicoNamespace, &handler.EnqueueRequestForObject{}); err != nil {
		return err
	}
	for _, namespace := range []string{common.OperatorNamespace(), render.APIServerNamespace} {
		for _, secretName := range []string{render.VoltronTunnelSecretName, render.ManagerTLSSecretName} {
			if err := utils.AddSecretsWatch(c, secretName, namespace); err != nil {
				return err
			}
		}
	}
	return utils.AddSecretsWatch(c, render.VoltronLinseedPublicCert, common.OperatorNamespace())
}

// ExtendInputs does the enterprise controller-side work: it builds the trusted bundle,
// fetches the enterprise CRs, creates the query server certificate, resolves the L7
// sidecar images, and stashes them for the modifiers. The base API server render carries
// none of this.
func (e *Extension) ExtendInputs(ctx context.Context, ci controller.Inputs) (controller.Inputs, []certificatemanagement.KeyPairInterface, error) {
	in := ci.RenderInputs.Installation

	trustedBundle, err := ci.CertificateManager.CreateNamedTrustedBundleFromSecrets(render.APIServerResourceName, ci.Client, common.OperatorNamespace(), false)
	if err != nil {
		return ci, nil, extensions.Degradedf(operatorv1.ResourceCreateError, "unable to create the trusted bundle: %w", err)
	}

	applicationLayer, err := utils.GetApplicationLayer(ctx, ci.Client)
	if err != nil {
		return ci, nil, extensions.Degradedf(operatorv1.ResourceReadError, "error reading ApplicationLayer: %w", err)
	}

	managementCluster, err := utils.GetManagementCluster(ctx, ci.Client)
	if err != nil {
		return ci, nil, extensions.Degradedf(operatorv1.ResourceReadError, "error reading ManagementCluster: %w", err)
	}

	managementClusterConnection, err := utils.GetManagementClusterConnection(ctx, ci.Client)
	if err != nil {
		return ci, nil, extensions.Degradedf(operatorv1.ResourceReadError, "error reading ManagementClusterConnection: %w", err)
	}

	if managementCluster != nil && managementClusterConnection != nil {
		return ci, nil, extensions.InvalidConfigf("having both a ManagementCluster and a ManagementClusterConnection is not supported")
	}

	rbacManagementEnabled, err := utils.RBACManagementEnabled(ctx, ci.Client, e.variant, e.opts.MultiTenant)
	if err != nil {
		return ci, nil, extensions.Degradedf(operatorv1.ResourceReadError, "error reading the RBAC management UI ConfigMap: %w", err)
	}

	// Management cluster only: the apiserver mounts the tunnel CA secret so it can sign
	// certificates for managed clusters. The manager controller writes it once
	// ManagementCluster.Spec.TLS is defaulted; degrade until it exists.
	if managementCluster != nil && managementCluster.Spec.TLS != nil && !e.opts.MultiTenant {
		if _, err := utils.GetSecret(ctx, ci.Client, managementCluster.Spec.TLS.SecretName, common.OperatorNamespace()); err != nil {
			return ci, nil, extensions.Degradedf(operatorv1.ResourceReadError, "unable to fetch the tunnel secret: %w", err)
		}
	}

	prometheusCertificate, err := ci.CertificateManager.GetCertificate(ci.Client, monitor.PrometheusClientTLSSecretName, common.OperatorNamespace())
	if err != nil {
		return ci, nil, extensions.Degradedf(operatorv1.ResourceReadError, "failed to get certificate: %w", err)
	}
	if prometheusCertificate != nil {
		trustedBundle.AddCertificates(prometheusCertificate)
	}

	if managementClusterConnection != nil {
		voltronLinseedCert, err := ci.CertificateManager.GetCertificate(ci.Client, render.VoltronLinseedPublicCert, common.OperatorNamespace())
		if err != nil {
			return ci, nil, extensions.Degradedf(operatorv1.ResourceReadError, "failed to retrieve %s: %w", render.VoltronLinseedPublicCert, err)
		}
		if voltronLinseedCert != nil {
			trustedBundle.AddCertificates(voltronLinseedCert)
		}
	}

	// Authentication: when a Dex-backed Authentication CR is ready, add its cert to the
	// bundle and build the key validator config for the query server and the policy.
	var keyValidatorConfig authentication.KeyValidatorConfig
	authenticationCR, err := utils.GetAuthentication(ctx, ci.Client)
	if err != nil && !apierrors.IsNotFound(err) {
		return ci, nil, extensions.Degradedf(operatorv1.ResourceReadError, "error while fetching Authentication: %w", err)
	}
	if authenticationCR != nil && authenticationCR.Status.State == operatorv1.TigeraStatusReady {
		if utils.DexEnabled(authenticationCR) {
			certificate, err := ci.CertificateManager.GetCertificate(ci.Client, render.DexTLSSecretName, common.OperatorNamespace())
			if err != nil {
				return ci, nil, extensions.Degradedf(operatorv1.CertificateError, "failed to retrieve %s: %w", render.DexTLSSecretName, err)
			} else if certificate == nil {
				return ci, nil, extensions.NotReadyf("waiting for secret '%s' to become available", render.DexTLSSecretName)
			}
			trustedBundle.AddCertificates(certificate)
		}
		keyValidatorConfig, err = utils.GetKeyValidatorConfig(ctx, ci.Client, authenticationCR, ci.RenderInputs.ClusterDomain, false)
		if err != nil {
			return ci, nil, extensions.Degradedf(operatorv1.ResourceReadError, "failed to get KeyValidator config: %w", err)
		}
	}

	// Under certificate management, the query server needs its own keypair so it can run
	// with different permissions than the apiserver.
	var queryServerTLS certificatemanagement.KeyPairInterface
	if in.CertificateManagement != nil {
		queryServerTLS, err = ci.CertificateManager.GetOrCreateKeyPair(
			ci.Client,
			"query-server-tls",
			common.OperatorNamespace(),
			dns.GetServiceDNSNames(render.APIServerServiceName, render.APIServerNamespace, ci.RenderInputs.ClusterDomain),
		)
		if err != nil {
			return ci, nil, extensions.Degradedf(operatorv1.ResourceCreateError, "unable to get or create query server tls key pair: %w", err)
		}
	}

	// Modifiers run with no ImageSet, so resolve the images they need here. The query
	// server and L7 admission controller containers run the combined calico image; the
	// sidecar images are only needed when sidecar injection is enabled.
	imageSet, err := imageset.GetImageSet(ctx, ci.Client, in.Variant)
	if err != nil {
		return ci, nil, extensions.Degradedf(operatorv1.ResourceReadError, "error getting ImageSet: %w", err)
	}
	calicoImage, err := components.GetReference(components.CombinedCalicoImage(in), in.Registry, in.ImagePath, in.ImagePrefix, imageSet)
	if err != nil {
		return ci, nil, extensions.Degradedf(operatorv1.ResourceUpdateError, "error with images from ImageSet: %w", err)
	}

	var l7EnvoyImage, dikastesImage string
	if applicationLayer != nil &&
		applicationLayer.Spec.SidecarInjection != nil &&
		*applicationLayer.Spec.SidecarInjection == operatorv1.SidecarEnabled {
		l7EnvoyImage, err = components.GetReference(components.ComponentEnvoyProxy, in.Registry, in.ImagePath, in.ImagePrefix, imageSet)
		if err != nil {
			return ci, nil, extensions.Degradedf(operatorv1.ResourceUpdateError, "error with images from ImageSet: %w", err)
		}
		dikastesImage, err = components.GetReference(components.ComponentDikastes, in.Registry, in.ImagePath, in.ImagePrefix, imageSet)
		if err != nil {
			return ci, nil, extensions.Degradedf(operatorv1.ResourceUpdateError, "error with images from ImageSet: %w", err)
		}
	}

	// On a multi-tenant management cluster, each tenant's calico-apiserver ServiceAccount is
	// granted Linseed access via a single ClusterRoleBinding with one subject per tenant
	// namespace. Zero/single-tenant clusters leave this empty - the calico-system API server
	// is covered by its own binding.
	var bindingNamespaces []string
	if e.opts.MultiTenant {
		bindingNamespaces, err = utils.TenantNamespaces(ctx, ci.Client, nil)
		if err != nil {
			return ci, nil, extensions.Degradedf(operatorv1.ResourceReadError, "error reading tenant namespaces: %w", err)
		}
	}

	ci.RenderInputs.TrustedBundle = trustedBundle
	ci.RenderInputs.Extension = apiServerRenderData{
		managementCluster:           managementCluster,
		managementClusterConnection: managementClusterConnection,
		applicationLayer:            applicationLayer,
		queryServerTLS:              queryServerTLS,
		keyValidatorConfig:          keyValidatorConfig,
		l7EnvoyImage:                l7EnvoyImage,
		dikastesImage:               dikastesImage,
		calicoImage:                 calicoImage,
		bindingNamespaces:           bindingNamespaces,
		cloud:                       e.opts.Cloud,
		rbacManagementEnabled:       rbacManagementEnabled,
	}
	return ci, nil, nil
}

// CalicoCleanup deletes the Enterprise API server objects a prior Enterprise
// installation left behind.
type CalicoCleanup struct{}

var _ extensions.APIServerExtension = CalicoCleanup{}

func (CalicoCleanup) ExtendInputs(_ context.Context, ci controller.Inputs) (controller.Inputs, []certificatemanagement.KeyPairInterface, error) {
	return ci, nil, nil
}

func (CalicoCleanup) Watches(ctrlruntime.Controller) error {
	return nil
}

func (CalicoCleanup) Modify(c render.Component, ri render.Inputs) render.Component {
	t, ok := c.(render.APIServerComponent)
	if !ok {
		return c
	}

	return extensions.Decorate(c, ri, operatorv1.Calico, func(create, del []client.Object) ([]client.Object, []client.Object) {
		return cleanupAPIServer(ri, t.APIServerConfig(), create, del)
	})
}

// modifyAPIServer layers Calico Enterprise behavior onto the rendered API server objects:
// the query server container and its volumes, audit logging on the aggregation API server
// container, the Enterprise RBAC objects, and the query server port on the Service.
func modifyAPIServer(ri render.Inputs, cfg *render.APIServerConfiguration, create, del []client.Object) ([]client.Object, []client.Object) {
	data := apiServerData(ri)
	c := &apiServer{cfg: cfg, calicoImage: data.calicoImage, data: data}

	// Ensure the deployment and its supporting objects exist. The base renders them when
	// running an aggregation API server; in v3-CRD mode it queues them for deletion, but
	// Enterprise always runs a query server, so render the skeleton ourselves and pull
	// those objects back out of the delete list.
	create, del = c.ensureDeployment(create, del)

	if dep, ok := extensions.FindObject[*appsv1.Deployment](create, render.APIServerName); ok {
		c.layerDeployment(dep)
	}
	if svc, ok := extensions.FindObject[*corev1.Service](create, render.APIServerServiceName); ok {
		c.addServicePorts(svc)
	}
	// Enterprise serves staged policies through the tiered-policy passthrough role.
	if role, ok := extensions.FindObject[*rbacv1.ClusterRole](create, render.TieredPolicyPassthruClusterRoleName); ok {
		for i := range role.Rules {
			if slices.Contains(role.Rules[i].Resources, "networkpolicies") {
				role.Rules[i].Resources = append(role.Rules[i].Resources, "stagednetworkpolicies", "stagedglobalnetworkpolicies")
			}
		}
	}

	// The L7 sidecar mutating webhook is driven by ApplicationLayer. The base always
	// queues it for deletion; when sidecar injection is on, render it and pull it back
	// out of the delete list.
	if c.isSidecarInjectionEnabled() {
		create = append(create, c.sidecarMutatingWebhookConfig())
		del = removeByRef(del, &admregv1.MutatingWebhookConfiguration{ObjectMeta: metav1.ObjectMeta{Name: common.SidecarMutatingWebhookConfigName}})
	}

	// Global Enterprise RBAC.
	create = append(create, c.tigeraAPIServerClusterRole(), c.tigeraAPIServerClusterRoleBinding())
	if c.cfg.MultiTenant {
		// Grant each tenant's calico-apiserver identity Linseed access. Bound across every tenant
		// namespace via one ClusterRoleBinding (see linseedAccessClusterRoleBinding).
		create = append(create, c.linseedAccessClusterRole(), c.linseedAccessClusterRoleBinding())
	} else {
		// These resources are only installed in zero-tenant clusters.
		create = append(create, c.tigeraUserClusterRole(), c.tigeraNetworkAdminClusterRole())
		del = append(del, c.linseedAccessClusterRoleBinding(), c.linseedAccessClusterRole())
	}
	if c.data.managementCluster != nil {
		create = append(create, c.managedClusterWatchClusterRole())
		if c.cfg.MultiTenant {
			create = append(create, c.multiTenantSecretsRBAC()...)
			create = append(create, c.multiTenantManagedClusterAccessClusterRoles()...)
		} else {
			create = append(create, c.secretsRBAC()...)
		}
	} else {
		// If we're not a management cluster, the API server doesn't need permissions to access secrets.
		del = append(del, c.multiTenantSecretsRBAC()...)
		del = append(del, c.secretsRBAC()...)
		del = append(del, c.multiTenantManagedClusterAccessClusterRoles()...)
		del = append(del, c.managedClusterWatchClusterRole())
	}

	// Namespaced Enterprise objects.
	if c.cfg.TrustedBundle != nil {
		create = append(create, c.cfg.TrustedBundle.ConfigMap(render.QueryserverNamespace))
	}
	if c.data.managementClusterConnection != nil {
		create = append(create, c.externalLinseedRoleBinding())
	}

	// Objects that only exist alongside the aggregation API server.
	aggregationObjects := []client.Object{
		c.uiSettingsGroupGetterClusterRole(),
		c.kubeControllerManagerUISettingsGroupGetterClusterRoleBinding(),
		c.uiSettingsPassthruClusterRole(),
		c.uiSettingsPassthruClusterRolebinding(),
		c.auditPolicyConfigMap(),
	}
	if c.cfg.RequiresAggregationServer {
		create = append(create, aggregationObjects...)
	} else {
		del = append(del, aggregationObjects...)
	}

	// Clean up cluster-scoped resources that were created with the 'tigera' prefix.
	if !c.cfg.HoldAPIServiceCutover {
		del = append(del, c.deprecatedResources()...)
	}

	// Re-apply deployment overrides so the modifier-added query server container picks up
	// any per-container overrides. The override appliers use replace/merge semantics, so
	// re-running over the render-applied containers is idempotent.
	if dep, ok := extensions.FindObject[*appsv1.Deployment](create, render.APIServerName); ok {
		if overrides := c.cfg.APIServer.APIServerDeployment; overrides != nil {
			rcomp.ApplyDeploymentOverrides(dep, overrides)
		}
	}

	return create, del
}

// cleanupAPIServer deletes the Enterprise API server objects when running Calico, so a
// cluster switched from Enterprise to Calico does not leave them behind.
func cleanupAPIServer(ri render.Inputs, cfg *render.APIServerConfiguration, create, del []client.Object) ([]client.Object, []client.Object) {
	c := &apiServer{cfg: cfg}

	del = append(del, c.tigeraAPIServerClusterRole(), c.tigeraAPIServerClusterRoleBinding())
	del = append(del, c.linseedAccessClusterRoleBinding(), c.linseedAccessClusterRole())
	if !c.cfg.MultiTenant {
		del = append(del, c.tigeraUserClusterRole(), c.tigeraNetworkAdminClusterRole())
	}
	del = append(del, c.multiTenantSecretsRBAC()...)
	del = append(del, c.secretsRBAC()...)
	del = append(del, c.multiTenantManagedClusterAccessClusterRoles()...)
	del = append(del, c.managedClusterWatchClusterRole())

	return create, del
}

// layerDeployment adds the Enterprise additions to the rendered API server deployment:
// the query server container (and, under certificate management, its init container and
// volume), audit logging and the management-cluster tunnel args on the aggregation API
// server container, the L7 admission controller sidecar, and the Linseed token and
// trusted bundle volumes.
func (c *apiServer) layerDeployment(d *appsv1.Deployment) {
	spec := &d.Spec.Template.Spec
	if d.Spec.Template.Annotations == nil {
		d.Spec.Template.Annotations = map[string]string{}
	}

	// Audit logging and the management-cluster tunnel args are layered onto the
	// aggregation API server container, which is only present when that server runs.
	if c.cfg.RequiresAggregationServer {
		{
			ctr := render.MustContainer(spec, render.APIServerContainerName)
			ctr.VolumeMounts = append(ctr.VolumeMounts,
				corev1.VolumeMount{Name: auditLogsVolumeName, MountPath: "/var/log/calico/audit"},
				corev1.VolumeMount{Name: auditPolicyVolumeName, MountPath: "/etc/tigera/audit"},
			)
			ctr.Args = append(ctr.Args,
				"--audit-policy-file=/etc/tigera/audit/policy.conf",
				"--audit-log-path=/var/log/calico/audit/tsee-audit.log",
			)
			ctr.Args = append(ctr.Args, c.managementClusterArgs()...)
			// In case of OpenShift, apiserver needs privileged access to write audit logs to the
			// host path volume. Audit logs are owned by root on hosts so we need to be root.
			ctr.SecurityContext = securitycontext.NewRootContext(c.cfg.OpenShift)
		}

		spec.Volumes = append(spec.Volumes, c.auditVolumes()...)
	}

	spec.Containers = append(spec.Containers, c.queryServerContainer())
	if c.isSidecarInjectionEnabled() {
		spec.Containers = append(spec.Containers, c.l7AdmissionControllerContainer())
	}

	// Under certificate management the query server gets its own cert init container and
	// volume, since apiserver and queryserver may run with different UID:GID.
	if c.data.queryServerTLS != nil {
		init := c.data.queryServerTLS.InitContainer(render.APIServerNamespace, securitycontext.NewNonRootContext())
		spec.InitContainers = append(spec.InitContainers, init)
		spec.Volumes = append(spec.Volumes, c.data.queryServerTLS.Volume())
		d.Spec.Template.Annotations[c.data.queryServerTLS.HashAnnotationKey()] = c.data.queryServerTLS.HashAnnotationValue()
	}

	if c.data.managementClusterConnection != nil {
		// Optional: the Secret is delivered over the Guardian tunnel, which can't be
		// established until calico-apiserver is Ready.
		spec.Volumes = append(spec.Volumes, corev1.Volume{
			Name: render.LinseedTokenVolumeName,
			VolumeSource: corev1.VolumeSource{
				Secret: &corev1.SecretVolumeSource{
					SecretName: fmt.Sprintf(render.LinseedTokenSecret, "calico-apiserver"),
					Items:      []corev1.KeyToPath{{Key: render.LinseedTokenKey, Path: render.LinseedTokenSubPath}},
					Optional:   ptr.To(true),
				},
			},
		})
	}

	if c.cfg.TrustedBundle != nil {
		spec.Volumes = append(spec.Volumes, c.cfg.TrustedBundle.Volume())
		for k, v := range c.cfg.TrustedBundle.HashAnnotations() {
			d.Spec.Template.Annotations[k] = v
		}
	}
}

// managementClusterArgs returns the aggregation API server tunnel args for a management
// cluster, or nil when this isn't one.
func (c *apiServer) managementClusterArgs() []string {
	mc := c.data.managementCluster
	if mc == nil {
		return nil
	}
	args := []string{"--enable-managed-clusters-create-api=true"}
	if mc.Spec.Address != "" {
		args = append(args, fmt.Sprintf("--managementClusterAddr=%s", mc.Spec.Address))
	}
	if mc.Spec.TLS != nil && mc.Spec.TLS.SecretName != "" {
		if mc.Spec.TLS.SecretName == render.ManagerTLSSecretName {
			args = append(args, "--managementClusterCAType=Public")
		}
		args = append(args, fmt.Sprintf("--tunnelSecretName=%s", mc.Spec.TLS.SecretName))
	}
	return args
}

// ensureDeployment makes sure the API server Deployment and its supporting objects are
// in the create list. The base renders them when running an aggregation API server; when
// it doesn't (v3-CRD mode), it queues them for deletion, so render the skeleton and pull
// those objects back out of the delete list.
func (c *apiServer) ensureDeployment(create, del []client.Object) ([]client.Object, []client.Object) {
	if _, ok := extensions.FindObject[*appsv1.Deployment](create, render.APIServerName); ok {
		return create, del
	}
	skeleton := render.APIServerDeploymentObjects(c.cfg, c.calicoImage)
	create = append(create, skeleton...)
	for _, obj := range render.APIServerDeploymentObjectMeta() {
		del = removeByRef(del, obj)
	}
	return create, del
}

// removeByRef returns del with any object matching ref's kind, namespace, and name
// removed.
func removeByRef(del []client.Object, ref client.Object) []client.Object {
	out := del[:0:0]
	for _, o := range del {
		if reflect.TypeOf(o) == reflect.TypeOf(ref) &&
			o.GetNamespace() == ref.GetNamespace() &&
			o.GetName() == ref.GetName() {
			continue
		}
		out = append(out, o)
	}
	return out
}

// addServicePorts adds the query server port and, when sidecar injection is enabled, the
// L7 admission controller port to the API server Service.
func (c *apiServer) addServicePorts(s *corev1.Service) {
	queryServerTargetPort := render.GetContainerPort(c.cfg, render.TigeraAPIServerQueryServerContainerName)
	s.Spec.Ports = append(s.Spec.Ports, corev1.ServicePort{
		Name:       render.QueryServerPortName,
		Port:       render.QueryServerPort,
		Protocol:   corev1.ProtocolTCP,
		TargetPort: intstr.FromInt32(queryServerTargetPort.ContainerPort),
	})
	if c.isSidecarInjectionEnabled() {
		l7Port := render.GetContainerPort(c.cfg, render.L7AdmissionControllerContainerName)
		s.Spec.Ports = append(s.Spec.Ports, corev1.ServicePort{
			Name:       render.L7AdmissionControllerPortName,
			Port:       render.L7AdmissionControllerPort,
			Protocol:   corev1.ProtocolTCP,
			TargetPort: intstr.FromInt32(l7Port.ContainerPort),
		})
	}
}

// l7AdmissionControllerContainer is the L7 admission controller sidecar, rendered when
// ApplicationLayer sidecar injection is enabled.
func (c *apiServer) l7AdmissionControllerContainer() corev1.Container {
	volumeMounts := []corev1.VolumeMount{
		c.cfg.TLSKeyPair.VolumeMount(rmeta.OSTypeLinux),
	}

	l7Port := render.GetContainerPort(c.cfg, render.L7AdmissionControllerContainerName).ContainerPort

	dataplane := "iptables"
	if c.cfg.Installation.IsNftables() {
		dataplane = "nftables"
	}

	return corev1.Container{
		Name:    render.L7AdmissionControllerContainerName,
		Image:   c.calicoImage,
		Command: []string{components.CalicoBinaryPath, "component", "l7-admission-controller"},
		Env: []corev1.EnvVar{
			{Name: "L7ADMCTRL_TLSCERTPATH", Value: c.cfg.TLSKeyPair.VolumeMountCertificateFilePath()},
			{Name: "L7ADMCTRL_TLSKEYPATH", Value: c.cfg.TLSKeyPair.VolumeMountKeyFilePath()},
			{Name: "L7ADMCTRL_ENVOYIMAGE", Value: c.data.l7EnvoyImage},
			{Name: "L7ADMCTRL_DIKASTESIMAGE", Value: c.data.dikastesImage},
			{Name: "L7ADMCTRL_LISTENADDR", Value: fmt.Sprintf(":%d", l7Port)},
			{Name: "DATAPLANE", Value: dataplane},
		},
		VolumeMounts: volumeMounts,
		LivenessProbe: &corev1.Probe{
			ProbeHandler: corev1.ProbeHandler{
				HTTPGet: &corev1.HTTPGetAction{
					Path:   "/live",
					Port:   intstr.FromInt32(l7Port),
					Scheme: corev1.URISchemeHTTPS,
				},
			},
		},
	}
}

// sidecarMutatingWebhookConfig is the L7 sidecar injection webhook, rendered when
// ApplicationLayer sidecar injection is enabled.
func (c *apiServer) sidecarMutatingWebhookConfig() *admregv1.MutatingWebhookConfiguration {
	var cacert []byte
	svcPort := render.GetContainerPort(c.cfg, render.L7AdmissionControllerContainerName).ContainerPort

	svcpath := "/sidecar-webhook"
	svcref := admregv1.ServiceReference{
		Name:      render.QueryserverServiceName,
		Namespace: render.QueryserverNamespace,
		Path:      &svcpath,
		Port:      &svcPort,
	}
	failpol := admregv1.Fail
	labelsel := metav1.LabelSelector{
		MatchLabels: map[string]string{
			"applicationlayer.projectcalico.org/sidecar": "true",
		},
	}
	rules := []admregv1.RuleWithOperations{
		{
			Rule: admregv1.Rule{
				APIGroups:   []string{""},
				APIVersions: []string{"v1"},
				Resources:   []string{"pods"},
			},
			Operations: []admregv1.OperationType{admregv1.Create},
		},
	}
	sidefx := admregv1.SideEffectClassNone
	if !c.cfg.TLSKeyPair.UseCertificateManagement() {
		cacert = c.cfg.TLSKeyPair.GetIssuer().GetCertificatePEM()
	} else {
		cacert = c.cfg.Installation.CertificateManagement.CACert
	}
	return &admregv1.MutatingWebhookConfiguration{
		TypeMeta: metav1.TypeMeta{
			Kind:       "MutatingWebhookConfiguration",
			APIVersion: "admissionregistration.k8s.io/v1",
		},
		ObjectMeta: metav1.ObjectMeta{Name: common.SidecarMutatingWebhookConfigName},
		Webhooks: []admregv1.MutatingWebhook{
			{
				AdmissionReviewVersions: []string{"v1"},
				ClientConfig: admregv1.WebhookClientConfig{
					Service:  &svcref,
					CABundle: cacert,
				},
				Name:           "sidecar.projectcalico.org",
				FailurePolicy:  &failpol,
				ObjectSelector: &labelsel,
				Rules:          rules,
				SideEffects:    &sidefx,
			},
		},
	}
}

// modifyAPIServerPolicy adds the enterprise additions to the API server network policy:
// the OIDC egress rule (when an OIDC key validator is configured) and the L7 admission
// controller ingress port (when sidecar injection is enabled). The base policy carries
// neither.
func modifyAPIServerPolicy(ri render.Inputs, cfg *render.APIServerConfiguration, create, del []client.Object) ([]client.Object, []client.Object) {
	c := &apiServer{cfg: cfg, data: apiServerData(ri)}

	policy, ok := extensions.FindObject[*v3.NetworkPolicy](create, render.APIServerPolicyName)
	if !ok {
		return create, del
	}

	// Insert the OIDC egress rule before the trailing Pass rule so it is evaluated.
	if c.data.keyValidatorConfig != nil {
		if parsedURL, err := url.Parse(c.data.keyValidatorConfig.Issuer()); err == nil {
			oidc := networkpolicy.GetOIDCEgressRule(parsedURL)
			egress := policy.Spec.Egress
			if n := len(egress); n > 0 && egress[n-1].Action == v3.Pass {
				policy.Spec.Egress = append(egress[:n-1:n-1], oidc, egress[n-1])
			} else {
				policy.Spec.Egress = append(egress, oidc)
			}
		}
	}

	// Allow the kube-apiserver to reach the L7 admission controller.
	if c.isSidecarInjectionEnabled() {
		l7Port := render.GetContainerPort(c.cfg, render.L7AdmissionControllerContainerName).ContainerPort
		for i := range policy.Spec.Ingress {
			policy.Spec.Ingress[i].Destination.Ports = append(policy.Spec.Ingress[i].Destination.Ports,
				numorstring.Port{MinPort: uint16(l7Port), MaxPort: uint16(l7Port)})
		}
	}

	return create, del
}

// auditVolumes are the host-path audit log and audit policy volumes used by the
// aggregation API server container.
func (c *apiServer) auditVolumes() []corev1.Volume {
	return []corev1.Volume{
		{
			Name: auditLogsVolumeName,
			VolumeSource: corev1.VolumeSource{
				HostPath: &corev1.HostPathVolumeSource{
					Path: "/var/log/calico/audit",
					Type: ptr.To(corev1.HostPathDirectoryOrCreate),
				},
			},
		},
		{
			Name: auditPolicyVolumeName,
			VolumeSource: corev1.VolumeSource{
				ConfigMap: &corev1.ConfigMapVolumeSource{
					LocalObjectReference: corev1.LocalObjectReference{Name: auditPolicyVolumeName},
					Items: []corev1.KeyToPath{
						{
							Key:  "config",
							Path: "policy.conf",
						},
					},
				},
			},
		},
	}
}

func (c *apiServer) multiTenantSecretsRBAC() []client.Object {
	return render.TunnelSecretRBAC(render.APIServerSecretsRBACName, render.APIServerServiceAccountName, c.data.managementCluster, true)
}

func (c *apiServer) secretsRBAC() []client.Object {
	return render.TunnelSecretRBAC(render.APIServerSecretsRBACName, render.APIServerServiceAccountName, c.data.managementCluster, false)
}

// linseedAccessClusterRole is a minimal, least-privilege ClusterRole granting the calico-apiserver
// identity read access to Linseed policy activity data (for queryserver enrichment). On a multi-tenant
// management cluster it is bound to each tenant's calico-apiserver ServiceAccount so that tenant's
// managed clusters can reach Linseed. The full backing-storage/queryserver rules live on the
// calico-apiserver ClusterRole, which is bound only to the calico-system API server itself.
//
// Calico Enterprise, multi-tenant only.
func (c *apiServer) linseedAccessClusterRole() *rbacv1.ClusterRole {
	return &rbacv1.ClusterRole{
		TypeMeta:   metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{Name: linseedAccessClusterRoleName},
		Rules: []rbacv1.PolicyRule{
			{
				// Read access to Linseed policy activity data for queryserver enrichment.
				APIGroups: []string{"linseed.tigera.io"},
				Resources: []string{"policyactivity"},
				Verbs:     []string{"get"},
			},
		},
	}
}

// linseedAccessClusterRoleBinding binds the Linseed-access ClusterRole to the calico-apiserver
// ServiceAccount in each tenant namespace. Linseed authorizes with a cluster-scoped
// SubjectAccessReview, so this is a single ClusterRoleBinding with one ServiceAccount subject per
// tenant namespace - mirroring how compliance, intrusion-detection, and the manager grant their
// managed-cluster components Linseed access.
//
// Calico Enterprise, multi-tenant only.
func (c *apiServer) linseedAccessClusterRoleBinding() *rbacv1.ClusterRoleBinding {
	return rcomp.ClusterRoleBinding(linseedAccessClusterRoleName, linseedAccessClusterRoleName, render.APIServerServiceAccountName, c.data.bindingNamespaces)
}

func (c *apiServer) queryServerContainer() corev1.Container {
	queryServerTargetPort := render.GetContainerPort(c.cfg, render.TigeraAPIServerQueryServerContainerName).ContainerPort

	var tlsSecret certificatemanagement.KeyPairInterface
	if c.data.queryServerTLS != nil {
		tlsSecret = c.data.queryServerTLS
	} else {
		tlsSecret = c.cfg.TLSKeyPair
	}
	env := []corev1.EnvVar{
		{Name: "DATASTORE_TYPE", Value: "kubernetes"},
		{Name: "LISTEN_ADDR", Value: fmt.Sprintf(":%d", queryServerTargetPort)},
		{Name: "TLS_CERT", Value: fmt.Sprintf("/%s/tls.crt", tlsSecret.GetName())},
		{Name: "TLS_KEY", Value: fmt.Sprintf("/%s/tls.key", tlsSecret.GetName())},
	}
	if c.cfg.TrustedBundle != nil {
		env = append(env, corev1.EnvVar{Name: "TRUSTED_BUNDLE_PATH", Value: c.cfg.TrustedBundle.MountPath()})
	}

	if render.HostNetwork(c.cfg) {
		env = append(env, c.cfg.K8SServiceEndpoint.EnvVars()...)
	} else {
		env = append(env, c.cfg.K8SServiceEndpointPodNetwork.EnvVars()...)
	}

	if c.cfg.Installation.CalicoNetwork != nil && c.cfg.Installation.CalicoNetwork.MultiInterfaceMode != nil {
		env = append(env, corev1.EnvVar{Name: "MULTI_INTERFACE_MODE", Value: c.cfg.Installation.CalicoNetwork.MultiInterfaceMode.Value()})
	}

	if c.data.keyValidatorConfig != nil {
		env = append(env, c.data.keyValidatorConfig.RequiredEnv("")...)
	}

	linseedURL := relasticsearch.LinseedEndpoint(rmeta.OSTypeLinux, c.cfg.ClusterDomain, render.ElasticsearchNamespace, c.data.managementClusterConnection != nil, false)
	env = append(env,
		corev1.EnvVar{Name: "LINSEED_URL", Value: linseedURL},
		corev1.EnvVar{Name: "LINSEED_CLIENT_CERT", Value: fmt.Sprintf("/%s/tls.crt", tlsSecret.GetName())},
		corev1.EnvVar{Name: "LINSEED_CLIENT_KEY", Value: fmt.Sprintf("/%s/tls.key", tlsSecret.GetName())},
	)
	if c.data.managementClusterConnection != nil {
		env = append(env,
			corev1.EnvVar{Name: "CLUSTER_ID", Value: ""},
			corev1.EnvVar{Name: "LINSEED_TOKEN", Value: render.GetLinseedTokenPath(true)},
		)
	}
	if c.cfg.TrustedBundle != nil {
		env = append(env, corev1.EnvVar{Name: "LINSEED_CA", Value: c.cfg.TrustedBundle.MountPath()})
	}

	// set LogLEVEL for queryserver container
	if logging := c.cfg.APIServer.Logging; logging != nil &&
		logging.QueryServerLogging != nil && logging.QueryServerLogging.LogSeverity != nil {
		env = append(env,
			corev1.EnvVar{Name: "LOGLEVEL", Value: strings.ToLower(string(*logging.QueryServerLogging.LogSeverity))})
	} else {
		// set default LOGLEVEL to info when not set by the user
		env = append(env, corev1.EnvVar{Name: "LOGLEVEL", Value: "info"})
	}

	volumeMounts := []corev1.VolumeMount{
		tlsSecret.VolumeMount(rmeta.OSTypeLinux),
	}
	if c.cfg.TrustedBundle != nil {
		volumeMounts = append(volumeMounts, c.cfg.TrustedBundle.VolumeMounts(rmeta.OSTypeLinux)...)
	}
	if c.data.managementClusterConnection != nil {
		volumeMounts = append(volumeMounts, corev1.VolumeMount{
			Name:      render.LinseedTokenVolumeName,
			MountPath: render.LinseedVolumeMountPath,
		})
	}

	container := corev1.Container{
		Name:    render.TigeraAPIServerQueryServerContainerName,
		Image:   c.calicoImage,
		Command: []string{components.CalicoBinaryPath, "component", "queryserver"},
		Env:     env,
		LivenessProbe: &corev1.Probe{
			ProbeHandler: corev1.ProbeHandler{
				HTTPGet: &corev1.HTTPGetAction{
					Path:   "/version",
					Port:   intstr.FromInt32(queryServerTargetPort),
					Scheme: corev1.URISchemeHTTPS,
				},
			},
			InitialDelaySeconds: 90,
		},
		SecurityContext: securitycontext.NewNonRootContext(),
		VolumeMounts:    volumeMounts,
	}
	return container
}

func (c *apiServer) externalLinseedRoleBinding() *rbacv1.RoleBinding {
	return &rbacv1.RoleBinding{
		TypeMeta: metav1.TypeMeta{Kind: "RoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "tigera-linseed",
			Namespace: render.APIServerNamespace,
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "ClusterRole",
			Name:     render.TigeraLinseedSecretsClusterRole,
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      "ServiceAccount",
				Name:      render.GuardianServiceAccountName,
				Namespace: render.GuardianNamespace,
			},
		},
	}
}

func (c *apiServer) tigeraAPIServerClusterRole() *rbacv1.ClusterRole {
	rules := []rbacv1.PolicyRule{
		{
			// Read access to Linseed policy activity data for queryserver enrichment.
			APIGroups: []string{"linseed.tigera.io"},
			Resources: []string{"policyactivity"},
			Verbs:     []string{"get"},
		},
		{
			// Calico Enterprise backing storage.
			APIGroups: []string{"projectcalico.org", "crd.projectcalico.org"},
			Resources: []string{
				"alertexceptions",
				"bfdconfigurations",
				"deeppacketinspections",
				"deeppacketinspections/status",
				"egressgatewaypolicies",
				"externalnetworks",
				"globalalerts",
				"globalalerts/status",
				"globalalerttemplates",
				"globalreports",
				"globalreports/status",
				"globalreporttypes",
				"globalthreatfeeds",
				"globalthreatfeeds/status",
				"licensekeys",
				"managedclusters",
				"managedclusters/status",
				"networks",
				"packetcaptures",
				"packetcaptures/status",
				"policyrecommendationscopes",
				"policyrecommendationscopes/status",
				"remoteclusterconfigurations",
				"securityeventwebhooks",
				"securityeventwebhooks/status",
				"uisettings",
				"uisettingsgroups",
			},
			Verbs: []string{
				"get",
				"list",
				"watch",
				"create",
				"update",
				"delete",
				"patch",
			},
		},
		{
			// The queryserver's RBAC calculator needs to list tiers,
			// uisettingsgroups, and managedclusters via the aggregated
			// API to evaluate user permissions for the /policies endpoint.
			APIGroups: []string{"projectcalico.org"},
			Resources: []string{
				"tiers",
				"uisettingsgroups",
				"managedclusters",
			},
			Verbs: []string{"get", "list", "watch"},
		},
		{
			// Required by the AuthorizationReview calculator in queryserver to evaluate
			// RBAC permissions for users.
			APIGroups: []string{"rbac.authorization.k8s.io"},
			Resources: []string{
				"clusterroles",
				"clusterrolebindings",
				"roles",
				"rolebindings",
			},
			Verbs: []string{"get", "list", "watch"},
		},
	}

	return &rbacv1.ClusterRole{
		TypeMeta: metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name: render.APIServerName,
		},
		Rules: rules,
	}
}

func (c *apiServer) tigeraAPIServerClusterRoleBinding() *rbacv1.ClusterRoleBinding {
	return &rbacv1.ClusterRoleBinding{
		TypeMeta: metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name: render.APIServerName,
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      "ServiceAccount",
				Name:      render.APIServerServiceAccountName,
				Namespace: render.APIServerNamespace,
			},
		},
		RoleRef: rbacv1.RoleRef{
			Kind:     "ClusterRole",
			Name:     render.APIServerName,
			APIGroup: "rbac.authorization.k8s.io",
		},
	}
}

func (c *apiServer) uiSettingsGroupGetterClusterRole() *rbacv1.ClusterRole {
	return &rbacv1.ClusterRole{
		TypeMeta: metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name: "calico-uisettingsgroup-getter",
		},
		Rules: []rbacv1.PolicyRule{
			{
				APIGroups: []string{"projectcalico.org"},
				Resources: []string{
					"uisettingsgroups",
				},
				Verbs: []string{"get"},
			},
		},
	}
}

func (c *apiServer) kubeControllerManagerUISettingsGroupGetterClusterRoleBinding() *rbacv1.ClusterRoleBinding {
	return &rbacv1.ClusterRoleBinding{
		TypeMeta: metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name: "calico-uisettingsgroup-getter",
		},
		RoleRef: rbacv1.RoleRef{
			Kind:     "ClusterRole",
			Name:     "calico-uisettingsgroup-getter",
			APIGroup: "rbac.authorization.k8s.io",
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:     "User",
				Name:     "system:kube-controller-manager",
				APIGroup: "rbac.authorization.k8s.io",
			},
		},
	}
}

func (c *apiServer) tigeraUserClusterRole() *rbacv1.ClusterRole {
	rules := []rbacv1.PolicyRule{
		// List requests that the Tigera manager needs.
		{
			APIGroups: []string{
				"projectcalico.org",
				"networking.k8s.io",
				"extensions",
				"",
			},
			// Use both the networkpolicies and tier.networkpolicies resource types to ensure identical behavior
			// irrespective of the Calico RBAC scheme (see the ClusterRole "calico-tiered-policy-passthrough" for
			// more details).  Similar for all tiered policy resource types.
			Resources: []string{
				"tiers",
				"networkpolicies",
				"tier.networkpolicies",
				"globalnetworkpolicies",
				"tier.globalnetworkpolicies",
				"namespaces",
				"globalnetworksets",
				"networksets",
				"managedclusters",
				"stagedglobalnetworkpolicies",
				"tier.stagedglobalnetworkpolicies",
				"stagednetworkpolicies",
				"tier.stagednetworkpolicies",
				"stagedkubernetesnetworkpolicies",
				"policyrecommendationscopes",
			},
			Verbs: []string{"watch", "list"},
		},
		{
			APIGroups: []string{"policy.networking.k8s.io"},
			Resources: []string{
				"clusternetworkpolicies",
				"adminnetworkpolicies",
				"baselineadminnetworkpolicies",
			},
			Verbs: []string{"watch", "list"},
		},
		{
			APIGroups: []string{"projectcalico.org"},
			Resources: []string{"packetcaptures/files"},
			Verbs:     []string{"get"},
		},
		{
			APIGroups: []string{"projectcalico.org"},
			Resources: []string{"packetcaptures"},
			Verbs:     []string{"get", "list", "watch"},
		},
		// Allow the user to view Networks.
		{
			APIGroups: []string{"projectcalico.org"},
			Resources: []string{"networks"},
			Verbs:     []string{"get", "list", "watch"},
		},
		// Additional "list" requests required to view flows.
		{
			APIGroups: []string{""},
			Resources: []string{"pods"},
			Verbs:     []string{"list"},
		},
		// Additional "list" requests required to view serviceaccount labels.
		{
			APIGroups: []string{""},
			Resources: []string{"serviceaccounts"},
			Verbs:     []string{"list"},
		},
		// Access for WAF API to read in coreruleset configmap
		{
			APIGroups:     []string{""},
			Resources:     []string{"configmaps"},
			ResourceNames: []string{"coreruleset-default"},
			Verbs:         []string{"get"},
		},
		// Access to statistics.
		{
			APIGroups: []string{""},
			Resources: []string{"services/proxy"},
			ResourceNames: []string{
				"https:calico-api:8080", "calico-node-prometheus:9090",
			},
			Verbs: []string{"get", "create"},
		},
		// Access to policies in all tiers
		{
			APIGroups: []string{"projectcalico.org"},
			Resources: []string{"tiers"},
			Verbs:     []string{"get"},
		},
		// List and download the reports in the Tigera Secure manager.
		{
			APIGroups: []string{"projectcalico.org"},
			Resources: []string{"globalreports"},
			Verbs:     []string{"get", "list"},
		},
		{
			APIGroups: []string{"projectcalico.org"},
			Resources: []string{"globalreporttypes"},
			Verbs:     []string{"get"},
		},
		{
			APIGroups: []string{"projectcalico.org"},
			Resources: []string{"clusterinformations"},
			Verbs:     []string{"get", "list"},
		},
		// Access to hostendpoints from the UI ServiceGraph.
		{
			APIGroups: []string{"projectcalico.org"},
			Resources: []string{"hostendpoints"},
			Verbs:     []string{"get", "list"},
		},
		// List and view the threat defense configuration
		{
			APIGroups: []string{"projectcalico.org"},
			Resources: []string{
				"alertexceptions",
				"globalalerts",
				"globalalerts/status",
				"globalalerttemplates",
				"globalthreatfeeds",
				"globalthreatfeeds/status",
				"securityeventwebhooks",
			},
			Verbs: []string{"get", "watch", "list"},
		},
	}

	// User can:
	// - read UISettings in the cluster-settings group (not on Calico Cloud, which only exposes
	//   per-user UISettings)
	// - read and write UISettings in the user-settings group
	// Default settings group and settings are created in manager.go.
	if c.data.cloud {
		rules = append(rules,
			rbacv1.PolicyRule{
				APIGroups:     []string{"projectcalico.org"},
				Resources:     []string{"uisettingsgroups"},
				Verbs:         []string{"get"},
				ResourceNames: []string{"user-settings"},
			},
		)
	} else {
		rules = append(rules,
			rbacv1.PolicyRule{
				APIGroups:     []string{"projectcalico.org"},
				Resources:     []string{"uisettingsgroups"},
				Verbs:         []string{"get"},
				ResourceNames: []string{"cluster-settings", "user-settings"},
			},
			rbacv1.PolicyRule{
				APIGroups:     []string{"projectcalico.org"},
				Resources:     []string{"uisettingsgroups/data"},
				Verbs:         []string{"get", "list", "watch"},
				ResourceNames: []string{"cluster-settings"},
			},
		)
	}

	rules = append(rules, []rbacv1.PolicyRule{
		{
			APIGroups:     []string{"projectcalico.org"},
			Resources:     []string{"uisettingsgroups/data"},
			Verbs:         []string{"*"},
			ResourceNames: []string{"user-settings"},
		},
		// Allow the user to read applicationlayers to detect if WAF is enabled/disabled.
		{
			APIGroups: []string{"operator.tigera.io"},
			Resources: []string{"applicationlayers", "packetcaptureapis", "compliances", "intrusiondetections"},
			Verbs:     []string{"get"},
		},
		// Allow the user to read the gatewayapis CR to detect if Gateway API is enabled/disabled.
		{
			APIGroups: []string{"operator.tigera.io"},
			Resources: []string{"gatewayapis"},
			Verbs:     []string{"get"},
		},
		// Allow the user to read Gateways and HTTPRoutes to offer as WAF policy attach targets.
		{
			APIGroups: []string{"gateway.networking.k8s.io"},
			Resources: []string{"gateways", "httproutes"},
			Verbs:     []string{"get", "list", "watch"},
		},
		// Allow the user to view WAF policies, plugins, and validation policies.
		{
			APIGroups: []string{"applicationlayer.projectcalico.org"},
			Resources: []string{
				"globalwafpolicies",
				"globalwafplugins",
				"globalwafvalidationpolicies",
				"wafpolicies",
				"wafplugins",
				"wafvalidationpolicies",
			},
			Verbs: []string{"get", "watch", "list"},
		},
		{
			APIGroups: []string{"apps"},
			Resources: []string{"deployments"},
			Verbs:     []string{"get", "list", "watch"},
		},
		// Allow the user to read services to view WAF configuration.
		{
			APIGroups: []string{""},
			Resources: []string{"services"},
			Verbs:     []string{"get", "list", "watch"},
		},
		// Allow the user to read felixconfigurations to detect if wireguard and/or other features are enabled.
		{
			APIGroups: []string{"projectcalico.org"},
			Resources: []string{"felixconfigurations"},
			Verbs:     []string{"get", "list"},
		},
		// Allow the user to only view securityeventwebhooks.
		{
			APIGroups: []string{"projectcalico.org", "crd.projectcalico.org"},
			Resources: []string{"securityeventwebhooks"},
			Verbs:     []string{"get", "list"},
		},
	}...)

	// Privileges for lma.tigera.io have no effect on managed clusters.
	if c.data.managementClusterConnection == nil {
		// Access to flow logs, audit logs, and statistics, plus logging into Kibana for oidc users.
		// Calico Cloud also gets runtime logs.
		resourceNames := []string{"flows", "audit*", "l7", "events", "dns", "waf", "kibana_login", "recommendations"}
		if c.data.cloud {
			resourceNames = append([]string{"runtime"}, resourceNames...)
		}
		rules = append(rules, rbacv1.PolicyRule{
			APIGroups:     []string{"lma.tigera.io"},
			Resources:     []string{"*"},
			ResourceNames: resourceNames,
			Verbs:         []string{"get"},
		})
	}

	return &rbacv1.ClusterRole{
		TypeMeta: metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name: "tigera-ui-user",
		},
		Rules: rules,
	}
}

func (c *apiServer) tigeraNetworkAdminClusterRole() *rbacv1.ClusterRole {
	rules := []rbacv1.PolicyRule{
		// Full access to all network policies
		{
			APIGroups: []string{
				"projectcalico.org",
				"networking.k8s.io",
				"extensions",
			},
			// Use both the networkpolicies and tier.networkpolicies resource types to ensure identical behavior
			// irrespective of the Calico RBAC scheme (see the ClusterRole "calico-tiered-policy-passthrough" for
			// more details).  Similar for all tiered policy resource types.
			Resources: []string{
				"tiers",
				"networkpolicies",
				"tier.networkpolicies",
				"globalnetworkpolicies",
				"tier.globalnetworkpolicies",
				"stagedglobalnetworkpolicies",
				"tier.stagedglobalnetworkpolicies",
				"stagednetworkpolicies",
				"tier.stagednetworkpolicies",
				"stagedkubernetesnetworkpolicies",
				"globalnetworksets",
				"networksets",
				"managedclusters",
				"packetcaptures",
				"policyrecommendationscopes",
			},
			Verbs: []string{"create", "update", "delete", "patch", "get", "watch", "list"},
		},
		{
			APIGroups: []string{
				"policy.networking.k8s.io",
			},
			Resources: []string{
				"clusternetworkpolicies",
				"adminnetworkpolicies",
				"baselineadminnetworkpolicies",
			},
			Verbs: []string{"create", "update", "delete", "patch", "get", "watch", "list"},
		},
		{
			APIGroups: []string{"projectcalico.org"},
			Resources: []string{"packetcaptures/files"},
			Verbs:     []string{"get", "delete"},
		},
		// Allow the user to CRUD Networks.
		{
			APIGroups: []string{"projectcalico.org"},
			Resources: []string{"networks"},
			Verbs:     []string{"create", "update", "delete", "patch", "get", "watch", "list"},
		},
		// Additional "list" requests that the Tigera Secure manager needs
		{
			APIGroups: []string{""},
			Resources: []string{"namespaces"},
			Verbs:     []string{"watch", "list"},
		},
		// Additional "list" requests required to view flows.
		{
			APIGroups: []string{""},
			Resources: []string{"pods"},
			Verbs:     []string{"list"},
		},
		// Additional "list" requests required to view serviceaccount labels.
		{
			APIGroups: []string{""},
			Resources: []string{"serviceaccounts"},
			Verbs:     []string{"list"},
		},
		// Access for WAF API to read in coreruleset configmap
		{
			APIGroups:     []string{""},
			Resources:     []string{"configmaps"},
			ResourceNames: []string{"coreruleset-default"},
			Verbs:         []string{"get"},
		},
		// Access to statistics.
		{
			APIGroups: []string{""},
			Resources: []string{"services/proxy"},
			ResourceNames: []string{
				"https:calico-api:8080", "calico-node-prometheus:9090",
			},
			Verbs: []string{"get", "create"},
		},
		// Manage globalreport configuration, view report generation status, and list reports in the Tigera Secure manager.
		{
			APIGroups: []string{"projectcalico.org"},
			Resources: []string{"globalreports"},
			Verbs:     []string{"*"},
		},
		{
			APIGroups: []string{"projectcalico.org"},
			Resources: []string{"globalreports/status"},
			Verbs:     []string{"get", "list", "watch"},
		},
		// List and download the reports in the Tigera Secure manager.
		{
			APIGroups: []string{"projectcalico.org"},
			Resources: []string{"globalreporttypes"},
			Verbs:     []string{"get"},
		},
		// Access to cluster information containing Calico and EE versions from the UI.
		{
			APIGroups: []string{"projectcalico.org"},
			Resources: []string{"clusterinformations"},
			Verbs:     []string{"get", "list"},
		},
		// Access to hostendpoints from the UI ServiceGraph.
		{
			APIGroups: []string{"projectcalico.org"},
			Resources: []string{"hostendpoints"},
			Verbs:     []string{"get", "list"},
		},
		// Manage the threat defense configuration
		{
			APIGroups: []string{"projectcalico.org"},
			Resources: []string{
				"alertexceptions",
				"globalalerts",
				"globalalerts/status",
				"globalalerttemplates",
				"globalthreatfeeds",
				"globalthreatfeeds/status",
				"securityeventwebhooks",
			},
			Verbs: []string{"create", "update", "delete", "patch", "get", "watch", "list"},
		},
	}

	// User can:
	// - read and write UISettings in the cluster-settings group, and rename the group (not on Calico
	//   Cloud, which only exposes per-user UISettings)
	// - read and write UISettings in the user-settings group, and rename the group
	// Default settings group and settings are created in manager.go.
	if c.data.cloud {
		rules = append(rules,
			rbacv1.PolicyRule{
				APIGroups:     []string{"projectcalico.org"},
				Resources:     []string{"uisettingsgroups"},
				Verbs:         []string{"get"},
				ResourceNames: []string{"user-settings"},
			},
			rbacv1.PolicyRule{
				APIGroups:     []string{"projectcalico.org"},
				Resources:     []string{"uisettingsgroups/data"},
				Verbs:         []string{"*"},
				ResourceNames: []string{"user-settings"},
			},
		)
	} else {
		rules = append(rules,
			rbacv1.PolicyRule{
				APIGroups:     []string{"projectcalico.org"},
				Resources:     []string{"uisettingsgroups"},
				Verbs:         []string{"get", "patch", "update"},
				ResourceNames: []string{"cluster-settings", "user-settings"},
			},
			rbacv1.PolicyRule{
				APIGroups:     []string{"projectcalico.org"},
				Resources:     []string{"uisettingsgroups/data"},
				Verbs:         []string{"*"},
				ResourceNames: []string{"cluster-settings", "user-settings"},
			},
		)
	}

	rules = append(rules, []rbacv1.PolicyRule{
		// Allow the user to read and write applicationlayers to enable/disable WAF.
		{
			APIGroups: []string{"operator.tigera.io"},
			Resources: []string{"applicationlayers", "packetcaptureapis", "compliances", "intrusiondetections"},
			Verbs:     []string{"get", "update", "patch", "create", "delete"},
		},
		// Allow the user to read the gatewayapis CR to detect if Gateway API is enabled/disabled.
		{
			APIGroups: []string{"operator.tigera.io"},
			Resources: []string{"gatewayapis"},
			Verbs:     []string{"get"},
		},
		// Allow the user to read Gateways and HTTPRoutes to offer as WAF policy attach targets.
		{
			APIGroups: []string{"gateway.networking.k8s.io"},
			Resources: []string{"gateways", "httproutes"},
			Verbs:     []string{"get", "list", "watch"},
		},
		// Allow the user to manage WAF policies, plugins, and validation policies.
		{
			APIGroups: []string{"applicationlayer.projectcalico.org"},
			Resources: []string{
				"globalwafpolicies",
				"globalwafplugins",
				"globalwafvalidationpolicies",
				"wafpolicies",
				"wafplugins",
				"wafvalidationpolicies",
			},
			Verbs: []string{"create", "update", "delete", "patch", "get", "watch", "list"},
		},
		// Allow the user to read deployments to view WAF configuration.
		{
			APIGroups: []string{"apps"},
			Resources: []string{"deployments"},
			Verbs:     []string{"get", "list", "watch", "patch"},
		},
		{
			APIGroups: []string{""},
			Resources: []string{"services"},
			Verbs:     []string{"get", "list", "watch", "patch"},
		},
		// Allow the user to read felixconfigurations to detect if wireguard and/or other features are enabled.
		{
			APIGroups: []string{"projectcalico.org"},
			Resources: []string{"felixconfigurations"},
			Verbs:     []string{"get", "list"},
		},
		// Allow the user to perform CRUD operations on securityeventwebhooks.
		{
			APIGroups: []string{"projectcalico.org", "crd.projectcalico.org"},
			Resources: []string{"securityeventwebhooks"},
			Verbs:     []string{"get", "list", "update", "patch", "create", "delete"},
		},
		// Allow the user to create secrets.
		{
			APIGroups: []string{""},
			Resources: []string{
				"secrets",
			},
			Verbs: []string{"create"},
		},
		// Allow the user to patch webhooks-secret secret.
		{
			APIGroups: []string{""},
			Resources: []string{
				"secrets",
			},
			ResourceNames: []string{
				"webhooks-secret",
			},
			Verbs: []string{"patch"},
		},
	}...)

	// ui-apis writes these impersonating the caller, so the apiserver enforces escalation
	// against the user's own permissions.
	if c.data.rbacManagementEnabled {
		rules = append(rules,
			rbacv1.PolicyRule{
				APIGroups: []string{"rbac.authorization.k8s.io"},
				Resources: []string{"clusterroles", "roles"},
				Verbs:     []string{"get", "list", "watch"},
			},
			rbacv1.PolicyRule{
				APIGroups: []string{"rbac.authorization.k8s.io"},
				Resources: []string{"clusterrolebindings", "rolebindings"},
				Verbs:     []string{"get", "list", "watch", "create", "update", "delete"},
			},
		)
	}

	// Privileges for lma.tigera.io have no effect on managed clusters.
	if c.data.managementClusterConnection == nil {
		// Access to flow logs, audit logs, and statistics, plus Elasticsearch superuser access once
		// logged into Kibana. Calico Cloud also gets runtime logs.
		resourceNames := []string{"flows", "audit*", "l7", "events", "dns", "waf", "kibana_login", "elasticsearch_superuser", "recommendations"}
		if c.data.cloud {
			resourceNames = append([]string{"runtime"}, resourceNames...)
		}
		rules = append(rules, rbacv1.PolicyRule{
			APIGroups:     []string{"lma.tigera.io"},
			Resources:     []string{"*"},
			ResourceNames: resourceNames,
			Verbs:         []string{"get"},
		})
	}

	// In v3 CRD / webhooks mode there is no aggregated apiserver, and the
	// calico-uisettings-passthrough ClusterRole that normally grants the broad
	// uisettings permission isn't deployed. Grant write verbs here so the
	// calico-webhooks UISettings handler (which narrows access via a SAR on
	// uisettingsgroups/data) gets invoked instead of being short-circuited by
	// kube-apiserver RBAC.
	if !c.cfg.RequiresAggregationServer {
		rules = append(rules, rbacv1.PolicyRule{
			APIGroups: []string{"projectcalico.org"},
			Resources: []string{"uisettings"},
			Verbs:     []string{"create", "update", "delete", "patch"},
		})
	}

	return &rbacv1.ClusterRole{
		TypeMeta: metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name: "tigera-network-admin",
		},
		Rules: rules,
	}
}

func (c *apiServer) uiSettingsPassthruClusterRole() *rbacv1.ClusterRole {
	return &rbacv1.ClusterRole{
		TypeMeta: metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name: "calico-uisettings-passthrough",
		},
		Rules: []rbacv1.PolicyRule{
			{
				APIGroups: []string{"projectcalico.org"},
				Resources: []string{"uisettings"},
				Verbs:     []string{"*"},
			},
		},
	}
}

func (c *apiServer) uiSettingsPassthruClusterRolebinding() *rbacv1.ClusterRoleBinding {
	return &rbacv1.ClusterRoleBinding{
		TypeMeta: metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name: "calico-uisettings-passthrough",
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:     "Group",
				Name:     "system:authenticated",
				APIGroup: "rbac.authorization.k8s.io",
			},
		},
		RoleRef: rbacv1.RoleRef{
			Kind:     "ClusterRole",
			Name:     "calico-uisettings-passthrough",
			APIGroup: "rbac.authorization.k8s.io",
		},
	}
}

func (c *apiServer) auditPolicyConfigMap() *corev1.ConfigMap {
	const defaultAuditPolicy = `apiVersion: audit.k8s.io/v1
kind: Policy
rules:
- level: RequestResponse
  omitStages:
  - RequestReceived
  verbs:
  - create
  - patch
  - update
  - delete
  resources:
  - group: projectcalico.org
    resources:
    - globalnetworkpolicies
    - networkpolicies
    - stagedglobalnetworkpolicies
    - stagednetworkpolicies
    - stagedkubernetesnetworkpolicies
    - globalnetworksets
    - networksets
    - tiers
    - hostendpoints`

	return &corev1.ConfigMap{
		TypeMeta: metav1.TypeMeta{Kind: "ConfigMap", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{
			// This object is for Enterprise only, so pass it explicitly.
			Namespace: render.APIServerNamespace,
			Name:      auditPolicyVolumeName,
		},
		Data: map[string]string{
			"config": defaultAuditPolicy,
		},
	}
}

func (c *apiServer) multiTenantManagedClusterAccessClusterRoles() []client.Object {
	var objects []client.Object
	objects = append(objects, &rbacv1.ClusterRole{
		TypeMeta:   metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{Name: render.MultiTenantManagedClustersAccessClusterRoleName},
		Rules: []rbacv1.PolicyRule{
			{
				APIGroups: []string{"projectcalico.org"},
				Resources: []string{"managedclusters"},
				Verbs: []string{
					// The Authentication Proxy in Voltron checks if Enterprise Components (using impersonation headers for
					// the service in the canonical namespace) can get a managed clusters before sending the request down the tunnel.
					// This ClusterRole will be assigned to each component using a RoleBinding in the canonical or tenant namespace.
					"get",
				},
			},
		},
	})

	return objects
}

func (c *apiServer) managedClusterWatchClusterRole() client.Object {
	return &rbacv1.ClusterRole{
		TypeMeta:   metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{Name: render.ManagedClustersWatchClusterRoleName},
		Rules: []rbacv1.PolicyRule{
			{
				APIGroups: []string{"projectcalico.org"},
				Resources: []string{"managedclusters"},
				Verbs: []string{
					"get", "list", "watch",
				},
			},
		},
	}
}

func (c *apiServer) deprecatedResources() []client.Object {
	return []client.Object{
		&rbacv1.ClusterRole{
			TypeMeta:   metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"},
			ObjectMeta: metav1.ObjectMeta{Name: "tigera-extension-apiserver-secrets-access"},
		},
		&rbacv1.ClusterRoleBinding{
			TypeMeta:   metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"},
			ObjectMeta: metav1.ObjectMeta{Name: "tigera-extension-apiserver-secrets-access"},
		},

		// delegateAuthClusterRoleBinding
		&rbacv1.ClusterRoleBinding{
			TypeMeta:   metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"},
			ObjectMeta: metav1.ObjectMeta{Name: "tigera-apiserver-delegate-auth"},
		},

		// authClusterRole
		&rbacv1.ClusterRole{
			TypeMeta:   metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"},
			ObjectMeta: metav1.ObjectMeta{Name: "tigera-extension-apiserver-auth-access"},
		},

		// authClusterRoleBinding
		&rbacv1.ClusterRoleBinding{
			TypeMeta:   metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"},
			ObjectMeta: metav1.ObjectMeta{Name: "tigera-extension-apiserver-auth-access"},
		},
		// authReaderRoleBinding - need clean up in diff namespace kube-system
		&rbacv1.RoleBinding{
			TypeMeta: metav1.TypeMeta{Kind: "RoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"},
			ObjectMeta: metav1.ObjectMeta{
				Name:      "tigera-auth-reader",
				Namespace: "kube-system",
			},
		},
		// webhookReaderClusterRole
		&rbacv1.ClusterRole{
			TypeMeta:   metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"},
			ObjectMeta: metav1.ObjectMeta{Name: "tigera-webhook-reader"},
		},

		// webhookReaderClusterRoleBinding
		&rbacv1.ClusterRoleBinding{
			TypeMeta:   metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"},
			ObjectMeta: metav1.ObjectMeta{Name: "tigera-apiserver-webhook-reader"},
		},

		// calico-apiserver CR and CRB
		&rbacv1.ClusterRole{
			TypeMeta:   metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"},
			ObjectMeta: metav1.ObjectMeta{Name: "tigera-apiserver"},
		},
		&rbacv1.ClusterRoleBinding{
			TypeMeta:   metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"},
			ObjectMeta: metav1.ObjectMeta{Name: "tigera-apiserver"},
		},

		&rbacv1.ClusterRole{
			TypeMeta:   metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"},
			ObjectMeta: metav1.ObjectMeta{Name: "tigera-uisettingsgroup-getter"},
		},
		&rbacv1.ClusterRoleBinding{
			TypeMeta:   metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"},
			ObjectMeta: metav1.ObjectMeta{Name: "tigera-uisettingsgroup-getter"},
		},

		&rbacv1.ClusterRole{
			TypeMeta:   metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"},
			ObjectMeta: metav1.ObjectMeta{Name: "tigera-tiered-policy-passthrough"},
		},
		&rbacv1.ClusterRoleBinding{
			TypeMeta:   metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"},
			ObjectMeta: metav1.ObjectMeta{Name: "tigera-tiered-policy-passthrough"},
		},

		&rbacv1.ClusterRole{
			TypeMeta:   metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"},
			ObjectMeta: metav1.ObjectMeta{Name: "tigera-uisettings-passthrough"},
		},
		&rbacv1.ClusterRoleBinding{
			TypeMeta:   metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"},
			ObjectMeta: metav1.ObjectMeta{Name: "tigera-uisettings-passthrough"},
		},

		// Clean up legacy secrets in the tigera-operator namespace
		&corev1.Secret{
			TypeMeta:   metav1.TypeMeta{Kind: "Secret", APIVersion: "v1"},
			ObjectMeta: metav1.ObjectMeta{Name: "tigera-api-cert", Namespace: common.OperatorNamespace()},
		},
	}
}
