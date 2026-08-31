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

package installation

import (
	"context"
	"strings"

	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	rbacv1 "k8s.io/api/rbac/v1"
	apiextenv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/components"
	"github.com/tigera/operator/pkg/controller"

	"github.com/tigera/operator/pkg/controller/utils"
	"github.com/tigera/operator/pkg/ctrlruntime"
	"github.com/tigera/operator/pkg/dns"
	"github.com/tigera/operator/pkg/enterprise/render/monitor"
	eutils "github.com/tigera/operator/pkg/enterprise/utils"
	"github.com/tigera/operator/pkg/extensions"
	"github.com/tigera/operator/pkg/imports/crds"
	"github.com/tigera/operator/pkg/render"
	relasticsearch "github.com/tigera/operator/pkg/render/common/elasticsearch"
	"github.com/tigera/operator/pkg/render/common/rbacmanagement"
	"github.com/tigera/operator/pkg/render/kubecontrollers"
	"github.com/tigera/operator/pkg/tls/certificatemanagement"
)

// installationRenderData is the controller-produced data the installation
// extension hands to its modifiers through Inputs.Extension. The node
// modifier type-asserts it back out.
type installationRenderData struct {
	nodePrometheusTLS certificatemanagement.KeyPairInterface

	// kubeControllerTLS is the calico-kube-controllers metrics serving keypair; the
	// kube-controllers modifier mounts it onto the deployment.
	kubeControllerTLS certificatemanagement.KeyPairInterface

	// collectProcessPath mirrors LogCollector.Spec.CollectProcessPath being
	// enabled; the node modifier uses it to set HostPID and the felix env.
	collectProcessPath bool

	// calico-kube-controllers enterprise additions the kube-controllers modifier
	// applies: the enterprise cluster role rules, the enterprise enabled controllers,
	// and the WAF v3 (Gateway API add-on) surface.
	kubeControllerRules       []rbacv1.PolicyRule
	kubeControllerControllers []string

	// rbacManagementEnabled mirrors the rbac-ui-config gate; the kube-controllers
	// modifier uses it to create the rbacsync controller's namespaced Role/RoleBinding.
	rbacManagementEnabled bool

	// managedCluster reports whether this is a managed cluster, which decides whether
	// kube-controllers reaches the manager through Guardian or directly.
	managedCluster bool

	// managementCluster reports whether this is a management cluster, which is what
	// gives kube-controllers the managed-cluster watch binding.
	managementCluster bool

	waf wafRenderData

	// nonClusterHost carries the second Typha the typha modifier renders.
	nonClusterHost nonClusterHostRenderData
}

// installationData pulls the installation extension's render data back out of the
// render inputs, returning the zero value when none is set.
func installationData(ri render.Inputs) installationRenderData {
	return render.ExtractExtensionData[installationRenderData](ri)
}

func collectProcessPathEnabled(lc *operatorv1.LogCollector) bool {
	return lc != nil &&
		lc.Spec.CollectProcessPath != nil &&
		*lc.Spec.CollectProcessPath == operatorv1.CollectProcessPathEnable
}

// ProductVersion is the release the operator reports in status. The Enterprise
// operator also manages Calico variant installs, during migration.
func (e *Extension) ProductVersion(install *operatorv1.InstallationSpec) string {
	if !install.Variant.IsEnterprise() {
		return components.CalicoRelease
	}
	return components.EnterpriseRelease
}

// DefaultFelixConfiguration sets the Enterprise-only FelixConfiguration defaults.
// Some platforms run a DNS service that isn't named "kube-dns", so dnsTrustedServers
// needs a provider-specific default for Enterprise DNS logging to work. Returns
// whether it changed fc.
func (e *Extension) DefaultFelixConfiguration(install *operatorv1.InstallationSpec, fc *v3.FelixConfiguration) (bool, error) {
	dnsService := ""
	switch install.KubernetesProvider {
	case operatorv1.ProviderOpenShift:
		dnsService = "k8s-service:openshift-dns/dns-default"
	case operatorv1.ProviderRKE2:
		dnsService = "k8s-service:kube-system/rke2-coredns-rke2-coredns"
	}
	if dnsService == "" {
		return false, nil
	}

	felixDefault := "k8s-service:kube-dns"
	trustedServers := []string{dnsService}
	// Keep any other values that are already configured, excepting the value we are
	// setting and the kube-dns default.
	existingSetting := ""
	if fc.Spec.DNSTrustedServers != nil {
		existingSetting = strings.Join(*fc.Spec.DNSTrustedServers, ",")
		for _, server := range *fc.Spec.DNSTrustedServers {
			if server != felixDefault && server != dnsService {
				trustedServers = append(trustedServers, server)
			}
		}
	}
	if strings.Join(trustedServers, ",") == existingSetting {
		return false, nil
	}
	fc.Spec.DNSTrustedServers = &trustedServers
	return true, nil
}

// Watches registers the enterprise resources the installation controller
// reconciles on.
func (e *Extension) Watches(c ctrlruntime.Controller) error {
	for _, obj := range []client.Object{
		&operatorv1.ManagementCluster{},
		&operatorv1.ManagementClusterConnection{},
		&operatorv1.LogCollector{},
		// GatewayAPI.spec.extensions.waf.state gates the WAF v3 surface on calico-kube-controllers.
		&operatorv1.GatewayAPI{},
	} {
		if err := c.WatchObject(obj, &handler.EnqueueRequestForObject{}); err != nil {
			return err
		}
	}
	// The switch gating the rbacsync controller and its RBAC.
	if err := utils.AddConfigMapWatch(c, rbacmanagement.ConfigMapName, common.CalicoNamespace, &handler.EnqueueRequestForObject{}); err != nil {
		return err
	}

	// The core controller watches the Calico CRDs; these are the ones this variant adds.
	if e.opts.ManageCRDs {
		if err := utils.AddCRDWatches(c, enterpriseOnlyCRDs(e.opts.UseV3CRDs)); err != nil {
			return err
		}
	}

	// es-kube-controllers includes the manager internal TLS secret in its bundle.
	return utils.AddSecretsWatch(c, render.ManagerInternalTLSSecretName, common.OperatorNamespace())
}

// ExtendInputs does the controller-side work the modifiers can't: creating and
// fetching the certificates that feed the trusted bundle. It returns the render
// inputs carrying the produced node prometheus keypair, and that keypair as one
// the controller should manage.
func (e *Extension) ExtendInputs(ctx context.Context, ci controller.Inputs) (controller.Inputs, []certificatemanagement.KeyPairInterface, error) {
	if err := ValidateReporterPort(ci.RenderInputs.FelixConfiguration); err != nil {
		return ci, nil, err
	}

	// Goldmane is Calico-only, so an Enterprise installation can't run alongside it.
	if ci.RenderInputs.Installation.Variant == operatorv1.CalicoEnterprise {
		if err := validateNoGoldmane(ctx, ci.Client); err != nil {
			return ci, nil, err
		}
	}

	nodePrometheusTLS, err := ci.CertificateManager.GetOrCreateKeyPair(
		ci.Client,
		render.NodePrometheusTLSServerSecret,
		common.OperatorNamespace(),
		dns.GetServiceDNSNames(render.CalicoNodeMetricsService, common.CalicoNamespace, ci.RenderInputs.ClusterDomain),
	)
	if err != nil {
		return ci, nil, extensions.Degradedf(operatorv1.ResourceCreateError, "error creating node prometheus TLS certificate: %w", err)
	}
	if nodePrometheusTLS != nil {
		ci.RenderInputs.TrustedBundle.AddCertificates(nodePrometheusTLS)
	}

	// The calico-kube-controllers metrics endpoint is served with mTLS in
	// Enterprise; the keypair is created here (cluster side effect) and mounted by
	// the kube-controllers modifier.
	kubeControllerTLS, err := ci.CertificateManager.GetOrCreateKeyPair(
		ci.Client,
		kubecontrollers.KubeControllerPrometheusTLSSecret,
		common.OperatorNamespace(),
		dns.GetServiceDNSNames(kubecontrollers.KubeControllerMetrics, common.CalicoNamespace, ci.RenderInputs.ClusterDomain),
	)
	if err != nil {
		return ci, nil, extensions.Degradedf(operatorv1.ResourceReadError, "error finding or creating the kube-controllers metrics TLS certificate: %w", err)
	}
	if kubeControllerTLS != nil {
		ci.RenderInputs.TrustedBundle.AddCertificates(kubeControllerTLS)
	}

	logCollector, err := eutils.GetLogCollector(ctx, ci.Client)
	if err != nil {
		return ci, nil, extensions.Degradedf(operatorv1.ResourceReadError, "error reading LogCollector: %w", err)
	}

	// calico-kube-controllers enterprise additions: the WAF surface, the enterprise
	// cluster role rules, and the enterprise enabled controllers. A managed cluster's
	// kube-controllers needs an extra license-push rule.
	managementClusterConnection, err := utils.GetManagementClusterConnection(ctx, ci.Client)
	if err != nil {
		return ci, nil, extensions.Degradedf(operatorv1.ResourceReadError, "error reading ManagementClusterConnection: %w", err)
	}

	managementCluster, err := eutils.GetManagementCluster(ctx, ci.Client)
	if err != nil {
		return ci, nil, extensions.Degradedf(operatorv1.ResourceReadError, "error reading ManagementCluster: %w", err)
	}
	if managementCluster != nil && managementClusterConnection != nil {
		return ci, nil, extensions.InvalidConfigf("having both a ManagementCluster and a ManagementClusterConnection is not supported")
	}
	waf, wafWebhookTLS, err := buildWAFData(ctx, ci)
	if err != nil {
		return ci, nil, err
	}

	nonClusterHost, nonClusterHostTyphaTLS, err := buildNonClusterHostData(ctx, ci)
	if err != nil {
		return ci, nil, err
	}
	if nonClusterHost.enabled && !ci.Terminating {
		if err := e.ensureTyphaAutoscaler(ci); err != nil {
			return ci, nil, err
		}
	}

	// The rbacsync controller reconciles the ClusterRoles backing the Manager UI's
	// RBAC management feature.
	rbacManagementEnabled, err := utils.RBACManagementEnabled(ctx, ci.Client, e.variant, e.opts.MultiTenant)
	if err != nil {
		return ci, nil, extensions.Degradedf(operatorv1.ResourceReadError, "error reading the RBAC management UI ConfigMap: %w", err)
	}

	ci.RenderInputs.Extension = installationRenderData{
		nodePrometheusTLS:         nodePrometheusTLS,
		kubeControllerTLS:         kubeControllerTLS,
		collectProcessPath:        collectProcessPathEnabled(logCollector),
		kubeControllerRules:       calicoKubeControllersEnterpriseRules(waf.gatewayAPIPresent, managementClusterConnection != nil, rbacManagementEnabled),
		kubeControllerControllers: calicoKubeControllersEnterpriseControllers(waf.gatewayAPIPresent, rbacManagementEnabled),
		rbacManagementEnabled:     rbacManagementEnabled,
		managedCluster:            managementClusterConnection != nil,
		managementCluster:         managementCluster != nil,
		waf:                       waf,
		nonClusterHost:            nonClusterHost,
	}

	prometheusClientCert, err := ci.CertificateManager.GetCertificate(ci.Client, monitor.PrometheusClientTLSSecretName, common.OperatorNamespace())
	if err != nil {
		return ci, nil, extensions.Degradedf(operatorv1.CertificateError, "unable to fetch prometheus certificate: %w", err)
	}
	if prometheusClientCert != nil {
		ci.RenderInputs.TrustedBundle.AddCertificates(prometheusClientCert)
	}

	esgwCertificate, err := ci.CertificateManager.GetCertificate(ci.Client, relasticsearch.PublicCertSecret, common.OperatorNamespace())
	if err != nil {
		return ci, nil, extensions.Degradedf(operatorv1.CertificateError, "failed to retrieve / validate %s: %w", relasticsearch.PublicCertSecret, err)
	}
	if esgwCertificate != nil {
		ci.RenderInputs.TrustedBundle.AddCertificates(esgwCertificate)
	}

	// es-kube-controllers talks to Voltron, so the shared bundle must trust the
	// manager internal cert.
	managerInternalTLS, err := ci.CertificateManager.GetCertificate(ci.Client, render.ManagerInternalTLSSecretName, common.OperatorNamespace())
	if err != nil {
		return ci, nil, extensions.Degradedf(operatorv1.ResourceReadError, "failed to retrieve %s: %w", render.ManagerInternalTLSSecretName, err)
	}
	if managerInternalTLS != nil {
		ci.RenderInputs.TrustedBundle.AddCertificates(managerInternalTLS)
	}

	var managed []certificatemanagement.KeyPairInterface
	if nodePrometheusTLS != nil {
		managed = append(managed, nodePrometheusTLS)
	}
	if kubeControllerTLS != nil {
		managed = append(managed, kubeControllerTLS)
	}
	if wafWebhookTLS != nil {
		managed = append(managed, wafWebhookTLS)
	}
	if nonClusterHostTyphaTLS != nil {
		managed = append(managed, nonClusterHostTyphaTLS)
	}
	return ci, managed, nil
}

// enterpriseOnlyCRDs is the Calico Enterprise CRD set minus the Calico set the core
// controller already watches.
func enterpriseOnlyCRDs(useV3 bool) []*apiextenv1.CustomResourceDefinition {
	calico := map[string]bool{}
	for _, crd := range crds.GetCRDs(operatorv1.Calico, useV3) {
		calico[crd.Name] = true
	}

	var out []*apiextenv1.CustomResourceDefinition
	for _, crd := range crds.GetCRDs(operatorv1.CalicoEnterprise, useV3) {
		if !calico[crd.Name] {
			out = append(out, crd)
		}
	}
	return out
}
