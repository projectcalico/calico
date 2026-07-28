// Copyright (c) 2019-2026 Tigera, Inc. All rights reserved.
//
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

package render

import (
	"encoding/json"
	"fmt"
	"net"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"sigs.k8s.io/controller-runtime/pkg/client"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/components"
	"github.com/tigera/operator/pkg/controller/k8sapi"
	"github.com/tigera/operator/pkg/controller/migration"
	rcomp "github.com/tigera/operator/pkg/render/common/components"
	"github.com/tigera/operator/pkg/render/common/configmap"
	rmeta "github.com/tigera/operator/pkg/render/common/meta"
	"github.com/tigera/operator/pkg/render/common/securitycontext"
	"github.com/tigera/operator/pkg/render/common/securitycontextconstraints"
	"github.com/tigera/operator/pkg/tls/certificatemanagement"
)

const (
	BirdTemplatesConfigMapName = "bird-templates"
	birdTemplateHashAnnotation = "hash.operator.tigera.io/bird-templates"
	BPFOperatorAnnotation      = "operator.tigera.io/bpfEnabled"

	DisableKubeProxyKey = "operator.tigera.io/disable-kube-proxy"

	nodeCniConfigAnnotation   = "hash.operator.tigera.io/cni-config"
	bgpLayoutHashAnnotation   = "hash.operator.tigera.io/bgp-layout"
	bgpBindModeHashAnnotation = "hash.operator.tigera.io/bgp-bind-mode"

	BGPLayoutConfigMapName            = "bgp-layout"
	BGPLayoutConfigMapKey             = "earlyNetworkConfiguration"
	BGPLayoutVolumeName               = "bgp-layout"
	BGPLayoutPath                     = "/etc/calico/early-networking.yaml"
	K8sSvcEndpointConfigMapName       = "kubernetes-services-endpoint"
	nodeTerminationGracePeriodSeconds = 5
	CNIFinalizer                      = "tigera.io/cni-protector"

	CalicoNodeMetricsService      = "calico-node-metrics"
	NodePrometheusTLSServerSecret = "calico-node-prometheus-server-tls"
	CalicoNodeObjectName          = "calico-node"
	CalicoCNIPluginObjectName     = "calico-cni-plugin"
	BPFVolumeName                 = "bpffs"

	goldmaneDomainName = "goldmane.calico-system.svc"
)

var (
	// The port used by calico/node to report Calico Enterprise BGP metrics.
	// This is currently not intended to be user configurable.
	nodeBGPReporterPort int32 = 9900

	NodeTLSSecretName               = "node-certs"
	NodeTLSSecretNameNonClusterHost = NodeTLSSecretName + TyphaNonClusterHostSuffix
)

// TyphaNodeTLS holds configuration for Node and Typha to establish TLS.
type TyphaNodeTLS struct {
	TrustedBundle             certificatemanagement.TrustedBundle
	TyphaSecret               certificatemanagement.KeyPairInterface
	TyphaSecretNonClusterHost certificatemanagement.KeyPairInterface
	TyphaCommonName           string
	TyphaURISAN               string
	NodeSecret                certificatemanagement.KeyPairInterface
	NodeCommonName            string
	NodeURISAN                string

	NodeNonClusterHostCommonName string
	NodeNonClusterHostURISAN     string
}

// NodeConfiguration is the public API used to provide information to the render code to
// generate Kubernetes objects for installing calico/node on a cluster.
type NodeConfiguration struct {
	GoldmaneRunning  bool
	K8sServiceEp     k8sapi.ServiceEndpoint
	K8sServiceAddrs  []k8sapi.ServiceEndpoint
	K8sEndpointSlice []k8sapi.ServiceEndpoint
	Installation     *operatorv1.InstallationSpec
	IPPools          []operatorv1.IPPool
	TLS              *TyphaNodeTLS
	ClusterDomain    string

	// Defaults for DNS.
	DefaultDNSPolicy corev1.DNSPolicy
	DefaultDNSConfig *corev1.PodDNSConfig

	// Goldmane IP, to avoid DNS resolution using kube-dns.
	GoldmaneIP string

	// Optional fields.
	LogCollector            *operatorv1.LogCollector
	MigrateNamespaces       bool
	NodeAppArmorProfile     string
	BirdTemplates           map[string]string
	NodeReporterMetricsPort int

	// CanRemoveCNIFinalizer specifies whether CNI plugin is still needed during uninstall since the CNI plugin and
	// associated RBAC resources are required for pod teardown to succeed. Setting this to true removes
	// the finalizer from the CNI plugin and associated RBAC resources, allowing them to be deleted.
	// For details on why this is needed see 'Node and Installation finalizer' in the core_controller.
	CanRemoveCNIFinalizer bool

	PrometheusServerTLS certificatemanagement.KeyPairInterface

	// BGPLayouts is returned by the rendering code after modifying its namespace
	// so that it can be deployed into the cluster.
	// TODO: The controller should pass the contents, the renderer should build its own
	// configmap, rather than this "copy" semantic.
	BGPLayouts *corev1.ConfigMap

	// The health port that Felix should bind to. The controller reads FelixConfiguration
	// and sets this.
	FelixHealthPort int

	// Node's CgroupV2Path override. The controller reads FelixConfiguration and sets this.
	NodeCgroupV2Path string

	// The bindMode read from the default BGPConfiguration. Used to trigger rolling updates
	// should this value change.
	BindMode string

	FelixPrometheusMetricsEnabled bool

	FelixPrometheusMetricsPort int

	V3CRDs bool
}

// Node creates the node daemonset and other resources for the daemonset to operate normally.
func Node(cfg *NodeConfiguration) Component {
	// Configure default values for any fields that might not be set.
	if cfg.DefaultDNSPolicy == "" {
		cfg.DefaultDNSPolicy = corev1.DNSClusterFirstWithHostNet
	}
	return &nodeComponent{cfg: cfg}
}

type nodeComponent struct {
	// Input configuration from the controller.
	cfg *NodeConfiguration

	// Calculated internal fields based on the given information.
	calicoImage     string
	cniPluginsImage string
	nodeImage       string
}

func (c *nodeComponent) ResolveImages(is *operatorv1.ImageSet) error {
	reg := c.cfg.Installation.Registry
	path := c.cfg.Installation.ImagePath
	prefix := c.cfg.Installation.ImagePrefix
	var errMsgs []string
	appendIfErr := func(imageName string, err error) string {
		if err != nil {
			errMsgs = append(errMsgs, err.Error())
		}
		return imageName
	}

	c.calicoImage = appendIfErr(components.GetReference(components.CombinedCalicoImage(c.cfg.Installation), reg, path, prefix, is))
	if c.installUpstreamPlugins() {
		if c.cfg.Installation.Variant.IsEnterprise() {
			c.cniPluginsImage = appendIfErr(components.GetReference(components.ComponentTigeraCNIPlugins, reg, path, prefix, is))
		} else {
			c.cniPluginsImage = appendIfErr(components.GetReference(components.ComponentCalicoCNIPlugins, reg, path, prefix, is))
		}
	}
	switch {
	case c.cfg.Installation.Variant.IsEnterprise():
		c.nodeImage = appendIfErr(components.GetReference(components.ComponentTigeraNode, reg, path, prefix, is))
	default:
		c.nodeImage = appendIfErr(components.GetReference(components.ComponentCalicoNode, reg, path, prefix, is))
	}

	if len(errMsgs) != 0 {
		return fmt.Errorf("%s", strings.Join(errMsgs, ","))
	}
	return nil
}

func (c *nodeComponent) SupportedOSType() rmeta.OSType {
	return rmeta.OSTypeLinux
}

func (c *nodeComponent) Objects() ([]client.Object, []client.Object) {
	objs := []client.Object{
		c.nodeServiceAccount(),
		c.nodeRole(),
		c.nodeRoleBinding(),
		c.cniPluginServiceAccount(),
		c.cniPluginRole(),
		c.cniPluginRoleBinding(),
	}

	// These are objects to keep even when we're terminating. They will be deleted by the Kubernetes
	// garbage collector when the Installation is finally deleted.
	objsToKeep := []client.Object{}

	if c.cfg.CanRemoveCNIFinalizer {
		objsToKeep = objs
		objs = []client.Object{}
	}

	if c.cfg.BGPLayouts != nil {
		objs = append(objs, configmap.ToRuntimeObjects(configmap.CopyToNamespace(common.CalicoNamespace, c.cfg.BGPLayouts)...)...)
	}

	var objsToDelete []client.Object

	if c.cfg.Installation.Variant.IsEnterprise() {
		// Include Service for exposing node metrics.
		objs = append(objs, c.nodeMetricsService())
	}

	cniConfig := c.nodeCNIConfigMap()
	if cniConfig != nil {
		objs = append(objs, cniConfig)
	}

	if btcm := c.birdTemplateConfigMap(); btcm != nil {
		objs = append(objs, btcm)
	}

	if c.cfg.Installation.KubernetesProvider.IsDockerEE() {
		objs = append(objs, c.clusterAdminClusterRoleBinding())
	}

	objs = append(objs, c.nodeDaemonset(cniConfig))

	if c.cfg.MigrateNamespaces {
		objs = append(objs, migration.ClusterRoleForKubeSystemNode())
		objs = append(objs, migration.ClusterRoleBindingForKubeSystemNode())
	} else {
		objsToDelete = append(objsToDelete, migration.ClusterRoleForKubeSystemNode())
		objsToDelete = append(objsToDelete, migration.ClusterRoleBindingForKubeSystemNode())
	}

	if c.cfg.CanRemoveCNIFinalizer {
		return objsToKeep, append(objs, objsToDelete...)
	}
	return objs, objsToDelete
}

func (c *nodeComponent) Ready() bool {
	return true
}

// CNIPluginFinalizedObjects returns a list of objects that use the CNIFinalizer that should be
// removed only after the CNI plugin is removed.
func CNIPluginFinalizedObjects() []client.Object {
	return []client.Object{
		&corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: CalicoNodeObjectName, Namespace: common.CalicoNamespace}},
		&corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: CalicoCNIPluginObjectName, Namespace: common.CalicoNamespace}},
		&rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: CalicoNodeObjectName}},
		&rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: CalicoCNIPluginObjectName}},
		&rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: CalicoNodeObjectName}},
		&rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: CalicoCNIPluginObjectName}},
	}
}

// nodeServiceAccount creates the node's service account.
func (c *nodeComponent) nodeServiceAccount() *corev1.ServiceAccount {
	finalizer := []string{}
	if !c.cfg.CanRemoveCNIFinalizer {
		finalizer = []string{CNIFinalizer}
	}

	return &corev1.ServiceAccount{
		TypeMeta: metav1.TypeMeta{Kind: "ServiceAccount", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:       CalicoNodeObjectName,
			Namespace:  common.CalicoNamespace,
			Finalizers: finalizer,
		},
	}
}

// cniPluginServiceAccount creates the Calico CNI plugin's service account.
func (c *nodeComponent) cniPluginServiceAccount() *corev1.ServiceAccount {
	finalizer := []string{}
	if !c.cfg.CanRemoveCNIFinalizer {
		finalizer = []string{CNIFinalizer}
	}

	return &corev1.ServiceAccount{
		TypeMeta: metav1.TypeMeta{Kind: "ServiceAccount", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:       CalicoCNIPluginObjectName,
			Namespace:  common.CalicoNamespace,
			Finalizers: finalizer,
		},
	}
}

// nodeRoleBinding creates a clusterrolebinding giving the node service account the required permissions to operate.
func (c *nodeComponent) nodeRoleBinding() *rbacv1.ClusterRoleBinding {
	finalizer := []string{}
	if !c.cfg.CanRemoveCNIFinalizer {
		finalizer = []string{CNIFinalizer}
	}
	crb := &rbacv1.ClusterRoleBinding{
		TypeMeta: metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:       CalicoNodeObjectName,
			Labels:     map[string]string{},
			Finalizers: finalizer,
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "ClusterRole",
			Name:     CalicoNodeObjectName,
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      "ServiceAccount",
				Name:      CalicoNodeObjectName,
				Namespace: common.CalicoNamespace,
			},
		},
	}
	if c.cfg.MigrateNamespaces {
		migration.AddBindingForKubeSystemNode(crb)
	}
	return crb
}

// cniPluginRoleBinding creates a rolebinding giving the Calico CNI plugin service account the required permissions to operate.
func (c *nodeComponent) cniPluginRoleBinding() *rbacv1.ClusterRoleBinding {
	finalizer := []string{}
	if !c.cfg.CanRemoveCNIFinalizer {
		finalizer = []string{CNIFinalizer}
	}
	crb := &rbacv1.ClusterRoleBinding{
		TypeMeta: metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:       CalicoCNIPluginObjectName,
			Finalizers: finalizer,
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "ClusterRole",
			Name:     CalicoCNIPluginObjectName,
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      "ServiceAccount",
				Name:      CalicoCNIPluginObjectName,
				Namespace: common.CalicoNamespace,
			},
		},
	}
	if c.cfg.MigrateNamespaces {
		migration.AddBindingForKubeSystemCNIPlugin(crb)
	}
	return crb
}

// nodeRole creates the clusterrole containing policy rules that allow the node daemonset to operate normally.
func (c *nodeComponent) nodeRole() *rbacv1.ClusterRole {
	finalizer := []string{}
	if !c.cfg.CanRemoveCNIFinalizer {
		finalizer = []string{CNIFinalizer}
	}
	role := &rbacv1.ClusterRole{
		TypeMeta: metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:       CalicoNodeObjectName,
			Labels:     map[string]string{},
			Finalizers: finalizer,
		},

		Rules: []rbacv1.PolicyRule{
			{
				// Calico uses endpoint slices for service-based network policy rules.
				APIGroups: []string{"discovery.k8s.io"},
				Resources: []string{"endpointslices"},
				Verbs:     []string{"list", "watch"},
			},
			{
				// The CNI plugin needs to get pods, nodes, namespaces.
				APIGroups: []string{""},
				Resources: []string{"pods", "nodes", "namespaces"},
				Verbs:     []string{"get"},
			},
			{
				// Used to discover Typha endpoints and service IPs for advertisement.
				APIGroups: []string{""},
				Resources: []string{"endpoints", "services"},
				Verbs:     []string{"watch", "list", "get"},
			},
			{
				// Some information is stored on the node status.
				APIGroups: []string{""},
				Resources: []string{"nodes/status"},
				Verbs:     []string{"patch", "update"},
			},
			{
				// For enforcing network policies.
				APIGroups: []string{"networking.k8s.io"},
				Resources: []string{"networkpolicies"},
				Verbs:     []string{"watch", "list"},
			},
			{
				// For enforcing k8s cluster network policies.
				APIGroups: []string{"policy.networking.k8s.io"},
				Resources: []string{
					"clusternetworkpolicies",
					"adminnetworkpolicies",
					"baselineadminnetworkpolicies",
				},
				Verbs: []string{"watch", "list"},
			},
			{
				// Metadata from these are used in conjunction with network policy.
				APIGroups: []string{""},
				Resources: []string{"pods", "namespaces", "serviceaccounts"},
				Verbs:     []string{"watch", "list"},
			},
			{
				// Calico patches the allocated IP onto the pod.
				APIGroups: []string{""},
				Resources: []string{"pods/status"},
				Verbs:     []string{"patch"},
			},
			{
				// Used for creating service account tokens to be used by the CNI plugin.
				APIGroups:     []string{""},
				Resources:     []string{"serviceaccounts/token"},
				ResourceNames: []string{CalicoCNIPluginObjectName},
				Verbs:         []string{"create"},
			},
			{
				// Calico needs to query configmaps for pool auto-detection on kubeadm.
				APIGroups: []string{""},
				Resources: []string{"configmaps"},
				Verbs:     []string{"get"},
			},
			{
				// For monitoring Calico-specific configuration.
				APIGroups: []string{"projectcalico.org", "crd.projectcalico.org"},
				Resources: []string{
					"bgpconfigurations",
					"bgpfilters",
					"bgpfilters",
					"bgppeers",
					"blockaffinities",
					"clusterinformations",
					"felixconfigurations",
					"globalnetworkpolicies",
					"globalnetworksets",
					"hostendpoints",
					"hostqospolicies",
					"ipamblocks",
					"ippools",
					"ipreservations",
					"networkpolicies",
					"networksets",
					"stagedglobalnetworkpolicies",
					"stagedkubernetesnetworkpolicies",
					"stagednetworkpolicies",
					"tiers",
				},
				Verbs: []string{"get", "list", "watch"},
			},
			{
				// calico/node monitors for caliconodestatus objects and writes its status back into the object.
				APIGroups: []string{"projectcalico.org", "crd.projectcalico.org"},
				Resources: []string{
					"caliconodestatuses",
				},
				Verbs: []string{"get", "list", "watch", "update"},
			},
			{
				// calico/node updates the status subresource of caliconodestatus objects.
				APIGroups: []string{"projectcalico.org", "crd.projectcalico.org"},
				Resources: []string{
					"caliconodestatuses/status",
				},
				Verbs: []string{"update"},
			},
			{
				// For migration code in calico/node startup only. Remove when the migration
				// code is removed from node.
				APIGroups: []string{"projectcalico.org", "crd.projectcalico.org"},
				Resources: []string{
					"globalbgpconfigs",
					"globalfelixconfigs",
				},
				Verbs: []string{"get", "list", "watch"},
			},
			{
				// Calico creates some configuration on startup.
				APIGroups: []string{"projectcalico.org", "crd.projectcalico.org"},
				Resources: []string{
					"clusterinformations",
					"felixconfigurations",
					"bgpconfigurations",
					"ippools",
				},
				Verbs: []string{"create", "update"},
			},
			{
				// Calico creates some tiers on startup.
				APIGroups: []string{"projectcalico.org", "crd.projectcalico.org"},
				Resources: []string{
					"tiers",
				},
				Verbs: []string{"create"},
			},
			{
				// Calico monitors nodes for some networking configuration.
				APIGroups: []string{""},
				Resources: []string{"nodes"},
				Verbs:     []string{"get", "list", "watch"},
			},
			{
				// Most IPAM resources need full CRUD permissions so we can allocate and
				// release IP addresses for pods.
				APIGroups: []string{"projectcalico.org", "crd.projectcalico.org"},
				Resources: []string{
					"blockaffinities",
					"ipamblocks",
					"ipamhandles",
					"ipamconfigurations",
					"ipamconfigs",
				},
				Verbs: []string{"get", "list", "create", "update", "delete"},
			},
			{
				// confd (and in some cases, felix) watches block affinities for route aggregation.
				APIGroups: []string{"projectcalico.org", "crd.projectcalico.org"},
				Resources: []string{"blockaffinities"},
				Verbs:     []string{"watch"},
			},
			{
				// For monitoring KubeVirt live migration.
				APIGroups: []string{"kubevirt.io"},
				Resources: []string{"virtualmachineinstancemigrations"},
				Verbs:     []string{"get", "list", "watch"},
			},
		},
	}
	if c.cfg.Installation.Variant.IsEnterprise() {
		extraRules := []rbacv1.PolicyRule{
			{
				// Calico Enterprise needs to be able to read additional resources.
				APIGroups: []string{"projectcalico.org", "crd.projectcalico.org"},
				Resources: []string{
					"bfdconfigurations",
					"egressgatewaypolicies",
					"externalnetworks",
					"licensekeys",
					"networks",
					"packetcaptures",
					"remoteclusterconfigurations",
				},
				Verbs: []string{"get", "list", "watch"},
			},
			{
				// Tigera Secure updates status for packet captures.
				APIGroups: []string{"projectcalico.org", "crd.projectcalico.org"},
				Resources: []string{
					"packetcaptures",
					"packetcaptures/status",
				},
				Verbs: []string{"update"},
			},
		}
		role.Rules = append(role.Rules, extraRules...)
	}
	if c.cfg.Installation.KubernetesProvider.IsOpenShift() {
		role.Rules = append(role.Rules, rbacv1.PolicyRule{
			APIGroups:     []string{"security.openshift.io"},
			Resources:     []string{"securitycontextconstraints"},
			Verbs:         []string{"use"},
			ResourceNames: []string{securitycontextconstraints.Privileged},
		})
	}
	return role
}

// cniPluginRole creates the role containing policy rules that allow the Calico CNI plugin to operate normally.
func (c *nodeComponent) cniPluginRole() *rbacv1.ClusterRole {
	finalizer := []string{}
	if !c.cfg.CanRemoveCNIFinalizer {
		finalizer = []string{CNIFinalizer}
	}
	role := &rbacv1.ClusterRole{
		TypeMeta: metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:       CalicoCNIPluginObjectName,
			Finalizers: finalizer,
		},

		Rules: []rbacv1.PolicyRule{
			{
				// The CNI plugin needs to get pods, nodes, namespaces.
				APIGroups: []string{""},
				Resources: []string{"pods", "nodes", "namespaces"},
				Verbs:     []string{"get"},
			},
			{
				// Calico patches the allocated IP onto the pod.
				APIGroups: []string{""},
				Resources: []string{"pods/status"},
				Verbs:     []string{"patch"},
			},
			{
				// Most IPAM resources need full CRUD permissions so we can allocate and
				// release IP addresses for pods.
				APIGroups: []string{"projectcalico.org", "crd.projectcalico.org"},
				Resources: []string{
					"blockaffinities",
					"ipamblocks",
					"ipamhandles",
					"ipamconfigurations",
					"ipamconfigs",
					"clusterinformations",
					"ippools",
					"ipreservations",
				},
				Verbs: []string{"get", "list", "create", "update", "delete"},
			},
			{
				// The CNI plugin reads KubeVirt resources for IPAM of KubeVirt workloads.
				APIGroups: []string{"kubevirt.io"},
				Resources: []string{"virtualmachineinstances", "virtualmachines"},
				Verbs:     []string{"get"},
			},
		},
	}
	if c.cfg.Installation.Variant.IsEnterprise() {
		// The Network resource is only available in Enterprise / Cloud at this time.
		role.Rules = append(role.Rules, rbacv1.PolicyRule{
			APIGroups: []string{"projectcalico.org", "crd.projectcalico.org"},
			Resources: []string{"networks"},
			Verbs:     []string{"get"},
		})
	}
	return role
}

func (c *nodeComponent) createCalicoPluginConfig() map[string]any {
	// Determine MTU to use for veth interfaces.
	// Zero means to use auto-detection.
	var mtu int32 = 0
	if m := getMTU(c.cfg.Installation); m != nil {
		mtu = *m
	}

	// Determine per-provider settings.
	nodenameFileOptional := false
	switch c.cfg.Installation.KubernetesProvider {
	case operatorv1.ProviderDockerEE:
		nodenameFileOptional = true
	}

	// Pull out other settings.
	ipForward := false
	if c.cfg.Installation.CalicoNetwork.ContainerIPForwarding != nil {
		ipForward = (*c.cfg.Installation.CalicoNetwork.ContainerIPForwarding == operatorv1.ContainerIPForwardingEnabled)
	}

	ipam := c.getCalicoIPAM()
	if c.cfg.Installation.CNI.IPAM.Type == operatorv1.IPAMPluginHostLocal {
		ipam = buildHostLocalIPAM(c.cfg.IPPools)
	}

	apiRoot := c.cfg.K8sServiceEp.CNIAPIRoot()

	linuxPolicySetupTimeoutSeconds := int32(0)
	if c.cfg.Installation.CalicoNetwork.LinuxPolicySetupTimeoutSeconds != nil {
		linuxPolicySetupTimeoutSeconds = *c.cfg.Installation.CalicoNetwork.LinuxPolicySetupTimeoutSeconds
	}
	apiGroup := ""
	if c.cfg.V3CRDs {
		apiGroup = "projectcalico.org/v3"
	}

	// calico plugin
	calicoPluginConfig := map[string]any{
		"type":                   "calico",
		"datastore_type":         "kubernetes",
		"mtu":                    mtu,
		"nodename_file_optional": nodenameFileOptional,
		"log_file_path":          "/var/log/calico/cni/cni.log",
		"ipam":                   ipam,
		"container_settings": map[string]any{
			"allow_ip_forwarding": ipForward,
		},
		"policy": map[string]any{
			"type": "k8s",
		},
		"policy_setup_timeout_seconds": linuxPolicySetupTimeoutSeconds,
		"endpoint_status_dir":          filepath.Join(c.varRunCalicoVolume().HostPath.Path, "endpoint-status"),
		"calico_api_group":             apiGroup,
	}

	// Determine logging configuration
	if c.cfg.Installation.Logging != nil && c.cfg.Installation.Logging.CNI != nil {

		if c.cfg.Installation.Logging.CNI.LogSeverity != nil {
			logSeverity := string(*c.cfg.Installation.Logging.CNI.LogSeverity)
			calicoPluginConfig["log_level"] = logSeverity
		}

		if c.cfg.Installation.Logging.CNI.LogFileMaxSize != nil {
			logFileMaxSize := c.cfg.Installation.Logging.CNI.LogFileMaxSize.Value() / (1024 * 1024)
			calicoPluginConfig["log_file_max_size"] = logFileMaxSize
		}

		if c.cfg.Installation.Logging.CNI.LogFileMaxCount != nil {
			logFileMaxCount := *c.cfg.Installation.Logging.CNI.LogFileMaxCount
			calicoPluginConfig["log_file_max_count"] = logFileMaxCount
		}

		if c.cfg.Installation.Logging.CNI.LogFileMaxAgeDays != nil {
			logFileMaxAgeDays := *c.cfg.Installation.Logging.CNI.LogFileMaxAgeDays
			calicoPluginConfig["log_file_max_age"] = logFileMaxAgeDays
		}
	}

	// optional properties
	kubernetes := map[string]any{
		"kubeconfig": "__KUBECONFIG_FILEPATH__",
	}
	if apiRoot != "" {
		kubernetes["k8s_api_root"] = apiRoot
	}
	calicoPluginConfig["kubernetes"] = kubernetes

	if c.vppDataplaneEnabled() {
		calicoPluginConfig["dataplane_options"] = map[string]any{
			"type":   "grpc",
			"socket": "unix:///var/run/calico/cni-server.sock",
		}
	}

	// device_type tells the Calico CNI plugin which virtual device to create for
	// the pod interface. Only emit when explicitly set to Netkit: leaving it out
	// keeps the default (veth) behavior and avoids churning existing CNI configs.
	if c.cfg.Installation.CalicoNetwork.LinuxPodInterfaceType != nil &&
		*c.cfg.Installation.CalicoNetwork.LinuxPodInterfaceType == operatorv1.LinuxPodInterfaceNetkit {
		calicoPluginConfig["device_type"] = "netkit"
	}

	return calicoPluginConfig
}

func (c *nodeComponent) createPortmapPlugin() map[string]any {
	// Determine portmap configuration to use.
	portmapPlugin := map[string]any{
		"type": "portmap",
		"snat": true,
		"capabilities": map[string]bool{
			"portMappings": true,
		},
	}

	return portmapPlugin
}

func (c *nodeComponent) createTuningPlugin() map[string]any {
	// tuning plugin (sysctl)
	sysctl := map[string]string{}
	tuningPlugin := map[string]any{
		"type":   "tuning",
		"sysctl": sysctl,
	}

	// convert []operatorv1.Sysctl{} to map[string]string for CNI definition
	// details: https://www.cni.dev/plugins/current/meta/tuning/#system-controls-operation
	for _, v := range c.cfg.Installation.CalicoNetwork.Sysctl {
		sysctl[v.Key] = v.Value
	}
	tuningPlugin["sysctl"] = sysctl
	return tuningPlugin
}

// nodeCNIConfigMap returns a config map containing the CNI network config to be installed on each node.
// Returns nil if no configmap is needed.
func (c *nodeComponent) nodeCNIConfigMap() *corev1.ConfigMap {
	if c.cfg.Installation.CNI.Type != operatorv1.PluginCalico {
		// If calico cni is not being used, then no cni configmap is needed.
		return nil
	}

	plugins := make([]any, 0)
	plugins = append(plugins, c.createCalicoPluginConfig())

	// optional portmap plugin
	if c.cfg.Installation.CalicoNetwork.HostPorts != nil &&
		*c.cfg.Installation.CalicoNetwork.HostPorts == operatorv1.HostPortsEnabled {
		plugins = append(plugins, c.createPortmapPlugin())
	}

	// optional tuning plugin
	if c.cfg.Installation.CalicoNetwork.Sysctl != nil {
		plugins = append(plugins, c.createTuningPlugin())
	}

	pluginsArray, _ := json.Marshal(plugins)

	config := fmt.Sprintf(`{
			  "name": "k8s-pod-network",
			  "cniVersion": "%s",
			  "plugins": %s
			}`, c.cfg.Installation.CNI.ResolvedSpecVersion(), string(pluginsArray))

	return &corev1.ConfigMap{
		TypeMeta: metav1.TypeMeta{Kind: "ConfigMap", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "cni-config",
			Namespace: common.CalicoNamespace,
			Labels:    map[string]string{},
		},
		Data: map[string]string{
			"config": config,
		},
	}
}

func (c *nodeComponent) getCalicoIPAM() map[string]any {
	// Determine what address families to enable.
	var assign_ipv4 string
	var assign_ipv6 string
	if v4pool := GetIPv4Pool(c.cfg.IPPools); v4pool != nil {
		assign_ipv4 = "true"
	} else {
		assign_ipv4 = "false"
	}
	if v6pool := GetIPv6Pool(c.cfg.IPPools); v6pool != nil {
		assign_ipv6 = "true"
	} else {
		assign_ipv6 = "false"
	}
	return map[string]any{
		"type":        "calico-ipam",
		"assign_ipv4": assign_ipv4,
		"assign_ipv6": assign_ipv6,
	}
}

func buildHostLocalIPAM(pools []operatorv1.IPPool) map[string]any {
	v6 := GetIPv6Pool(pools) != nil
	v4 := GetIPv4Pool(pools) != nil

	if v4 && v6 {
		// Dual-stack
		return map[string]any{
			"type":   "host-local",
			"ranges": [][]map[string]string{{{"subnet": "usePodCidr"}}, {{"subnet": "usePodCidrIPv6"}}},
		}
	} else if v6 {
		// Single-stack v6
		return map[string]any{
			"type":   "host-local",
			"subnet": "usePodCidrIPv6",
		}
	} else {
		// Single-stack v4
		return map[string]any{
			"type":   "host-local",
			"subnet": "usePodCidr",
		}
	}
}

func (c *nodeComponent) birdTemplateConfigMap() *corev1.ConfigMap {
	if len(c.cfg.BirdTemplates) == 0 {
		return nil
	}
	cm := corev1.ConfigMap{
		TypeMeta: metav1.TypeMeta{Kind: "ConfigMap", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      BirdTemplatesConfigMapName,
			Namespace: common.CalicoNamespace,
		},
		Data: map[string]string{},
	}
	for k, v := range c.cfg.BirdTemplates {
		cm.Data[k] = v
	}
	return &cm
}

// clusterAdminClusterRoleBinding returns a ClusterRoleBinding for DockerEE to give
// the cluster-admin role to calico-node and calico-cni-plugin, this is needed for calico-node/calico-cni-plugin to be
// able to use hostNetwork in Docker Enterprise.
func (c *nodeComponent) clusterAdminClusterRoleBinding() *rbacv1.ClusterRoleBinding {
	crb := &rbacv1.ClusterRoleBinding{
		TypeMeta: metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:   "calico-cluster-admin",
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
				Name:      CalicoNodeObjectName,
				Namespace: common.CalicoNamespace,
			},
			{
				Kind:      "ServiceAccount",
				Name:      CalicoCNIPluginObjectName,
				Namespace: common.CalicoNamespace,
			},
		},
	}
	return crb
}

// nodeDaemonset creates the node daemonset.
func (c *nodeComponent) nodeDaemonset(cniCfgMap *corev1.ConfigMap) *appsv1.DaemonSet {
	var terminationGracePeriod int64 = nodeTerminationGracePeriodSeconds
	var initContainers []corev1.Container
	nodeContainer := c.nodeContainer()
	annotations := c.cfg.TLS.TrustedBundle.HashAnnotations()
	if len(c.cfg.BirdTemplates) != 0 {
		annotations[birdTemplateHashAnnotation] = rmeta.AnnotationHash(c.cfg.BirdTemplates)
	}
	if c.cfg.PrometheusServerTLS != nil {
		annotations[c.cfg.PrometheusServerTLS.HashAnnotationKey()] = c.cfg.PrometheusServerTLS.HashAnnotationValue()
	}

	if c.cfg.TLS.NodeSecret.UseCertificateManagement() {
		initContainers = append(initContainers, c.cfg.TLS.NodeSecret.InitContainer(common.CalicoNamespace, nodeContainer.SecurityContext))
	}

	if c.cfg.PrometheusServerTLS != nil && c.cfg.PrometheusServerTLS.UseCertificateManagement() {
		initContainers = append(initContainers, c.cfg.PrometheusServerTLS.InitContainer(common.CalicoNamespace, nodeContainer.SecurityContext))
	}

	if cniCfgMap != nil {
		annotations[nodeCniConfigAnnotation] = rmeta.AnnotationHash(cniCfgMap.Data)
	}

	// Include annotation for prometheus scraping configuration.
	if c.cfg.Installation.NodeMetricsPort != nil {
		annotations["prometheus.io/scrape"] = "true"
		annotations["prometheus.io/port"] = fmt.Sprintf("%d", *c.cfg.Installation.NodeMetricsPort)
	}

	// check tech preview annotation for calico-node apparmor profile
	if c.cfg.NodeAppArmorProfile != "" {
		annotations["container.apparmor.security.beta.kubernetes.io/calico-node"] = c.cfg.NodeAppArmorProfile
	}

	if c.cfg.BGPLayouts != nil {
		annotations[bgpLayoutHashAnnotation] = rmeta.AnnotationHash(c.cfg.BGPLayouts.Data)
	}

	if c.cfg.Installation.FlexVolumePath != "None" {
		initContainers = append(initContainers, c.flexVolumeContainer())
	}

	// Mount the bpf fs for the node container.
	// This is required for the BPF dataplane, but also for the other dataplanes
	// as we need to cleanup the BPF state when switching dataplanes.
	initContainers = append(initContainers, c.bpfBootstrapInitContainer())

	var affinity *corev1.Affinity
	if c.cfg.Installation.KubernetesProvider.IsAKS() {
		affinity = &corev1.Affinity{
			NodeAffinity: &corev1.NodeAffinity{
				RequiredDuringSchedulingIgnoredDuringExecution: &corev1.NodeSelector{
					NodeSelectorTerms: []corev1.NodeSelectorTerm{{
						MatchExpressions: []corev1.NodeSelectorRequirement{{
							Key:      "type",
							Operator: corev1.NodeSelectorOpNotIn,
							Values:   []string{"virtual-kubelet"},
						}},
					}},
				},
			},
		}
	} else if c.cfg.Installation.KubernetesProvider.IsEKS() {
		affinity = &corev1.Affinity{
			NodeAffinity: &corev1.NodeAffinity{
				RequiredDuringSchedulingIgnoredDuringExecution: &corev1.NodeSelector{
					NodeSelectorTerms: []corev1.NodeSelectorTerm{{
						MatchExpressions: []corev1.NodeSelectorRequirement{{
							Key:      "eks.amazonaws.com/compute-type",
							Operator: corev1.NodeSelectorOpNotIn,
							Values:   []string{"fargate"},
						}},
					}},
				},
			},
		}
	}

	// Include the annotation of BindMode
	if c.cfg.BindMode != "" {
		annotations[bgpBindModeHashAnnotation] = rmeta.AnnotationHash(c.cfg.BindMode)
	}

	var hostAliases []corev1.HostAlias
	if c.cfg.GoldmaneIP != "" {
		hostAliases = []corev1.HostAlias{
			{
				Hostnames: []string{goldmaneDomainName},
				IP:        c.cfg.GoldmaneIP,
			},
		}
	}

	// Determine the name to use for the calico/node daemonset. For mixed-mode, we run the enterprise DaemonSet
	// with its own name so as to not conflict.
	ds := appsv1.DaemonSet{
		TypeMeta: metav1.TypeMeta{Kind: "DaemonSet", APIVersion: "apps/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      common.NodeDaemonSetName,
			Namespace: common.CalicoNamespace,
		},
		Spec: appsv1.DaemonSetSpec{
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Annotations: annotations,
				},
				Spec: corev1.PodSpec{
					Tolerations:                   rmeta.TolerateAll,
					Affinity:                      affinity,
					ImagePullSecrets:              c.cfg.Installation.ImagePullSecrets,
					HostAliases:                   hostAliases,
					ServiceAccountName:            CalicoNodeObjectName,
					TerminationGracePeriodSeconds: &terminationGracePeriod,
					HostNetwork:                   true,
					InitContainers:                initContainers,
					Containers:                    []corev1.Container{nodeContainer},
					Volumes:                       c.nodeVolumes(),
					DNSPolicy:                     c.cfg.DefaultDNSPolicy,
					DNSConfig:                     c.cfg.DefaultDNSConfig,
				},
			},
			UpdateStrategy: c.cfg.Installation.NodeUpdateStrategy,
		},
	}

	if c.cfg.Installation.CNI.Type == operatorv1.PluginCalico {
		if c.installUpstreamPlugins() {
			// cniPluginsContainer must run before cniContainer: it populates the
			// staging volume that install-cni reads from at /opt/cni/bin.
			ds.Spec.Template.Spec.InitContainers = append(ds.Spec.Template.Spec.InitContainers, c.cniPluginsContainer())
		}
		ds.Spec.Template.Spec.InitContainers = append(ds.Spec.Template.Spec.InitContainers, c.cniContainer())
	}

	if c.collectProcessPathEnabled() {
		ds.Spec.Template.Spec.HostPID = true
	}

	SetNodeCriticalPod(&(ds.Spec.Template))
	if c.cfg.MigrateNamespaces {
		migration.LimitDaemonSetToMigratedNodes(&ds)
	}

	if overrides := c.cfg.Installation.CalicoNodeDaemonSet; overrides != nil {
		// If the overrides specify the legacy mount-bpffs init container, then we rename it to the new value: ebpf-bootstrap.
		for index := range rcomp.GetInitContainers(overrides) {
			if overrides.Spec.Template.Spec.InitContainers[index].Name == "mount-bpffs" {
				overrides.Spec.Template.Spec.InitContainers[index].Name = "ebpf-bootstrap"
			}
		}
		rcomp.ApplyDaemonSetOverrides(&ds, overrides)
	}
	return &ds
}

// nodeVolumes creates the node's volumes.
func (c *nodeComponent) nodeVolumes() []corev1.Volume {
	fileOrCreate := corev1.HostPathFileOrCreate
	dirOrCreate := corev1.HostPathDirectoryOrCreate
	dirMustExist := corev1.HostPathDirectory

	volumes := []corev1.Volume{
		{Name: "lib-modules", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/lib/modules"}}},
		{Name: "xtables-lock", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/run/xtables.lock", Type: &fileOrCreate}}},
		{Name: "policysync", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/var/run/nodeagent", Type: &dirOrCreate}}},
		c.cfg.TLS.TrustedBundle.Volume(),
		c.cfg.TLS.NodeSecret.Volume(),
		c.varRunCalicoVolume(),
		corev1.Volume{Name: "var-lib-calico", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/var/lib/calico", Type: &dirOrCreate}}},
		// Volume for the containing directory so that the init container can mount the child bpf directory if needed.
		corev1.Volume{Name: "sys-fs", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/sys/fs", Type: &dirOrCreate}}},
		// Volume for the bpffs itself, used by the main node container.
		corev1.Volume{Name: "bpffs", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/sys/fs/bpf", Type: &dirMustExist}}},
		// securityfs, read by Felix to detect kernel lockdown=confidentiality. No
		// Type set (like nodeproc) so nodes without securityfs still start; Felix
		// treats an unreadable lockdown file as "not locked down".
		corev1.Volume{Name: "sys-kernel-security", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/sys/kernel/security"}}},
		// Volume used by mount-cgroupv2 init container to access root cgroup name space of node.
		corev1.Volume{Name: "nodeproc", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/proc"}}},
	}

	if c.vppDataplaneEnabled() {
		volumes = append(volumes,
			// Volume that contains the felix dataplane binary
			corev1.Volume{Name: "felix-plugins", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/var/lib/calico/felix-plugins"}}},
		)
	}

	// If needed for this configuration, then include the CNI volumes.
	if c.cfg.Installation.CNI.Type == operatorv1.PluginCalico {
		volumes = append(volumes, corev1.Volume{Name: "cni-bin-dir", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: *c.cfg.Installation.CNI.BinDir, Type: &dirOrCreate}}})
		volumes = append(volumes, corev1.Volume{Name: "cni-net-dir", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: *c.cfg.Installation.CNI.ConfDir}}})
		volumes = append(volumes, corev1.Volume{Name: "cni-log-dir", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/var/log/calico/cni"}}})
	}
	if c.installUpstreamPlugins() {
		// Staging volume populated by the cni-plugins init container and read
		// by install-cni when copying upstream plugins onto the host.
		volumes = append(volumes, corev1.Volume{Name: "cni-plugins-stage", VolumeSource: corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{}}})
	}

	// Override with Tigera-specific config.
	if c.cfg.Installation.Variant.IsEnterprise() {
		// Add volume for calico logs.
		calicoLogVol := corev1.Volume{
			Name:         "var-log-calico",
			VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/var/log/calico", Type: &dirOrCreate}},
		}
		volumes = append(volumes, calicoLogVol)
	}

	// Create and append flexvolume
	if c.cfg.Installation.FlexVolumePath != "None" {
		volumes = append(volumes, corev1.Volume{
			Name: "flexvol-driver-host",
			VolumeSource: corev1.VolumeSource{
				HostPath: &corev1.HostPathVolumeSource{Path: c.cfg.Installation.FlexVolumePath + "nodeagent~uds", Type: &dirOrCreate},
			},
		})
	}
	if c.cfg.BirdTemplates != nil {
		volumes = append(volumes,
			corev1.Volume{
				Name: "bird-templates",
				VolumeSource: corev1.VolumeSource{
					ConfigMap: &corev1.ConfigMapVolumeSource{
						LocalObjectReference: corev1.LocalObjectReference{
							Name: BirdTemplatesConfigMapName,
						},
					},
				},
			})
	}

	if c.cfg.BGPLayouts != nil {
		volumes = append(volumes,
			corev1.Volume{
				Name: BGPLayoutVolumeName,
				VolumeSource: corev1.VolumeSource{
					ConfigMap: &corev1.ConfigMapVolumeSource{
						LocalObjectReference: corev1.LocalObjectReference{
							Name: BGPLayoutConfigMapName,
						},
					},
				},
			})
	}
	if c.cfg.PrometheusServerTLS != nil {
		volumes = append(volumes, c.cfg.PrometheusServerTLS.Volume())
	}

	return volumes
}

func (c *nodeComponent) varRunCalicoVolume() corev1.Volume {
	dirOrCreate := corev1.HostPathDirectoryOrCreate
	return corev1.Volume{
		Name: "var-run-calico",
		VolumeSource: corev1.VolumeSource{
			HostPath: &corev1.HostPathVolumeSource{Path: "/var/run/calico", Type: &dirOrCreate},
		},
	}
}

func (c *nodeComponent) vppDataplaneEnabled() bool {
	return c.cfg.Installation.CalicoNetwork != nil &&
		c.cfg.Installation.CalicoNetwork.LinuxDataplane != nil &&
		*c.cfg.Installation.CalicoNetwork.LinuxDataplane == operatorv1.LinuxDataplaneVPP
}

func (c *nodeComponent) collectProcessPathEnabled() bool {
	return c.cfg.LogCollector != nil &&
		c.cfg.LogCollector.Spec.CollectProcessPath != nil &&
		*c.cfg.LogCollector.Spec.CollectProcessPath == operatorv1.CollectProcessPathEnable
}

// cniContainer creates the node's init container that installs CNI.
func (c *nodeComponent) cniContainer() corev1.Container {
	// Determine environment to pass to the CNI init container.
	cniEnv := c.cniEnvvars()
	cniVolumeMounts := []corev1.VolumeMount{
		{MountPath: "/host/opt/cni/bin", Name: "cni-bin-dir"},
		{MountPath: "/host/etc/cni/net.d", Name: "cni-net-dir"},
	}
	if c.installUpstreamPlugins() {
		// Upstream plugin binaries staged by the cni-plugins init container.
		// install.go walks /opt/cni/bin to copy them onto the host.
		cniVolumeMounts = append(cniVolumeMounts, corev1.VolumeMount{MountPath: "/opt/cni/bin", Name: "cni-plugins-stage"})
	}

	return corev1.Container{
		Name:            "install-cni",
		Image:           c.calicoImage,
		Command:         []string{components.CalicoBinaryPath, "component", "cni", "install"},
		Env:             cniEnv,
		SecurityContext: securitycontext.NewRootContext(true),
		VolumeMounts:    cniVolumeMounts,
	}
}

// installUpstreamPlugins reports whether the operator should stage the upstream
// CNI plugin binaries onto the host. Gated on CNI.Type == Calico and the
// CNI.InstallMode override (defaults to All).
func (c *nodeComponent) installUpstreamPlugins() bool {
	if c.cfg.Installation.CNI == nil || c.cfg.Installation.CNI.Type != operatorv1.PluginCalico {
		return false
	}
	if c.cfg.Installation.CNI.InstallMode != nil && *c.cfg.Installation.CNI.InstallMode == operatorv1.CNIInstallModeCalicoOnly {
		return false
	}
	return true
}

// cniPluginsContainer creates the init container that stages upstream CNI
// plugin binaries (host-local, portmap, loopback, tuning, flannel) into a
// shared volume read by the install-cni init container. The plugins ship as
// a separate image rather than baked into the combined calico image so the
// main image stays small.
func (c *nodeComponent) cniPluginsContainer() corev1.Container {
	return corev1.Container{
		Name:            "cni-plugins",
		Image:           c.cniPluginsImage,
		SecurityContext: securitycontext.NewRootContext(true),
		VolumeMounts: []corev1.VolumeMount{
			{MountPath: "/stage", Name: "cni-plugins-stage"},
		},
	}
}

// flexVolumeContainer creates the node's init container that installs the Unix Domain Socket to allow Dikastes
// to communicate with Felix over the Policy Sync API.
func (c *nodeComponent) flexVolumeContainer() corev1.Container {
	flexVolumeMounts := []corev1.VolumeMount{
		{MountPath: "/host/driver", Name: "flexvol-driver-host"},
	}

	return corev1.Container{
		Name:            "flexvol-driver",
		Image:           c.calicoImage,
		Command:         []string{components.CalicoBinaryPath, "component", "flexvol", "install", "--target", "/host/driver/uds"},
		SecurityContext: securitycontext.NewRootContext(true),
		VolumeMounts:    flexVolumeMounts,
	}
}

// bpfBootstrapInitContainer creates an init container that attempts to mount the BPF filesystem.  doing this from an
// init container reduces the privileges needed by the main container.  It's important that the BPF filesystem is
// mounted on the host itself, otherwise, a restart of the node container would tear down the mount and destroy
// the BPF dataplane's BPF maps.
func (c *nodeComponent) bpfBootstrapInitContainer() corev1.Container {
	bidirectional := corev1.MountPropagationBidirectional
	mounts := []corev1.VolumeMount{
		{
			MountPath: "/sys/fs",
			Name:      "sys-fs",
			// Bidirectional is required to ensure that the new mount we make at /sys/fs/bpf propagates to the host
			// so that it outlives the init container.
			MountPropagation: &bidirectional,
		},
		{
			MountPath: "/var/run/calico",
			Name:      "var-run-calico",
			// Bidirectional is required to ensure that the new mount we make at /var/run/calico/cgroup propagates to the host
			// so that it outlives the init container.
			MountPropagation: &bidirectional,
		},
		{
			MountPath: "/nodeproc",
			Name:      "nodeproc",
			ReadOnly:  true,
		},
	}

	command := []string{components.CalicoBinaryPath, "component", "node", "init"}
	if !c.cfg.Installation.BPFEnabled() {
		command = append(command, "--best-effort")
	}
	return corev1.Container{
		Name:            "ebpf-bootstrap",
		Image:           c.nodeImage,
		Env:             c.bpffsEnvvars(),
		Command:         command,
		SecurityContext: securitycontext.NewRootContext(true),
		VolumeMounts:    mounts,
	}
}

// bpffsEnvvars creates the environment variables for the BPF filesystem init container.
func (c *nodeComponent) bpffsEnvvars() []corev1.EnvVar {
	envVars := []corev1.EnvVar{}
	env := JoinServiceEndpoints(c.cfg.K8sServiceAddrs)
	if env != "" {
		envVars = append(envVars, corev1.EnvVar{Name: "KUBERNETES_SERVICE_IPS_PORTS", Value: env})
	}
	env = JoinServiceEndpoints(c.cfg.K8sEndpointSlice)
	if env != "" {
		envVars = append(envVars, corev1.EnvVar{Name: "KUBERNETES_APISERVER_ENDPOINTS", Value: env})
	}

	if c.cfg.NodeCgroupV2Path != "" {
		envVars = append(envVars, corev1.EnvVar{Name: "CALICO_CGROUP_PATH", Value: c.cfg.NodeCgroupV2Path})
	}

	return envVars
}

// JoinServiceEndpoints joins a list of ServiceEndpoint into a comma-separated string of ip:port.
func JoinServiceEndpoints(endpoints []k8sapi.ServiceEndpoint) string {
	var parts []string
	for _, ep := range endpoints {

		if ep.Host == "" || ep.Port == "" {
			continue
		}
		parts = append(parts, net.JoinHostPort(ep.Host, ep.Port))
	}
	return strings.Join(parts, ",")
}

// cniEnvvars creates the CNI container's envvars.
func (c *nodeComponent) cniEnvvars() []corev1.EnvVar {
	if c.cfg.Installation.CNI.Type != operatorv1.PluginCalico {
		return []corev1.EnvVar{}
	}

	envVars := []corev1.EnvVar{
		{Name: "CNI_CONF_NAME", Value: "10-calico.conflist"},
		{Name: "SLEEP", Value: "false"},
		{Name: "CNI_NET_DIR", Value: *c.cfg.Installation.CNI.ConfDir},
		{
			Name: "CNI_NETWORK_CONFIG",
			ValueFrom: &corev1.EnvVarSource{
				ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
					Key: "config",
					LocalObjectReference: corev1.LocalObjectReference{
						Name: "cni-config",
					},
				},
			},
		},
	}

	envVars = append(envVars, c.cfg.K8sServiceEp.EnvVars()...)

	if c.cfg.Installation.Variant.IsEnterprise() {
		if c.cfg.Installation.CalicoNetwork != nil && c.cfg.Installation.CalicoNetwork.MultiInterfaceMode != nil {
			envVars = append(envVars, corev1.EnvVar{Name: "MULTI_INTERFACE_MODE", Value: c.cfg.Installation.CalicoNetwork.MultiInterfaceMode.Value()})
		}
	}

	return envVars
}

// nodeContainer creates the main node container.
func (c *nodeComponent) nodeContainer() corev1.Container {
	sc := securitycontext.NewRootContext(true)

	lp, rp := c.nodeLivenessReadinessProbes()

	return corev1.Container{
		Name:            CalicoNodeObjectName,
		Image:           c.nodeImage,
		Resources:       c.nodeResources(),
		SecurityContext: sc,
		Env:             c.nodeEnvVars(),
		VolumeMounts:    c.nodeVolumeMounts(),
		LivenessProbe:   lp,
		ReadinessProbe:  rp,
		Lifecycle:       c.nodeLifecycle(),
	}
}

// nodeResources creates the node's resource requirements.
func (c *nodeComponent) nodeResources() corev1.ResourceRequirements {
	return rmeta.GetResourceRequirements(c.cfg.Installation, operatorv1.ComponentNameNode)
}

// nodeVolumeMounts creates the node's volume mounts.
func (c *nodeComponent) nodeVolumeMounts() []corev1.VolumeMount {
	nodeVolumeMounts := c.cfg.TLS.TrustedBundle.VolumeMounts(c.SupportedOSType())
	nodeVolumeMounts = append(nodeVolumeMounts,
		corev1.VolumeMount{MountPath: "/lib/modules", Name: "lib-modules", ReadOnly: true},
		corev1.VolumeMount{MountPath: "/run/xtables.lock", Name: "xtables-lock"},
		corev1.VolumeMount{MountPath: "/var/run/nodeagent", Name: "policysync"},
		corev1.VolumeMount{MountPath: "/var/run/calico", Name: "var-run-calico"},
		corev1.VolumeMount{MountPath: "/var/lib/calico", Name: "var-lib-calico"},
		corev1.VolumeMount{MountPath: "/sys/fs/bpf", Name: BPFVolumeName},
		// Read-only so Felix can detect kernel lockdown=confidentiality via
		// /sys/kernel/security/lockdown (securityfs is separate from /sys/fs).
		corev1.VolumeMount{MountPath: "/sys/kernel/security", Name: "sys-kernel-security", ReadOnly: true},
		c.cfg.TLS.NodeSecret.VolumeMount(c.SupportedOSType()),
	)

	if c.vppDataplaneEnabled() {
		nodeVolumeMounts = append(nodeVolumeMounts, corev1.VolumeMount{MountPath: "/usr/local/bin/felix-plugins", Name: "felix-plugins", ReadOnly: true})
	}
	if c.cfg.Installation.Variant.IsEnterprise() {
		extraNodeMounts := []corev1.VolumeMount{
			{MountPath: "/var/log/calico", Name: "var-log-calico"},
		}
		nodeVolumeMounts = append(nodeVolumeMounts, extraNodeMounts...)
	} else if c.cfg.Installation.CNI.Type == operatorv1.PluginCalico {
		cniLogMount := corev1.VolumeMount{MountPath: "/var/log/calico/cni", Name: "cni-log-dir", ReadOnly: false}
		nodeVolumeMounts = append(nodeVolumeMounts, cniLogMount)
	}

	if c.cfg.Installation.CNI.Type == operatorv1.PluginCalico {
		nodeVolumeMounts = append(nodeVolumeMounts, corev1.VolumeMount{MountPath: "/host/etc/cni/net.d", Name: "cni-net-dir"})
	}

	if c.cfg.BirdTemplates != nil {
		// create a volume mount for each bird template, but sort them alphabetically first,
		// otherwise, since map iteration is random, they'll be added to the list of volumes in a random order,
		// which will cause another reconciliation event when calico-node is updated.
		sortedKeys := []string{}
		for k := range c.cfg.BirdTemplates {
			sortedKeys = append(sortedKeys, k)
		}
		sort.Strings(sortedKeys)

		for _, k := range sortedKeys {
			nodeVolumeMounts = append(nodeVolumeMounts,
				corev1.VolumeMount{
					Name:      "bird-templates",
					ReadOnly:  true,
					MountPath: fmt.Sprintf("/etc/calico/confd/templates/%s", k),
					SubPath:   k,
				})
		}
	}

	if c.cfg.BGPLayouts != nil {
		nodeVolumeMounts = append(nodeVolumeMounts,
			corev1.VolumeMount{
				Name:      BGPLayoutVolumeName,
				ReadOnly:  true,
				MountPath: BGPLayoutPath,
				SubPath:   BGPLayoutConfigMapKey,
			})
	}
	if c.cfg.PrometheusServerTLS != nil {
		nodeVolumeMounts = append(nodeVolumeMounts, c.cfg.PrometheusServerTLS.VolumeMount(c.SupportedOSType()))
	}
	return nodeVolumeMounts
}

// nodeEnvVars creates the node's envvars.
func (c *nodeComponent) nodeEnvVars() []corev1.EnvVar {
	// Set the clusterType.
	clusterType := "k8s,operator"

	// Note: Felix now activates certain special-case logic based on the provider in the cluster type; avoid changing
	// these unless you also update Felix's parsing logic.
	switch c.cfg.Installation.KubernetesProvider {
	case operatorv1.ProviderOpenShift:
		clusterType = clusterType + ",openshift"
	case operatorv1.ProviderEKS:
		clusterType = clusterType + ",ecs"
	case operatorv1.ProviderGKE:
		clusterType = clusterType + ",gke"
	case operatorv1.ProviderAKS:
		clusterType = clusterType + ",aks"
	}

	if bgpEnabled(c.cfg.Installation) {
		clusterType = clusterType + ",bgp"
	}

	if c.vppDataplaneEnabled() {
		clusterType = clusterType + ",vpp"
	}

	nodeEnv := []corev1.EnvVar{
		{Name: "DATASTORE_TYPE", Value: "kubernetes"},
		{Name: "WAIT_FOR_DATASTORE", Value: "true"},
		{Name: "CLUSTER_TYPE", Value: clusterType},
		{Name: "CALICO_DISABLE_FILE_LOGGING", Value: "false"},
		{Name: "FELIX_DEFAULTENDPOINTTOHOSTACTION", Value: "ACCEPT"},
		{Name: "FELIX_HEALTHENABLED", Value: "true"},
		{Name: "FELIX_HEALTHPORT", Value: fmt.Sprintf("%d", c.cfg.FelixHealthPort)},
		{
			Name: "NODENAME",
			ValueFrom: &corev1.EnvVarSource{
				FieldRef: &corev1.ObjectFieldSelector{FieldPath: "spec.nodeName"},
			},
		},
		{
			Name: "NAMESPACE",
			ValueFrom: &corev1.EnvVarSource{
				FieldRef: &corev1.ObjectFieldSelector{FieldPath: "metadata.namespace"},
			},
		},
		{Name: "FELIX_TYPHAK8SNAMESPACE", Value: common.CalicoNamespace},
		{Name: "FELIX_TYPHAK8SSERVICENAME", Value: TyphaServiceName},
		{Name: "FELIX_TYPHACAFILE", Value: c.cfg.TLS.TrustedBundle.MountPath()},
		{Name: "FELIX_TYPHACERTFILE", Value: c.cfg.TLS.NodeSecret.VolumeMountCertificateFilePath()},
		{Name: "FELIX_TYPHAKEYFILE", Value: c.cfg.TLS.NodeSecret.VolumeMountKeyFilePath()},
		{Name: "NO_DEFAULT_POOLS", Value: "true"},
	}

	// Only append goldmane variables if goldmane is running and we have a valid IP address,
	// as we rely on an explicitly configured host alias to resolve the goldmane service.
	if c.cfg.GoldmaneRunning && c.cfg.GoldmaneIP != "" {
		nodeEnv = append(nodeEnv,
			corev1.EnvVar{
				Name:  "FELIX_FLOWLOGSGOLDMANESERVER",
				Value: fmt.Sprintf("%s:7443", goldmaneDomainName),
			},
			corev1.EnvVar{
				Name:  "FELIX_FLOWLOGSFLUSHINTERVAL",
				Value: "15",
			})
	}

	// We need at least the CN or URISAN set, we depend on the validation
	// done by the core_controller that the Secret will have one.
	if c.cfg.TLS.TyphaCommonName != "" {
		nodeEnv = append(nodeEnv, corev1.EnvVar{Name: "FELIX_TYPHACN", Value: c.cfg.TLS.TyphaCommonName})
	}
	if c.cfg.TLS.TyphaURISAN != "" {
		nodeEnv = append(nodeEnv, corev1.EnvVar{Name: "FELIX_TYPHAURISAN", Value: c.cfg.TLS.TyphaURISAN})
	}

	if c.cfg.Installation.CNI != nil && c.cfg.Installation.CNI.Type == operatorv1.PluginCalico {
		// If using Calico CNI, we need to manage CNI credential rotation on the host.
		nodeEnv = append(nodeEnv, corev1.EnvVar{Name: "CALICO_MANAGE_CNI", Value: "true"})
	} else {
		nodeEnv = append(nodeEnv, corev1.EnvVar{Name: "CALICO_MANAGE_CNI", Value: "false"})
	}

	if c.cfg.Installation.CNI != nil && c.cfg.Installation.CNI.Type == operatorv1.PluginAmazonVPC {
		nodeEnv = append(nodeEnv, corev1.EnvVar{Name: "FELIX_BPFEXTTOSERVICECONNMARK", Value: "0x80"})
	}

	if c.vppDataplaneEnabled() {
		nodeEnv = append(nodeEnv, corev1.EnvVar{
			Name:  "FELIX_USEINTERNALDATAPLANEDRIVER",
			Value: "false",
		}, corev1.EnvVar{
			Name:  "FELIX_DATAPLANEDRIVER",
			Value: "/usr/local/bin/felix-plugins/felix-api-proxy",
		}, corev1.EnvVar{
			Name:  "FELIX_XDPENABLED",
			Value: "false",
		})
		if c.cfg.Installation.KubernetesProvider.IsEKS() {
			nodeEnv = append(nodeEnv, corev1.EnvVar{
				Name:  "FELIX_AWSSRCDSTCHECK",
				Value: "Disable",
			})
		}
	}

	if c.collectProcessPathEnabled() {
		nodeEnv = append(nodeEnv, corev1.EnvVar{Name: "FELIX_FLOWLOGSCOLLECTPROCESSPATH", Value: "true"})
	}

	// Determine MTU to use. If specified explicitly, use that. Otherwise, set defaults based on an overall
	// MTU of 1460.
	mtu := getMTU(c.cfg.Installation)
	if mtu != nil {
		vxlanMtu := strconv.Itoa(int(*mtu))
		wireguardMtu := strconv.Itoa(int(*mtu))
		nodeEnv = append(nodeEnv, corev1.EnvVar{Name: "FELIX_VXLANMTU", Value: vxlanMtu})
		nodeEnv = append(nodeEnv, corev1.EnvVar{Name: "FELIX_WIREGUARDMTU", Value: wireguardMtu})
	}

	// If host-local IPAM is in use, we need to configure calico/node to use the Kubernetes pod CIDR.
	cni := c.cfg.Installation.CNI
	if cni != nil && cni.IPAM != nil && cni.IPAM.Type == operatorv1.IPAMPluginHostLocal {
		nodeEnv = append(nodeEnv, corev1.EnvVar{
			Name:  "USE_POD_CIDR",
			Value: "true",
		})
	}

	// Configure whether or not BGP should be enabled.
	if !bgpEnabled(c.cfg.Installation) {
		if c.cfg.Installation.CNI.Type == operatorv1.PluginCalico {
			if c.cfg.Installation.CNI.IPAM.Type == operatorv1.IPAMPluginHostLocal {
				// If BGP is disabled and using HostLocal, then that means routing is done
				// by Cloud routing, so networking backend is none. (because we don't support
				// vxlan with HostLocal.)
				nodeEnv = append(nodeEnv, corev1.EnvVar{Name: "CALICO_NETWORKING_BACKEND", Value: "none"})
			} else {
				// If BGP is disabled, then set the networking backend to "vxlan". This means that BIRD will be
				// disabled, and VXLAN will optionally be configurable via IP pools.
				nodeEnv = append(nodeEnv, corev1.EnvVar{Name: "CALICO_NETWORKING_BACKEND", Value: "vxlan"})
			}
		} else {
			// If not using Calico networking at all, set the backend to "none".
			nodeEnv = append(nodeEnv, corev1.EnvVar{Name: "CALICO_NETWORKING_BACKEND", Value: "none"})
		}
	} else {
		// BGP is enabled.
		if c.vppDataplaneEnabled() {
			// VPP comes with its own BGP daemon, so bird should be disabled
			nodeEnv = append(nodeEnv, corev1.EnvVar{Name: "CALICO_NETWORKING_BACKEND", Value: "none"})
		} else {
			nodeEnv = append(nodeEnv, corev1.EnvVar{Name: "CALICO_NETWORKING_BACKEND", Value: "bird"})
		}
		if mtu != nil {
			ipipMtu := strconv.Itoa(int(*mtu))
			nodeEnv = append(nodeEnv, corev1.EnvVar{Name: "FELIX_IPINIPMTU", Value: ipipMtu})
		}
	}

	// IPv4 auto-detection configuration.
	var v4Method string
	if c.cfg.Installation.CalicoNetwork != nil {
		v4Method = getAutodetectionMethod(c.cfg.Installation.CalicoNetwork.NodeAddressAutodetectionV4)
	}
	if v4Method != "" {
		// IPv4 Auto-detection is enabled.
		nodeEnv = append(nodeEnv, corev1.EnvVar{Name: "IP", Value: "autodetect"})
		nodeEnv = append(nodeEnv, corev1.EnvVar{Name: "IP_AUTODETECTION_METHOD", Value: v4Method})
	} else {
		// IPv4 Auto-detection is disabled.
		nodeEnv = append(nodeEnv, corev1.EnvVar{Name: "IP", Value: "none"})
	}

	// IPv6 auto-detection and ippool configuration.
	var v6Method string
	if c.cfg.Installation.CalicoNetwork != nil {
		v6Method = getAutodetectionMethod(c.cfg.Installation.CalicoNetwork.NodeAddressAutodetectionV6)
	}
	if v6Method != "" {
		// IPv6 Auto-detection is enabled.
		nodeEnv = append(nodeEnv, corev1.EnvVar{Name: "IP6", Value: "autodetect"})
		nodeEnv = append(nodeEnv, corev1.EnvVar{Name: "IP6_AUTODETECTION_METHOD", Value: v6Method})
		nodeEnv = append(nodeEnv, corev1.EnvVar{Name: "FELIX_IPV6SUPPORT", Value: "true"})

		// Set CALICO_ROUTER_ID to "hash" for IPv6-only with BGP enabled.
		if v4Method == "" && bgpEnabled(c.cfg.Installation) {
			nodeEnv = append(nodeEnv, corev1.EnvVar{Name: "CALICO_ROUTER_ID", Value: "hash"})
		}

		// Set IPv6 VXLAN and Wireguard MTU
		if mtu != nil {
			vxlanMtuV6 := strconv.Itoa(int(*mtu))
			wireguardMtuV6 := strconv.Itoa(int(*mtu))
			nodeEnv = append(nodeEnv, corev1.EnvVar{Name: "FELIX_VXLANMTUV6", Value: vxlanMtuV6})
			nodeEnv = append(nodeEnv, corev1.EnvVar{Name: "FELIX_WIREGUARDMTUV6", Value: wireguardMtuV6})
		}
	} else {
		// IPv6 Auto-detection is disabled.
		nodeEnv = append(nodeEnv, corev1.EnvVar{Name: "IP6", Value: "none"})
		nodeEnv = append(nodeEnv, corev1.EnvVar{Name: "FELIX_IPV6SUPPORT", Value: "false"})
	}

	if c.cfg.Installation.Variant.IsEnterprise() {
		// Add in Calico Enterprise specific configuration.
		extraNodeEnv := []corev1.EnvVar{
			{Name: "FELIX_PROMETHEUSREPORTERENABLED", Value: "true"},
			{Name: "FELIX_PROMETHEUSREPORTERPORT", Value: fmt.Sprintf("%d", c.cfg.NodeReporterMetricsPort)},
			{Name: "FELIX_FLOWLOGSFILEENABLED", Value: "true"},
			{Name: "FELIX_FLOWLOGSFILEINCLUDELABELS", Value: "true"},
			{Name: "FELIX_FLOWLOGSFILEINCLUDEPOLICIES", Value: "true"},
			{Name: "FELIX_FLOWLOGSFILEINCLUDESERVICE", Value: "true"},
			{Name: "FELIX_FLOWLOGSENABLENETWORKSETS", Value: "true"},
			{Name: "FELIX_FLOWLOGSCOLLECTPROCESSINFO", Value: "true"},
			{Name: "FELIX_DNSLOGSFILEENABLED", Value: "true"},
			{Name: "FELIX_DNSLOGSFILEPERNODELIMIT", Value: "1000"},
		}

		if c.cfg.Installation.CalicoNetwork != nil && c.cfg.Installation.CalicoNetwork.MultiInterfaceMode != nil {
			extraNodeEnv = append(extraNodeEnv, corev1.EnvVar{Name: "MULTI_INTERFACE_MODE", Value: c.cfg.Installation.CalicoNetwork.MultiInterfaceMode.Value()})
		}

		if c.cfg.PrometheusServerTLS != nil {
			extraNodeEnv = append(extraNodeEnv,
				corev1.EnvVar{Name: "FELIX_PROMETHEUSREPORTERCERTFILE", Value: c.cfg.PrometheusServerTLS.VolumeMountCertificateFilePath()},
				corev1.EnvVar{Name: "FELIX_PROMETHEUSREPORTERKEYFILE", Value: c.cfg.PrometheusServerTLS.VolumeMountKeyFilePath()},
				corev1.EnvVar{Name: "FELIX_PROMETHEUSREPORTERCAFILE", Value: c.cfg.TLS.TrustedBundle.MountPath()},
			)
		}
		nodeEnv = append(nodeEnv, extraNodeEnv...)
	}

	if c.cfg.Installation.NodeMetricsPort != nil {
		// If a node metrics port was given, then enable felix prometheus metrics and set the port.
		// Note that this takes precedence over any FelixConfiguration resources in the cluster.
		extraNodeEnv := []corev1.EnvVar{
			{Name: "FELIX_PROMETHEUSMETRICSENABLED", Value: "true"},
			{Name: "FELIX_PROMETHEUSMETRICSPORT", Value: fmt.Sprintf("%d", *c.cfg.Installation.NodeMetricsPort)},
		}
		nodeEnv = append(nodeEnv, extraNodeEnv...)
	}

	// Configure provider specific environment variables here.
	switch c.cfg.Installation.KubernetesProvider {
	// For AKS/AzureVNET and EKS/VPCCNI, we must explicitly ask felix to add host IP's to wireguard ifaces
	case operatorv1.ProviderAKS:
		if c.cfg.Installation.CNI.Type == operatorv1.PluginAzureVNET {
			nodeEnv = append(nodeEnv, corev1.EnvVar{Name: "FELIX_WIREGUARDHOSTENCRYPTIONENABLED", Value: "true"})
		}
	case operatorv1.ProviderEKS:
		if c.cfg.Installation.CNI.Type == operatorv1.PluginAmazonVPC {
			nodeEnv = append(nodeEnv, corev1.EnvVar{Name: "FELIX_WIREGUARDHOSTENCRYPTIONENABLED", Value: "true"})
		}
	}

	switch c.cfg.Installation.CNI.Type {
	case operatorv1.PluginAmazonVPC:
		nodeEnv = append(nodeEnv, corev1.EnvVar{Name: "FELIX_INTERFACEPREFIX", Value: "eni"})
		nodeEnv = append(nodeEnv, corev1.EnvVar{Name: "FELIX_IPTABLESMANGLEALLOWACTION", Value: "Return"})
	case operatorv1.PluginGKE:
		// The GKE CNI plugin uses its own interface prefix.
		nodeEnv = append(nodeEnv, corev1.EnvVar{Name: "FELIX_INTERFACEPREFIX", Value: "gke"})
		// The GKE CNI plugin has its own iptables rules. Defer to them after ours.
		nodeEnv = append(nodeEnv, corev1.EnvVar{Name: "FELIX_IPTABLESMANGLEALLOWACTION", Value: "Return"})
		nodeEnv = append(nodeEnv, corev1.EnvVar{Name: "FELIX_IPTABLESFILTERALLOWACTION", Value: "Return"})
	case operatorv1.PluginAzureVNET:
		nodeEnv = append(nodeEnv, corev1.EnvVar{Name: "FELIX_INTERFACEPREFIX", Value: "azv"})
	}

	if c.cfg.Installation.CNI.Type != operatorv1.PluginCalico {
		nodeEnv = append(nodeEnv, corev1.EnvVar{Name: "FELIX_ROUTESOURCE", Value: "WorkloadIPs"})
	}

	nodeEnv = append(nodeEnv, c.cfg.K8sServiceEp.EnvVars()...)

	if c.cfg.BGPLayouts != nil {
		nodeEnv = append(nodeEnv, corev1.EnvVar{
			Name:  "CALICO_EARLY_NETWORKING",
			Value: BGPLayoutPath,
		})
	}

	if c.cfg.Installation.CalicoNetwork != nil &&
		c.cfg.Installation.CalicoNetwork.LinuxPolicySetupTimeoutSeconds != nil &&
		*c.cfg.Installation.CalicoNetwork.LinuxPolicySetupTimeoutSeconds > 0 {
		nodeEnv = append(nodeEnv, corev1.EnvVar{
			Name:  "FELIX_ENDPOINTSTATUSPATHPREFIX",
			Value: "/var/run/calico",
		})
	}

	return nodeEnv
}

// nodeLifecycle creates the node's postStart and preStop hooks.
func (c *nodeComponent) nodeLifecycle() *corev1.Lifecycle {
	return &corev1.Lifecycle{
		PreStop: &corev1.LifecycleHandler{Exec: &corev1.ExecAction{
			Command: []string{components.CalicoBinaryPath, "component", "node", "shutdown"},
		}},
	}
}

// nodeLivenessReadinessProbes creates the node's liveness and readiness probes.
func (c *nodeComponent) nodeLivenessReadinessProbes() (*corev1.Probe, *corev1.Probe) {
	// Determine liveness and readiness configuration for node.
	livenessPort := intstr.FromInt(c.cfg.FelixHealthPort)
	var readinessCmd []string

	readinessCmd = []string{components.CalicoBinaryPath, "component", "node", "health", "--bird-ready", "--felix-ready"}
	if c.cfg.Installation.Variant.IsEnterprise() {
		readinessCmd = append(readinessCmd, "--bgp-metrics-ready")
	}
	// If not using BGP or using VPP, don't check bird status (or bgp metrics server for enterprise).
	if !bgpEnabled(c.cfg.Installation) || c.vppDataplaneEnabled() {
		readinessCmd = []string{components.CalicoBinaryPath, "component", "node", "health", "--felix-ready"}
	}

	lp := &corev1.Probe{
		ProbeHandler: corev1.ProbeHandler{
			HTTPGet: &corev1.HTTPGetAction{
				Host: "localhost",
				Path: "/liveness",
				Port: livenessPort,
			},
		},
		TimeoutSeconds: 10,
	}
	rp := &corev1.Probe{
		ProbeHandler: corev1.ProbeHandler{Exec: &corev1.ExecAction{Command: readinessCmd}},
		// Use a shorter period than the global default (30s) so that calico-node is
		// marked ready promptly after startup. The global default is too slow for
		// calico-node, which typically becomes ready within ~10s of container start.
		PeriodSeconds:  10,
		TimeoutSeconds: 5,
	}
	return lp, rp
}

// nodeMetricsService creates a Service which exposes two endpoints on calico/node for
// reporting Prometheus metrics (for policy enforcement activity and BGP stats).
// This service is used internally by Calico Enterprise and is separate from general
// Prometheus metrics which are user-configurable.
func (c *nodeComponent) nodeMetricsService() *corev1.Service {
	ports := []corev1.ServicePort{
		{
			Name:       "calico-metrics-port",
			Port:       int32(c.cfg.NodeReporterMetricsPort),
			TargetPort: intstr.FromInt(c.cfg.NodeReporterMetricsPort),
			Protocol:   corev1.ProtocolTCP,
		},
		{
			Name:       "calico-bgp-metrics-port",
			Port:       nodeBGPReporterPort,
			TargetPort: intstr.FromInt(int(nodeBGPReporterPort)),
			Protocol:   corev1.ProtocolTCP,
		},
	}

	if c.cfg.FelixPrometheusMetricsEnabled {
		felixMetricsPort := int32(c.cfg.FelixPrometheusMetricsPort)

		ports = append(ports, corev1.ServicePort{
			Name:       "felix-metrics-port",
			Port:       felixMetricsPort,
			TargetPort: intstr.FromInt(int(felixMetricsPort)),
			Protocol:   corev1.ProtocolTCP,
		})
	}

	return &corev1.Service{
		TypeMeta: metav1.TypeMeta{Kind: "Service", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      CalicoNodeMetricsService,
			Namespace: common.CalicoNamespace,
			Labels:    map[string]string{"k8s-app": CalicoNodeObjectName},
		},
		Spec: corev1.ServiceSpec{
			Selector: map[string]string{"k8s-app": CalicoNodeObjectName},
			// Important: "None" tells Kubernetes that we want a headless service with
			// no kube-proxy load balancer.  If we omit this then kube-proxy will render
			// a huge set of iptables rules for this service since there's an instance
			// on every node.
			ClusterIP: "None",
			Ports:     ports,
		},
	}
}

// getAutodetectionMethod returns the IP auto detection method in a form understandable by the calico/node
// startup processing. It returns an empty string if IP auto detection should not be enabled.
func getAutodetectionMethod(ad *operatorv1.NodeAddressAutodetection) string {
	if ad != nil {
		if len(ad.Interface) != 0 {
			return fmt.Sprintf("interface=%s", ad.Interface)
		}
		if len(ad.SkipInterface) != 0 {
			return fmt.Sprintf("skip-interface=%s", ad.SkipInterface)
		}
		if len(ad.CanReach) != 0 {
			return fmt.Sprintf("can-reach=%s", ad.CanReach)
		}
		if ad.FirstFound != nil && *ad.FirstFound {
			return "first-found"
		}
		if len(ad.CIDRS) != 0 {
			return fmt.Sprintf("cidr=%s", strings.Join(ad.CIDRS, ","))
		}
		if ad.Kubernetes != nil {
			if *ad.Kubernetes == operatorv1.NodeInternalIP {
				return "kubernetes-internal-ip"
			}
		}
	}
	return ""
}

// GetIPv4Pool returns the IPv4 IPPool in an installation, or nil if one can't be found.
func GetIPv4Pool(pools []operatorv1.IPPool) *operatorv1.IPPool {
	for ii, pool := range pools {
		addr, _, err := net.ParseCIDR(pool.CIDR)
		if err == nil {
			if addr.To4() != nil {
				return &pools[ii]
			}
		}
	}

	return nil
}

// GetIPv6Pool returns the IPv6 IPPool in an installation, or nil if one can't be found.
func GetIPv6Pool(pools []operatorv1.IPPool) *operatorv1.IPPool {
	for ii, pool := range pools {
		addr, _, err := net.ParseCIDR(pool.CIDR)
		if err == nil {
			if addr.To4() == nil {
				return &pools[ii]
			}
		}
	}

	return nil
}

// bgpEnabled returns true if the given Installation enables BGP, false otherwise.
func bgpEnabled(instance *operatorv1.InstallationSpec) bool {
	return instance.CalicoNetwork != nil &&
		instance.CalicoNetwork.BGP != nil &&
		*instance.CalicoNetwork.BGP == operatorv1.BGPEnabled
}

// getMTU returns the MTU configured in the Installation if there is one, nil otherwise.
func getMTU(instance *operatorv1.InstallationSpec) *int32 {
	var mtu *int32
	if instance.CalicoNetwork != nil && instance.CalicoNetwork.MTU != nil {
		mtu = instance.CalicoNetwork.MTU
	}
	return mtu
}

// DefaultCNIDirectories returns the binary and network config directories for the configured platform.
func DefaultCNIDirectories(provider operatorv1.Provider) (string, string) {
	var cniBinDir, cniNetDir string
	switch provider {
	case operatorv1.ProviderOpenShift:
		cniNetDir = "/var/run/multus/cni/net.d"
		cniBinDir = "/var/lib/cni/bin"
	case operatorv1.ProviderGKE:
		// Used if we're installing a CNI plugin. If using the GKE plugin, these are not necessary.
		cniBinDir = "/home/kubernetes/bin"
		cniNetDir = "/etc/cni/net.d"
	default:
		// Default locations to match vanilla Kubernetes.
		cniBinDir = "/opt/cni/bin"
		cniNetDir = "/etc/cni/net.d"
	}
	return cniNetDir, cniBinDir
}
