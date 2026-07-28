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

package render

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"strconv"
	"strings"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"sigs.k8s.io/controller-runtime/pkg/client"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/components"
	"github.com/tigera/operator/pkg/controller/k8sapi"
	rcomp "github.com/tigera/operator/pkg/render/common/components"
	rmeta "github.com/tigera/operator/pkg/render/common/meta"
	"github.com/tigera/operator/pkg/render/common/securitycontext"
	"github.com/tigera/operator/pkg/tls/certificatemanagement"
)

const (
	WindowsNodeObjectName     = "calico-node-windows"
	WindowsNodeMetricsService = "calico-node-metrics-windows"
)

func Windows(
	cfg *WindowsConfiguration,
) Component {
	return &windowsComponent{cfg: cfg}
}

type WindowsConfiguration struct {
	K8sServiceEp            k8sapi.ServiceEndpoint
	K8sDNSServers           []string
	Installation            *operatorv1.InstallationSpec
	ClusterDomain           string
	TLS                     *TyphaNodeTLS
	PrometheusServerTLS     certificatemanagement.KeyPairInterface
	NodeReporterMetricsPort int
	VXLANVNI                int
}

type windowsComponent struct {
	cfg       *WindowsConfiguration
	cniImage  string
	nodeImage string
}

func (c *windowsComponent) ResolveImages(is *operatorv1.ImageSet) error {
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

	if c.cfg.Installation.Variant.IsEnterprise() {
		c.cniImage = appendIfErr(components.GetReference(components.ComponentTigeraCNIWindows, reg, path, prefix, is))
		c.nodeImage = appendIfErr(components.GetReference(components.ComponentTigeraNodeWindows, reg, path, prefix, is))
	} else {
		c.cniImage = appendIfErr(components.GetReference(components.ComponentCalicoCNIWindows, reg, path, prefix, is))
		c.nodeImage = appendIfErr(components.GetReference(components.ComponentCalicoNodeWindows, reg, path, prefix, is))
	}

	if len(errMsgs) != 0 {
		return fmt.Errorf("%s", strings.Join(errMsgs, ","))
	}
	return nil
}

func (c *windowsComponent) SupportedOSType() rmeta.OSType {
	return rmeta.OSTypeWindows
}

func (c *windowsComponent) Objects() ([]client.Object, []client.Object) {
	// Clean up old windows upgrader daemonset if present
	objsToDelete := []client.Object{
		&corev1.ServiceAccount{
			TypeMeta: metav1.TypeMeta{Kind: "ServiceAccount", APIVersion: "v1"},
			ObjectMeta: metav1.ObjectMeta{
				Name:      common.CalicoWindowsUpgradeResourceName,
				Namespace: common.CalicoNamespace,
			},
		},
		&appsv1.DaemonSet{
			TypeMeta: metav1.TypeMeta{Kind: "DaemonSet", APIVersion: "apps/v1"},
			ObjectMeta: metav1.ObjectMeta{
				Name:      common.CalicoWindowsUpgradeResourceName,
				Namespace: "calico-system",
			},
		},
	}

	objs := []client.Object{}

	if c.cfg.Installation.Variant.IsEnterprise() {
		// Include Service for exposing node metrics.
		objs = append(objs, c.nodeMetricsService())
	}

	cniConfig := c.windowsCNIConfigMap()
	if cniConfig != nil {
		objs = append(objs, cniConfig)
	}

	objs = append(objs, c.windowsDaemonset(cniConfig))

	return objs, objsToDelete
}

func (c *windowsComponent) Ready() bool {
	return true
}

// nodeMetricsService creates a Service which exposes two endpoints on calico/node for
// reporting Prometheus metrics (for policy enforcement activity and BGP stats).
// This service is used internally by Calico Enterprise and is separate from general
// Prometheus metrics which are user-configurable.
func (c *windowsComponent) nodeMetricsService() *corev1.Service {
	return &corev1.Service{
		TypeMeta: metav1.TypeMeta{Kind: "Service", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      WindowsNodeMetricsService,
			Namespace: common.CalicoNamespace,
			Labels:    map[string]string{"k8s-app": WindowsNodeObjectName},
		},
		Spec: corev1.ServiceSpec{
			Selector: map[string]string{"k8s-app": WindowsNodeObjectName},
			// Important: "None" tells Kubernetes that we want a headless service with
			// no kube-proxy load balancer.  If we omit this then kube-proxy will render
			// a huge set of iptables rules for this service since there's an instance
			// on every node.
			ClusterIP: "None",
			Ports: []corev1.ServicePort{
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
			},
		},
	}
}

// windowsCNIConfigMap returns a config map containing the CNI network config to be installed on each node.
// Returns nil if no configmap is needed.
func (c *windowsComponent) windowsCNIConfigMap() *corev1.ConfigMap {
	if c.cfg.Installation.CNI.Type != operatorv1.PluginCalico {
		// If calico cni is not being used, then no cni configmap is needed.
		return nil
	}

	plugins := make([]interface{}, 0)
	plugins = append(plugins, c.createCalicoPluginConfig())

	pluginsArray, _ := json.Marshal(plugins)

	config := fmt.Sprintf(`{
			  "name": "Calico",
			  "cniVersion": "%s",
			  "plugins": %s
			}`, c.cfg.Installation.CNI.ResolvedSpecVersion(), string(pluginsArray))

	return &corev1.ConfigMap{
		TypeMeta: metav1.TypeMeta{Kind: "ConfigMap", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "cni-config-windows",
			Namespace: common.CalicoNamespace,
			Labels:    map[string]string{},
		},
		Data: map[string]string{
			"config": config,
		},
	}
}

// cniEnvVars creates the CNI container's envvars.
func (c *windowsComponent) cniEnvVars() []corev1.EnvVar {
	if c.cfg.Installation.CNI.Type != operatorv1.PluginCalico {
		return []corev1.EnvVar{}
	}

	cniNetDir := c.cfg.Installation.WindowsNodes.CNIConfigDir

	// cniNetDir is used in the cni config file, and will have the "c:" prefix added to it.
	cniNetDir = strings.TrimPrefix(cniNetDir, "c:")
	cniNetDir = strings.TrimPrefix(cniNetDir, "C:")

	envVars := []corev1.EnvVar{
		{Name: "SLEEP", Value: "false"},
		{Name: "CNI_PLUGIN_TYPE", Value: string(c.cfg.Installation.CNI.Type)},
		{Name: "CNI_BIN_DIR", Value: "/host/opt/cni/bin"},
		{Name: "CNI_CONF_NAME", Value: "10-calico.conflist"},
		{Name: "CNI_NET_DIR", Value: cniNetDir},
		{Name: "KUBERNETES_DNS_SERVERS", Value: strings.Join(c.cfg.K8sDNSServers, ",")},
		{Name: "KUBERNETES_SERVICE_CIDRS", Value: strings.Join(c.cfg.Installation.ServiceCIDRs, ",")},
		{Name: "VXLAN_VNI", Value: fmt.Sprintf("%d", c.cfg.VXLANVNI)},
		{
			Name: "KUBERNETES_NODE_NAME",
			ValueFrom: &corev1.EnvVarSource{
				FieldRef: &corev1.ObjectFieldSelector{FieldPath: "spec.nodeName"},
			},
		},
		{
			Name: "CNI_NETWORK_CONFIG",
			ValueFrom: &corev1.EnvVarSource{
				ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
					Key: "config",
					LocalObjectReference: corev1.LocalObjectReference{
						Name: "cni-config-windows",
					},
				},
			},
		},
	}

	envVars = append(envVars, c.cfg.K8sServiceEp.EnvVars()...)

	return envVars
}

func (c *windowsComponent) createCalicoPluginConfig() map[string]interface{} {
	// Determine MTU to use for veth interfaces.
	// Zero means to use auto-detection.
	var mtu int32 = 0
	if m := getMTU(c.cfg.Installation); m != nil {
		mtu = *m
	}

	ipam := map[string]interface{}{
		"type":   "calico-ipam",
		"subnet": "usePodCidr",
	}
	if c.cfg.Installation.CNI.IPAM.Type == operatorv1.IPAMPluginHostLocal {
		ipam["type"] = "host-local"
	}

	// Determine the networking backend
	backend := getWindowsBackend(c.cfg.Installation)

	apiRoot := c.cfg.K8sServiceEp.CNIAPIRoot()

	vxlanMACPrefix := "0E-2A"
	if c.cfg.Installation.WindowsNodes != nil && c.cfg.Installation.WindowsNodes.VXLANMACPrefix != "" {
		vxlanMACPrefix = c.cfg.Installation.WindowsNodes.VXLANMACPrefix
	}

	capabilities := map[string]interface{}{
		"dns": true,
	}

	// calico plugin
	calicoPluginConfig := map[string]interface{}{
		"type":                       "calico",
		"name":                       "Calico",
		"windows_use_single_network": true,
		"mode":                       backend,
		"vxlan_mac_prefix":           vxlanMACPrefix,
		"vxlan_vni":                  c.cfg.VXLANVNI,
		"mtu":                        mtu,
		"policy": map[string]interface{}{
			"type": "k8s",
		},
		"log_file_path":          "c:/var/log/calico/cni/cni.log",
		"windows_loopback_DSR":   "__DSR_SUPPORT__",
		"capabilities":           capabilities,
		"nodename":               "__KUBERNETES_NODE_NAME__",
		"nodename_file":          "__NODENAME_FILE__",
		"nodename_file_optional": true,
		"datastore_type":         "kubernetes",
		"ipam":                   ipam,
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

	cniNetDir := c.cfg.Installation.WindowsNodes.CNIConfigDir
	cniNetDir = strings.TrimPrefix(cniNetDir, "c:")
	cniNetDir = strings.TrimPrefix(cniNetDir, "C:")
	kubernetes := map[string]interface{}{
		"kubeconfig": filepath.ToSlash(filepath.Join("c:", cniNetDir, "calico-kubeconfig")),
	}

	if apiRoot != "" {
		kubernetes["k8s_api_root"] = apiRoot
	}
	calicoPluginConfig["kubernetes"] = kubernetes

	dns := map[string]interface{}{
		"Nameservers": c.cfg.K8sDNSServers,
		"Search": []string{
			"svc.cluster.local",
		},
	}
	calicoPluginConfig["DNS"] = dns

	policies := []map[string]interface{}{
		{
			"Name": "EndpointPolicy",
			"Value": map[string]interface{}{
				"Type":          "OutBoundNAT",
				"ExceptionList": c.cfg.Installation.ServiceCIDRs,
			},
		},
	}
	for _, serviceCIDR := range c.cfg.Installation.ServiceCIDRs {
		policies = append(policies, map[string]interface{}{
			"Name": "EndpointPolicy",
			"Value": map[string]interface{}{
				"Type":              "SDNROUTE",
				"DestinationPrefix": serviceCIDR,
				"NeedEncap":         true,
			},
		})
	}
	calicoPluginConfig["policies"] = policies

	return calicoPluginConfig
}

// windowsVolumes creates the node's volumes.
func (c *windowsComponent) windowsVolumes() []corev1.Volume {
	fileOrCreate := corev1.HostPathFileOrCreate
	dirOrCreate := corev1.HostPathDirectoryOrCreate

	volumes := []corev1.Volume{
		{Name: "lib-modules", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/lib/modules"}}},
		{Name: "xtables-lock", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/run/xtables.lock", Type: &fileOrCreate}}},
		{Name: "policysync", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/var/run/nodeagent", Type: &dirOrCreate}}},
		c.cfg.TLS.TrustedBundle.Volume(),
		c.cfg.TLS.NodeSecret.Volume(),
		corev1.Volume{Name: "var-run-calico", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/var/run/calico", Type: &dirOrCreate}}},
		corev1.Volume{Name: "var-lib-calico", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/var/lib/calico", Type: &dirOrCreate}}},
	}

	// If needed for this configuration, then include the CNI volumes.
	if c.cfg.Installation.CNI.Type == operatorv1.PluginCalico {
		// Determine directories to use for CNI artifacts based on the provider.
		volumes = append(volumes, corev1.Volume{Name: "cni-bin-dir", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: c.cfg.Installation.WindowsNodes.CNIBinDir, Type: &dirOrCreate}}})
		volumes = append(volumes, corev1.Volume{Name: "cni-net-dir", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: c.cfg.Installation.WindowsNodes.CNIConfigDir}}})
		volumes = append(volumes, corev1.Volume{Name: "cni-log-dir", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: c.cfg.Installation.WindowsNodes.CNILogDir, Type: &dirOrCreate}}})
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

	if c.cfg.PrometheusServerTLS != nil {
		volumes = append(volumes, c.cfg.PrometheusServerTLS.Volume())
	}

	return volumes
}

// uninstallEnvVars creates the uninstall-calico initContainer's envvars.
func (c *windowsComponent) uninstallEnvVars() []corev1.EnvVar {
	envVars := []corev1.EnvVar{
		{Name: "SLEEP", Value: "false"},
		{Name: "CNI_PLUGIN_TYPE", Value: string(c.cfg.Installation.CNI.Type)},
		{Name: "CNI_BIN_DIR", Value: "/host/opt/cni/bin"},
		{Name: "CNI_CONF_NAME", Value: "10-calico.conflist"},
		{Name: "CNI_NET_DIR", Value: "/host/etc/cni/net.d"},
	}

	return envVars
}

// uninstallContainer creates the node's init container that uninstalls non-HPC Calico from the host.
func (c *windowsComponent) uninstallContainer() corev1.Container {
	// Determine environment to pass to the uninstall-calico init container.
	uninstallEnv := c.uninstallEnvVars()
	uninstallVolumeMounts := []corev1.VolumeMount{}

	// Only mount CNI volumes if using Calico CNI
	if c.cfg.Installation.CNI.Type == operatorv1.PluginCalico {
		uninstallVolumeMounts = append(uninstallVolumeMounts, corev1.VolumeMount{MountPath: "/host/opt/cni/bin", Name: "cni-bin-dir"})
		uninstallVolumeMounts = append(uninstallVolumeMounts, corev1.VolumeMount{MountPath: "/host/etc/cni/net.d", Name: "cni-net-dir"})
	}

	return corev1.Container{
		Name:            "uninstall-calico",
		Image:           c.nodeImage,
		Args:            []string{"$env:CONTAINER_SANDBOX_MOUNT_POINT/uninstall-calico.ps1"},
		Env:             uninstallEnv,
		SecurityContext: securitycontext.NewWindowsHostProcessContext(),
		VolumeMounts:    uninstallVolumeMounts,
	}
}

// cniContainer creates the node's init container that installs CNI.
func (c *windowsComponent) cniContainer() corev1.Container {
	// Determine environment to pass to the CNI init container.
	cniEnv := c.cniEnvVars()
	cniVolumeMounts := []corev1.VolumeMount{
		{MountPath: "/host/opt/cni/bin", Name: "cni-bin-dir"},
		{MountPath: "/host/etc/cni/net.d", Name: "cni-net-dir"},
	}

	// install-cni runs the cni image, which ships the combined binary at
	// /opt/cni/bin/calico.exe. The node containers below run the node image,
	// which ships the same binary at /CalicoWindows/calico.exe. Keep each
	// command's path in sync with the image it runs in.
	return corev1.Container{
		Name:            "install-cni",
		Image:           c.cniImage,
		Command:         []string{"$env:CONTAINER_SANDBOX_MOUNT_POINT/opt/cni/bin/calico.exe", "component", "cni", "install"},
		Env:             cniEnv,
		SecurityContext: securitycontext.NewWindowsHostProcessContext(),
		VolumeMounts:    cniVolumeMounts,
	}
}

// nodeContainer creates the windows node startup container.
func (c *windowsComponent) nodeContainer() corev1.Container {
	return corev1.Container{
		Name:            "node",
		Image:           c.nodeImage,
		Args:            []string{"$env:CONTAINER_SANDBOX_MOUNT_POINT/CalicoWindows/node-service.ps1"},
		WorkingDir:      "$env:CONTAINER_SANDBOX_MOUNT_POINT/CalicoWindows/",
		Resources:       c.nodeWindowsResources(),
		SecurityContext: securitycontext.NewWindowsHostProcessContext(),
		Env:             c.windowsEnvVars(),
		VolumeMounts:    c.windowsVolumeMounts(),
	}
}

// felixContainer creates the windows felix container.
func (c *windowsComponent) felixContainer() corev1.Container {

	lp, rp := c.windowsLivenessReadinessProbes()

	return corev1.Container{
		Name:            "felix",
		Image:           c.nodeImage,
		Args:            []string{"$env:CONTAINER_SANDBOX_MOUNT_POINT/CalicoWindows/felix-service.ps1"},
		WorkingDir:      "$env:CONTAINER_SANDBOX_MOUNT_POINT/CalicoWindows/",
		Resources:       c.felixWindowsResources(),
		SecurityContext: securitycontext.NewWindowsHostProcessContext(),
		Env:             c.windowsEnvVars(),
		VolumeMounts:    c.windowsVolumeMounts(),
		LivenessProbe:   lp,
		ReadinessProbe:  rp,
		Lifecycle:       c.windowsLifecycle(),
	}
}

// confdContainer creates the windows confd container (used only for the windows-bgp backend).
func (c *windowsComponent) confdContainer() corev1.Container {
	return corev1.Container{
		Name:            "confd",
		Image:           c.nodeImage,
		Args:            []string{"$env:CONTAINER_SANDBOX_MOUNT_POINT/CalicoWindows/confd/confd-service.ps1"},
		WorkingDir:      "$env:CONTAINER_SANDBOX_MOUNT_POINT/CalicoWindows/",
		Resources:       c.confdWindowsResources(),
		SecurityContext: securitycontext.NewWindowsHostProcessContext(),
		Env:             c.windowsEnvVars(),
		VolumeMounts:    c.windowsVolumeMounts(),
	}
}

// windowsEnvVars creates the node's envvars.
func (c *windowsComponent) windowsEnvVars() []corev1.EnvVar {
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

	clusterType = clusterType + ",windows"

	vxlanAdapter := ""
	if c.cfg.Installation.WindowsNodes != nil && c.cfg.Installation.WindowsNodes.VXLANAdapter != "" {
		vxlanAdapter = c.cfg.Installation.WindowsNodes.VXLANAdapter
	}

	windowsEnv := []corev1.EnvVar{
		{Name: "CNI_PLUGIN_TYPE", Value: string(c.cfg.Installation.CNI.Type)},
		{Name: "DATASTORE_TYPE", Value: "kubernetes"},
		{Name: "WAIT_FOR_DATASTORE", Value: "true"},
		{Name: "CLUSTER_TYPE", Value: clusterType},
		{Name: "CALICO_DISABLE_FILE_LOGGING", Value: "false"},
		{Name: "FELIX_DEFAULTENDPOINTTOHOSTACTION", Value: "ACCEPT"},
		{Name: "FELIX_HEALTHENABLED", Value: "true"},
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
		{Name: "VXLAN_VNI", Value: fmt.Sprintf("%d", c.cfg.VXLANVNI)},
		{Name: "VXLAN_ADAPTER", Value: vxlanAdapter},
	}
	// We need at least the CN or URISAN set, we depend on the validation
	// done by the core_controller that the Secret will have one.
	if c.cfg.TLS.TyphaCommonName != "" {
		windowsEnv = append(windowsEnv, corev1.EnvVar{Name: "FELIX_TYPHACN", Value: c.cfg.TLS.TyphaCommonName})
	}
	if c.cfg.TLS.TyphaURISAN != "" {
		windowsEnv = append(windowsEnv, corev1.EnvVar{Name: "FELIX_TYPHAURISAN", Value: c.cfg.TLS.TyphaURISAN})
	}

	kubeNetwork := "Calico.*"
	if c.cfg.Installation.CNI != nil && c.cfg.Installation.CNI.Type == operatorv1.PluginCalico {
		// If using Calico CNI, we need to manage CNI credential rotation on the host.
		windowsEnv = append(windowsEnv, corev1.EnvVar{Name: "CALICO_MANAGE_CNI", Value: "true"})
	} else {
		windowsEnv = append(windowsEnv, corev1.EnvVar{Name: "CALICO_MANAGE_CNI", Value: "false"})
	}

	if c.cfg.Installation.CNI != nil && c.cfg.Installation.CNI.Type == operatorv1.PluginAmazonVPC {
		windowsEnv = append(windowsEnv, corev1.EnvVar{Name: "FELIX_BPFEXTTOSERVICECONNMARK", Value: "0x80"})
		kubeNetwork = "vpc.*"
	}
	if c.cfg.Installation.CNI != nil && c.cfg.Installation.CNI.Type == operatorv1.PluginAzureVNET {
		kubeNetwork = "azure.*"
	}

	windowsEnv = append(windowsEnv, corev1.EnvVar{Name: "KUBE_NETWORK", Value: kubeNetwork})

	// Determine MTU to use. If specified explicitly, use that. Otherwise, set defaults based on an overall
	// MTU of 1460.
	mtu := getMTU(c.cfg.Installation)
	if mtu != nil {
		vxlanMtu := strconv.Itoa(int(*mtu))
		wireguardMtu := strconv.Itoa(int(*mtu))
		windowsEnv = append(windowsEnv, corev1.EnvVar{Name: "FELIX_VXLANMTU", Value: vxlanMtu})
		windowsEnv = append(windowsEnv, corev1.EnvVar{Name: "FELIX_WIREGUARDMTU", Value: wireguardMtu})
	}

	// If host-local IPAM is in use, we need to configure calico/node to use the Kubernetes pod CIDR.
	cni := c.cfg.Installation.CNI
	if cni != nil && cni.IPAM != nil && cni.IPAM.Type == operatorv1.IPAMPluginHostLocal {
		windowsEnv = append(windowsEnv, corev1.EnvVar{
			Name:  "USE_POD_CIDR",
			Value: "true",
		})
	}

	windowsEnv = append(windowsEnv, corev1.EnvVar{Name: "CALICO_NETWORKING_BACKEND", Value: getWindowsBackend(c.cfg.Installation)})

	// IPv4 auto-detection configuration.
	var v4Method string
	if c.cfg.Installation.CalicoNetwork != nil {
		v4Method = getAutodetectionMethod(c.cfg.Installation.CalicoNetwork.NodeAddressAutodetectionV4)
	}
	if v4Method != "" {
		// IPv4 Auto-detection is enabled.
		windowsEnv = append(windowsEnv, corev1.EnvVar{Name: "IP", Value: "autodetect"})
		windowsEnv = append(windowsEnv, corev1.EnvVar{Name: "IP_AUTODETECTION_METHOD", Value: v4Method})
	} else {
		// IPv4 Auto-detection is disabled.
		windowsEnv = append(windowsEnv, corev1.EnvVar{Name: "IP", Value: "none"})
	}

	// IPv6 auto-detection and ippool configuration.
	var v6Method string
	if c.cfg.Installation.CalicoNetwork != nil {
		v6Method = getAutodetectionMethod(c.cfg.Installation.CalicoNetwork.NodeAddressAutodetectionV6)
	}
	if v6Method != "" {
		// IPv6 Auto-detection is enabled.
		windowsEnv = append(windowsEnv, corev1.EnvVar{Name: "IP6", Value: "autodetect"})
		windowsEnv = append(windowsEnv, corev1.EnvVar{Name: "IP6_AUTODETECTION_METHOD", Value: v6Method})
		windowsEnv = append(windowsEnv, corev1.EnvVar{Name: "FELIX_IPV6SUPPORT", Value: "true"})

		// Set CALICO_ROUTER_ID to "hash" for IPv6-only with BGP enabled.
		if v4Method == "" && bgpEnabled(c.cfg.Installation) {
			windowsEnv = append(windowsEnv, corev1.EnvVar{Name: "CALICO_ROUTER_ID", Value: "hash"})
		}

		// Set IPv6 VXLAN and Wireguard MTU
		if mtu != nil {
			vxlanMtuV6 := strconv.Itoa(int(*mtu))
			wireguardMtuV6 := strconv.Itoa(int(*mtu))
			windowsEnv = append(windowsEnv, corev1.EnvVar{Name: "FELIX_VXLANMTUV6", Value: vxlanMtuV6})
			windowsEnv = append(windowsEnv, corev1.EnvVar{Name: "FELIX_WIREGUARDMTUV6", Value: wireguardMtuV6})
		}
	} else {
		// IPv6 Auto-detection is disabled.
		windowsEnv = append(windowsEnv, corev1.EnvVar{Name: "IP6", Value: "none"})
		windowsEnv = append(windowsEnv, corev1.EnvVar{Name: "FELIX_IPV6SUPPORT", Value: "false"})
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

		if c.cfg.PrometheusServerTLS != nil {
			extraNodeEnv = append(extraNodeEnv,
				corev1.EnvVar{Name: "FELIX_PROMETHEUSREPORTERCERTFILE", Value: c.cfg.PrometheusServerTLS.VolumeMountCertificateFilePath()},
				corev1.EnvVar{Name: "FELIX_PROMETHEUSREPORTERKEYFILE", Value: c.cfg.PrometheusServerTLS.VolumeMountKeyFilePath()},
				corev1.EnvVar{Name: "FELIX_PROMETHEUSREPORTERCAFILE", Value: c.cfg.TLS.TrustedBundle.MountPath()},
			)
		}
		windowsEnv = append(windowsEnv, extraNodeEnv...)
	}

	if c.cfg.Installation.NodeMetricsPort != nil {
		// If a node metrics port was given, then enable felix prometheus metrics and set the port.
		// Note that this takes precedence over any FelixConfiguration resources in the cluster.
		extraNodeEnv := []corev1.EnvVar{
			{Name: "FELIX_PROMETHEUSMETRICSENABLED", Value: "true"},
			{Name: "FELIX_PROMETHEUSMETRICSPORT", Value: fmt.Sprintf("%d", *c.cfg.Installation.NodeMetricsPort)},
		}
		windowsEnv = append(windowsEnv, extraNodeEnv...)
	}

	// Configure provider specific environment variables here.
	switch c.cfg.Installation.KubernetesProvider {
	case operatorv1.ProviderOpenShift:
		if c.cfg.Installation.Variant.IsEnterprise() {
			// We need to configure a non-default trusted DNS server, since there's no kube-dns.
			windowsEnv = append(windowsEnv, corev1.EnvVar{Name: "FELIX_DNSTRUSTEDSERVERS", Value: "k8s-service:openshift-dns/dns-default"})
		}
	case operatorv1.ProviderRKE2:
		// For RKE2, configure a non-default trusted DNS server, as the DNS service is not named "kube-dns".
		if c.cfg.Installation.Variant.IsEnterprise() {
			windowsEnv = append(windowsEnv, corev1.EnvVar{Name: "FELIX_DNSTRUSTEDSERVERS", Value: "k8s-service:kube-system/rke2-coredns-rke2-coredns"})
		}
	}

	if c.cfg.Installation.CNI.Type != operatorv1.PluginCalico {
		windowsEnv = append(windowsEnv, corev1.EnvVar{Name: "FELIX_ROUTESOURCE", Value: "WorkloadIPs"})
	}

	windowsEnv = append(windowsEnv, c.cfg.K8sServiceEp.EnvVars()...)

	return windowsEnv
}

// windowsVolumeMounts creates the windows node's volume mounts.
func (c *windowsComponent) windowsVolumeMounts() []corev1.VolumeMount {
	windowsVolumeMounts := c.cfg.TLS.TrustedBundle.VolumeMounts(c.SupportedOSType())

	windowsVolumeMounts = append(windowsVolumeMounts,
		c.cfg.TLS.NodeSecret.VolumeMount(c.SupportedOSType()),
		corev1.VolumeMount{MountPath: "/var/run/calico", Name: "var-run-calico"},
		corev1.VolumeMount{MountPath: "/var/lib/calico", Name: "var-lib-calico"})

	if c.cfg.Installation.Variant.IsEnterprise() {
		extraNodeMounts := []corev1.VolumeMount{
			{MountPath: "/var/log/calico", Name: "var-log-calico"},
		}
		windowsVolumeMounts = append(windowsVolumeMounts, extraNodeMounts...)
	} else if c.cfg.Installation.CNI.Type == operatorv1.PluginCalico {
		windowsVolumeMounts = append(windowsVolumeMounts, corev1.VolumeMount{MountPath: "/var/log/calico/cni", Name: "cni-log-dir", ReadOnly: false})
	}

	if c.cfg.Installation.CNI.Type == operatorv1.PluginCalico {
		windowsVolumeMounts = append(windowsVolumeMounts, corev1.VolumeMount{MountPath: "/host/etc/cni/net.d", Name: "cni-net-dir"})
	}

	if c.cfg.PrometheusServerTLS != nil {
		windowsVolumeMounts = append(windowsVolumeMounts, c.cfg.PrometheusServerTLS.VolumeMount(c.SupportedOSType()))
	}
	return windowsVolumeMounts
}

// windowsLivenessReadinessProbes creates the node's liveness and readiness probes.
func (c *windowsComponent) windowsLivenessReadinessProbes() (*corev1.Probe, *corev1.Probe) {
	livenessCmd := []string{"$env:CONTAINER_SANDBOX_MOUNT_POINT/CalicoWindows/calico.exe", "component", "node", "health", "--felix-live"}
	readinessCmd := []string{"$env:CONTAINER_SANDBOX_MOUNT_POINT/CalicoWindows/calico.exe", "component", "node", "health", "--felix-ready"}

	lp := &corev1.Probe{
		ProbeHandler:        corev1.ProbeHandler{Exec: &corev1.ExecAction{Command: livenessCmd}},
		InitialDelaySeconds: 10,
		FailureThreshold:    6,
		TimeoutSeconds:      10,
		PeriodSeconds:       10,
	}
	rp := &corev1.Probe{
		ProbeHandler:   corev1.ProbeHandler{Exec: &corev1.ExecAction{Command: readinessCmd}},
		TimeoutSeconds: 10,
		PeriodSeconds:  10,
	}
	return lp, rp
}

// windowsLifecycle creates the node's postStart and preStop hooks.
func (c *windowsComponent) windowsLifecycle() *corev1.Lifecycle {
	return &corev1.Lifecycle{
		PreStop: &corev1.LifecycleHandler{Exec: &corev1.ExecAction{
			Command: []string{"$env:CONTAINER_SANDBOX_MOUNT_POINT/CalicoWindows/calico.exe", "component", "node", "shutdown"},
		}},
	}
}

// nodeWindowsResources creates the windows node's resource requirements.
func (c *windowsComponent) nodeWindowsResources() corev1.ResourceRequirements {
	return rmeta.GetResourceRequirements(c.cfg.Installation, operatorv1.ComponentNameNodeWindows)
}

// felixWindowsResources creates the node's resource requirements.
func (c *windowsComponent) felixWindowsResources() corev1.ResourceRequirements {
	return rmeta.GetResourceRequirements(c.cfg.Installation, operatorv1.ComponentNameFelixWindows)
}

// confdWindowsResources creates the node's resource requirements.
func (c *windowsComponent) confdWindowsResources() corev1.ResourceRequirements {
	return rmeta.GetResourceRequirements(c.cfg.Installation, operatorv1.ComponentNameConfdWindows)
}

// windowsDaemonset creates the windows node daemonset.
func (c *windowsComponent) windowsDaemonset(cniCfgMap *corev1.ConfigMap) *appsv1.DaemonSet {
	var terminationGracePeriod int64 = nodeTerminationGracePeriodSeconds

	// The uninstall-calico initContainer must be the first initContainer
	initContainers := []corev1.Container{c.uninstallContainer()}

	annotations := c.cfg.TLS.TrustedBundle.HashAnnotations()
	if c.cfg.PrometheusServerTLS != nil {
		annotations[c.cfg.PrometheusServerTLS.HashAnnotationKey()] = c.cfg.PrometheusServerTLS.HashAnnotationValue()
	}

	if cniCfgMap != nil {
		annotations[nodeCniConfigAnnotation] = rmeta.AnnotationHash(cniCfgMap.Data)
	}

	// Include annotation for prometheus scraping configuration.
	if c.cfg.Installation.NodeMetricsPort != nil {
		annotations["prometheus.io/scrape"] = "true"
		annotations["prometheus.io/port"] = fmt.Sprintf("%d", *c.cfg.Installation.NodeMetricsPort)
	}

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

	ds := appsv1.DaemonSet{
		TypeMeta: metav1.TypeMeta{Kind: "DaemonSet", APIVersion: "apps/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      common.WindowsDaemonSetName,
			Namespace: common.CalicoNamespace,
		},
		Spec: appsv1.DaemonSetSpec{
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Annotations: annotations,
				},
				Spec: corev1.PodSpec{
					NodeSelector:                  map[string]string{"kubernetes.io/os": "windows"},
					Tolerations:                   rmeta.TolerateAll,
					Affinity:                      affinity,
					ImagePullSecrets:              c.cfg.Installation.ImagePullSecrets,
					ServiceAccountName:            CalicoNodeObjectName,
					TerminationGracePeriodSeconds: &terminationGracePeriod,
					HostNetwork:                   true,
					InitContainers:                initContainers,
					Containers: []corev1.Container{
						c.felixContainer(),
						c.nodeContainer(),
					},
					Volumes: c.windowsVolumes(),
				},
			},
			UpdateStrategy: c.cfg.Installation.NodeUpdateStrategy,
		},
	}

	// Add confd container if BGP is enabled
	if bgpEnabled(c.cfg.Installation) {
		ds.Spec.Template.Spec.Containers = append(ds.Spec.Template.Spec.Containers, c.confdContainer())
	}

	// Only add the CNI initContainer if using Calico CNI
	if c.cfg.Installation.CNI.Type == operatorv1.PluginCalico {
		ds.Spec.Template.Spec.InitContainers = append(ds.Spec.Template.Spec.InitContainers, c.cniContainer())
	}

	SetNodeCriticalPod(&(ds.Spec.Template))

	if overrides := c.cfg.Installation.CalicoNodeWindowsDaemonSet; overrides != nil {
		rcomp.ApplyDaemonSetOverrides(&ds, overrides)
	}

	return &ds
}

func getWindowsBackend(installation *operatorv1.InstallationSpec) string {
	if !bgpEnabled(installation) {
		if installation.CNI.Type == operatorv1.PluginCalico {
			if installation.CNI.IPAM.Type == operatorv1.IPAMPluginHostLocal {
				// If BGP is disabled and using HostLocal, then that means routing is done
				// by Cloud routing, so networking backend is none. (because we don't support
				// vxlan with HostLocal.)
				return "none"
			} else {
				// If BGP is disabled, then set the networking backend to "vxlan". This means that BIRD will be
				// disabled, and VXLAN will optionally be configurable via IP pools.
				return "vxlan"
			}
		} else {
			// If not using Calico networking at all, set the backend to "none".
			return "none"
		}
	} else {
		// BGP is enabled.
		return "windows-bgp"
	}
}

// DefaultWindowsCNIDirectories returns the CNI binary, network config and log directories and the CNI conf filename for the configured platform.
// FIXME: populate with known default for other providers
func DefaultWindowsCNIDirectories(installation operatorv1.InstallationSpec) (string, string, string) {
	var cniBinDir, cniNetDir, cniLogDir string
	switch installation.KubernetesProvider {
	case operatorv1.ProviderAKS:
		cniBinDir = "/k/azurecni/bin"
		cniNetDir = "/k/azurecni/netconf"
		cniLogDir = "/var/log/calico/cni"
	case operatorv1.ProviderEKS:
		cniBinDir = "/Program Files/Amazon/EKS/cni"
		cniNetDir = "/Program Files/Amazon/EKS/cni/config"
		cniLogDir = "/var/log/calico/cni"
	default:
		// Default locations to match vanilla Kubernetes.
		cniBinDir = "/opt/cni/bin"
		cniNetDir = "/etc/cni/net.d"
		cniLogDir = "/var/log/calico/cni"
	}

	return cniBinDir, cniNetDir, cniLogDir
}
