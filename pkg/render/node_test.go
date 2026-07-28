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

package render_test

import (
	"fmt"
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/onsi/gomega/gstruct"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/apis"
	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/components"
	"github.com/tigera/operator/pkg/controller/certificatemanager"
	"github.com/tigera/operator/pkg/controller/k8sapi"
	ctrlrfake "github.com/tigera/operator/pkg/ctrlruntime/client/fake"
	"github.com/tigera/operator/pkg/render"
	rmeta "github.com/tigera/operator/pkg/render/common/meta"
	rtest "github.com/tigera/operator/pkg/render/common/test"
	tls2 "github.com/tigera/operator/pkg/tls"
	"github.com/tigera/operator/pkg/tls/certificatemanagement"
)

var (
	bgpEnabled        = operatorv1.BGPEnabled
	bgpDisabled       = operatorv1.BGPDisabled
	logSeverity       = operatorv1.LogLevelDebug
	logFileMaxAgeDays = uint32(5)
	logFileMaxCount   = uint32(5)
	logFileMaxSize    = resource.MustParse("1Mi")
)

var _ = Describe("Node rendering tests", func() {
	type testConf struct {
		EnableIPv4 bool
		EnableIPv6 bool
	}
	for _, testConfig := range []testConf{
		{true, false},
		{false, true},
		{true, true},
	} {
		enableIPv4 := testConfig.EnableIPv4
		enableIPv6 := testConfig.EnableIPv6
		Describe(fmt.Sprintf("IPv4 enabled: %v, IPv6 enabled: %v", enableIPv4, enableIPv6), func() {
			var defaultInstance *operatorv1.InstallationSpec
			var typhaNodeTLS *render.TyphaNodeTLS
			var k8sServiceEp k8sapi.ServiceEndpoint
			one := intstr.FromInt(1)
			defaultNumExpectedResources := 8
			const defaultClusterDomain = "svc.cluster.local"
			var defaultMode int32 = 420
			var cfg render.NodeConfiguration
			var cli client.Client

			BeforeEach(func() {
				ff := true
				hp := operatorv1.HostPortsEnabled
				miMode := operatorv1.MultiInterfaceModeNone
				defaultInstance = &operatorv1.InstallationSpec{
					CNI: &operatorv1.CNISpec{
						Type: "Calico",
						IPAM: &operatorv1.IPAMSpec{Type: "Calico"},
					},
					CalicoNetwork: &operatorv1.CalicoNetworkSpec{
						BGP:                        &bgpEnabled,
						IPPools:                    []operatorv1.IPPool{},
						NodeAddressAutodetectionV4: &operatorv1.NodeAddressAutodetection{},
						NodeAddressAutodetectionV6: &operatorv1.NodeAddressAutodetection{},
						HostPorts:                  &hp,
						MultiInterfaceMode:         &miMode,
					},
					NodeUpdateStrategy: appsv1.DaemonSetUpdateStrategy{
						RollingUpdate: &appsv1.RollingUpdateDaemonSet{
							MaxUnavailable: &one,
						},
					},
					Logging: &operatorv1.Logging{
						CNI: &operatorv1.CNILogging{
							LogSeverity:       &logSeverity,
							LogFileMaxSize:    &logFileMaxSize,
							LogFileMaxAgeDays: &logFileMaxAgeDays,
							LogFileMaxCount:   &logFileMaxCount,
						},
					},
				}
				if enableIPv4 {
					defaultInstance.CalicoNetwork.IPPools = append(defaultInstance.CalicoNetwork.IPPools, operatorv1.IPPool{CIDR: "192.168.1.0/16"})
					defaultInstance.CalicoNetwork.NodeAddressAutodetectionV4 = &operatorv1.NodeAddressAutodetection{FirstFound: &ff}
				}
				if enableIPv6 {
					defaultInstance.CalicoNetwork.IPPools = append(defaultInstance.CalicoNetwork.IPPools, operatorv1.IPPool{CIDR: "2001:db8:1::/122"})
					defaultInstance.CalicoNetwork.NodeAddressAutodetectionV6 = &operatorv1.NodeAddressAutodetection{FirstFound: &ff}
				}
				scheme := runtime.NewScheme()
				Expect(apis.AddToScheme(scheme, false)).NotTo(HaveOccurred())
				cli = ctrlrfake.DefaultFakeClientBuilder(scheme).Build()

				certificateManager, err := certificatemanager.Create(cli, nil, clusterDomain, common.OperatorNamespace(), certificatemanager.AllowCACreation())
				Expect(err).NotTo(HaveOccurred())

				// Create a dummy secret to pass as input.
				typhaNodeTLS = getTyphaNodeTLS(cli, certificateManager)

				// Dummy service endpoint for k8s API.
				k8sServiceEp = k8sapi.ServiceEndpoint{}

				defaultCNIConfDir, defaultCNIBinDir := render.DefaultCNIDirectories(defaultInstance.KubernetesProvider)
				defaultInstance.CNI.ConfDir, defaultInstance.CNI.BinDir = &defaultCNIConfDir, &defaultCNIBinDir

				// Create a default configuration.
				cfg = render.NodeConfiguration{
					K8sServiceEp:                  k8sServiceEp,
					Installation:                  defaultInstance,
					TLS:                           typhaNodeTLS,
					ClusterDomain:                 defaultClusterDomain,
					FelixHealthPort:               9099,
					IPPools:                       defaultInstance.CalicoNetwork.IPPools,
					FelixPrometheusMetricsEnabled: false,
					FelixPrometheusMetricsPort:    9098,
				}
			})

			It("should render SecurityContextConstrains properly when provider is OpenShift", func() {
				cfg.Installation.KubernetesProvider = operatorv1.ProviderOpenShift
				component := render.Node(&cfg)
				Expect(component.ResolveImages(nil)).To(BeNil())
				resources, _ := component.Objects()

				role := rtest.GetResource(resources, "calico-node", "", "rbac.authorization.k8s.io", "v1", "ClusterRole").(*rbacv1.ClusterRole)
				Expect(role.Rules).To(ContainElement(rbacv1.PolicyRule{
					APIGroups:     []string{"security.openshift.io"},
					Resources:     []string{"securitycontextconstraints"},
					Verbs:         []string{"use"},
					ResourceNames: []string{"privileged"},
				}))
			})

			It("should render all resources for a default configuration", func() {
				expectedResources := []struct {
					name    string
					ns      string
					group   string
					version string
					kind    string
				}{
					{name: "calico-node", ns: common.CalicoNamespace, group: "", version: "v1", kind: "ServiceAccount"},
					{name: "calico-node", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
					{name: "calico-node", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
					{name: "calico-cni-plugin", ns: common.CalicoNamespace, group: "", version: "v1", kind: "ServiceAccount"},
					{name: "calico-cni-plugin", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
					{name: "calico-cni-plugin", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
					{name: "cni-config", ns: common.CalicoNamespace, group: "", version: "v1", kind: "ConfigMap"},
					{name: common.NodeDaemonSetName, ns: common.CalicoNamespace, group: "apps", version: "v1", kind: "DaemonSet"},
				}

				defaultInstance.FlexVolumePath = "/usr/libexec/kubernetes/kubelet-plugins/volume/exec/"
				component := render.Node(&cfg)
				Expect(component.ResolveImages(nil)).To(BeNil())
				resources, _ := component.Objects()
				Expect(len(resources)).To(Equal(len(expectedResources)))

				// Should render the correct resources.
				i := 0
				for _, expectedRes := range expectedResources {
					rtest.ExpectResourceTypeAndObjectMetadata(resources[i], expectedRes.name, expectedRes.ns, expectedRes.group, expectedRes.version, expectedRes.kind)
					i++
				}

				// calico-cni-plugin clusterRole should have kubevirt.io PolicyRule for IPAM of KubeVirt workloads.
				cniRole := rtest.GetResource(resources, "calico-cni-plugin", "", "rbac.authorization.k8s.io", "v1", "ClusterRole").(*rbacv1.ClusterRole)
				Expect(cniRole.Rules).To(ContainElement(rbacv1.PolicyRule{
					APIGroups: []string{"kubevirt.io"},
					Resources: []string{"virtualmachineinstances", "virtualmachines"},
					Verbs:     []string{"get"},
				}))

				// Check CNI configmap.
				cniCmResource := rtest.GetResource(resources, "cni-config", "calico-system", "", "v1", "ConfigMap")
				Expect(cniCmResource).ToNot(BeNil())
				cniCm := cniCmResource.(*corev1.ConfigMap)
				Expect(cniCm.Data["config"]).To(MatchJSON(fmt.Sprintf(`{
  "name": "k8s-pod-network",
  "cniVersion": "1.0.0",
  "plugins": [
    {
      "type": "calico",
			"calico_api_group": "",
      "policy_setup_timeout_seconds": 0,
      "endpoint_status_dir": "/var/run/calico/endpoint-status",
      "datastore_type": "kubernetes",
      "mtu": 0,
      "nodename_file_optional": false,
      "log_level": "Debug",
      "log_file_path": "/var/log/calico/cni/cni.log",
      "log_file_max_size": 1,
      "log_file_max_age": 5,
      "log_file_max_count": 5,
      "ipam": {
          "type": "calico-ipam",
          "assign_ipv4" : "%t",
          "assign_ipv6" : "%t"
      },
      "container_settings": {
          "allow_ip_forwarding": false
      },
      "policy": {
          "type": "k8s"
      },
      "kubernetes": {
          "kubeconfig": "__KUBECONFIG_FILEPATH__"
      }
    },
    {"type": "portmap", "snat": true, "capabilities": {"portMappings": true}}
  ]
}`, enableIPv4, enableIPv6)))

				dsResource := rtest.GetResource(resources, "calico-node", "calico-system", "apps", "v1", "DaemonSet")
				Expect(dsResource).ToNot(BeNil())

				// The DaemonSet should have the correct configuration.
				ds := dsResource.(*appsv1.DaemonSet)

				// The pod template should have node critical priority
				Expect(ds.Spec.Template.Spec.PriorityClassName).To(Equal(render.NodePriorityClassName))

				rtest.ExpectEnv(ds.Spec.Template.Spec.Containers[0].Env, "NO_DEFAULT_POOLS", "true")

				// The pod template should have node critical priority
				Expect(ds.Spec.Template.Spec.PriorityClassName).To(Equal(render.NodePriorityClassName))

				// Node image override results in correct image.
				Expect(ds.Spec.Template.Spec.Containers).To(HaveLen(1))
				Expect(ds.Spec.Template.Spec.Containers[0].Image).To(Equal(fmt.Sprintf("quay.io/%s%s:%s", components.CalicoImagePath, components.ComponentCalicoNode.Image, components.ComponentCalicoNode.Version)))

				Expect(*ds.Spec.Template.Spec.Containers[0].SecurityContext.AllowPrivilegeEscalation).To(BeTrue())
				Expect(*ds.Spec.Template.Spec.Containers[0].SecurityContext.Privileged).To(BeTrue())
				Expect(*ds.Spec.Template.Spec.Containers[0].SecurityContext.RunAsGroup).To(BeEquivalentTo(0))
				Expect(*ds.Spec.Template.Spec.Containers[0].SecurityContext.RunAsNonRoot).To(BeFalse())
				Expect(*ds.Spec.Template.Spec.Containers[0].SecurityContext.RunAsUser).To(BeEquivalentTo(0))
				Expect(ds.Spec.Template.Spec.Containers[0].SecurityContext.Capabilities).To(Equal(
					&corev1.Capabilities{
						Drop: []corev1.Capability{"ALL"},
					},
				))
				Expect(ds.Spec.Template.Spec.Containers[0].SecurityContext.SeccompProfile).To(Equal(
					&corev1.SeccompProfile{
						Type: corev1.SeccompProfileTypeRuntimeDefault,
					}))

				verifyInitContainers(ds, defaultInstance)
				// Verify env
				expectedNodeEnv := []corev1.EnvVar{
					{Name: "DATASTORE_TYPE", Value: "kubernetes"},
					{Name: "WAIT_FOR_DATASTORE", Value: "true"},
					{Name: "CALICO_MANAGE_CNI", Value: "true"},
					{Name: "CALICO_NETWORKING_BACKEND", Value: "bird"},
					{Name: "CALICO_DISABLE_FILE_LOGGING", Value: "false"},
					{Name: "CLUSTER_TYPE", Value: "k8s,operator,bgp"},
					{Name: "FELIX_DEFAULTENDPOINTTOHOSTACTION", Value: "ACCEPT"},
					{Name: "FELIX_HEALTHENABLED", Value: "true"},
					{Name: "FELIX_HEALTHPORT", Value: "9099"},
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
					{Name: "FELIX_TYPHAK8SNAMESPACE", Value: "calico-system"},
					{Name: "FELIX_TYPHAK8SSERVICENAME", Value: "calico-typha"},
					{Name: "FELIX_TYPHACAFILE", Value: certificatemanagement.TrustedCertBundleMountPath},
					{Name: "FELIX_TYPHACERTFILE", Value: "/node-certs/tls.crt"},
					{Name: "FELIX_TYPHACN", Value: "typha-server"},
					{Name: "FELIX_TYPHAKEYFILE", Value: "/node-certs/tls.key"},
					{Name: "NO_DEFAULT_POOLS", Value: "true"},
				}
				expectedNodeEnv = configureExpectedNodeEnvIPVersions(expectedNodeEnv, defaultInstance, enableIPv4, enableIPv6)
				Expect(ds.Spec.Template.Spec.Containers[0].Env).To(ConsistOf(expectedNodeEnv))
				// Expect the SECURITY_GROUP env variables to not be set
				Expect(ds.Spec.Template.Spec.Containers[0].Env).NotTo(ContainElement(gstruct.MatchFields(gstruct.IgnoreExtras, gstruct.Fields{"Name": Equal("TIGERA_DEFAULT_SECURITY_GROUPS")})))
				Expect(ds.Spec.Template.Spec.Containers[0].Env).NotTo(ContainElement(gstruct.MatchFields(gstruct.IgnoreExtras, gstruct.Fields{"Name": Equal("TIGERA_POD_SECURITY_GROUP")})))

				// Verify volumes.
				fileOrCreate := corev1.HostPathFileOrCreate
				dirOrCreate := corev1.HostPathDirectoryOrCreate
				dirMustExist := corev1.HostPathDirectory
				expectedVols := []corev1.Volume{
					{Name: "lib-modules", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/lib/modules"}}},
					{Name: "var-run-calico", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/var/run/calico", Type: &dirOrCreate}}},
					{Name: "var-lib-calico", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/var/lib/calico", Type: &dirOrCreate}}},
					{Name: "xtables-lock", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/run/xtables.lock", Type: &fileOrCreate}}},
					{Name: "cni-bin-dir", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/opt/cni/bin", Type: &dirOrCreate}}},
					{Name: "cni-net-dir", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/etc/cni/net.d"}}},
					{Name: "cni-log-dir", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/var/log/calico/cni"}}},
					{Name: "cni-plugins-stage", VolumeSource: corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{}}},
					{Name: "policysync", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/var/run/nodeagent", Type: &dirOrCreate}}},
					{Name: "sys-fs", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/sys/fs", Type: &dirOrCreate}}},
					{Name: "bpffs", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/sys/fs/bpf", Type: &dirMustExist}}},
					{Name: "sys-kernel-security", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/sys/kernel/security"}}},
					{Name: "nodeproc", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/proc"}}},
					{
						Name: "tigera-ca-bundle",
						VolumeSource: corev1.VolumeSource{
							ConfigMap: &corev1.ConfigMapVolumeSource{
								LocalObjectReference: corev1.LocalObjectReference{
									Name: "tigera-ca-bundle",
								},
							},
						},
					},
					{
						Name: render.NodeTLSSecretName,
						VolumeSource: corev1.VolumeSource{
							Secret: &corev1.SecretVolumeSource{
								SecretName:  render.NodeTLSSecretName,
								DefaultMode: &defaultMode,
							},
						},
					},
					{Name: "flexvol-driver-host", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/usr/libexec/kubernetes/kubelet-plugins/volume/exec/nodeagent~uds", Type: &dirOrCreate}}},
				}
				Expect(ds.Spec.Template.Spec.Volumes).To(ConsistOf(expectedVols))

				// Verify volume mounts.
				expectedNodeVolumeMounts := []corev1.VolumeMount{
					{MountPath: "/lib/modules", Name: "lib-modules", ReadOnly: true},
					{MountPath: "/host/etc/cni/net.d", Name: "cni-net-dir"},
					{MountPath: "/run/xtables.lock", Name: "xtables-lock"},
					{MountPath: "/var/run/calico", Name: "var-run-calico"},
					{MountPath: "/var/lib/calico", Name: "var-lib-calico"},
					{MountPath: "/var/run/nodeagent", Name: "policysync"},
					{MountPath: "/etc/pki/tls/certs", Name: "tigera-ca-bundle", ReadOnly: true},
					{MountPath: "/node-certs", Name: render.NodeTLSSecretName, ReadOnly: true},
					{MountPath: "/var/log/calico/cni", Name: "cni-log-dir", ReadOnly: false},
					{MountPath: "/sys/fs/bpf", Name: "bpffs"},
					{MountPath: "/sys/kernel/security", Name: "sys-kernel-security", ReadOnly: true},
				}
				Expect(ds.Spec.Template.Spec.Containers[0].VolumeMounts).To(ConsistOf(expectedNodeVolumeMounts))

				// Verify tolerations.
				Expect(ds.Spec.Template.Spec.Tolerations).To(ConsistOf(rmeta.TolerateAll))

				verifyProbesAndLifecycle(ds, false, false)
			})

			It("should render node correctly for BPF dataplane", func() {
				expectedResources := []struct {
					name    string
					ns      string
					group   string
					version string
					kind    string
				}{
					{name: "calico-node", ns: common.CalicoNamespace, group: "", version: "v1", kind: "ServiceAccount"},
					{name: "calico-node", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
					{name: "calico-node", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
					{name: "calico-cni-plugin", ns: common.CalicoNamespace, group: "", version: "v1", kind: "ServiceAccount"},
					{name: "calico-cni-plugin", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
					{name: "calico-cni-plugin", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
					{name: "cni-config", ns: common.CalicoNamespace, group: "", version: "v1", kind: "ConfigMap"},
					{name: common.NodeDaemonSetName, ns: common.CalicoNamespace, group: "apps", version: "v1", kind: "DaemonSet"},
				}

				defaultInstance.FlexVolumePath = "/usr/libexec/kubernetes/kubelet-plugins/volume/exec/"
				dpBPF := operatorv1.LinuxDataplaneBPF
				defaultInstance.CalicoNetwork.LinuxDataplane = &dpBPF
				component := render.Node(&cfg)
				Expect(component.ResolveImages(nil)).To(BeNil())
				resources, _ := component.Objects()
				Expect(len(resources)).To(Equal(len(expectedResources)))

				// Should render the correct resources.
				i := 0
				for _, expectedRes := range expectedResources {
					rtest.ExpectResourceTypeAndObjectMetadata(resources[i], expectedRes.name, expectedRes.ns, expectedRes.group, expectedRes.version, expectedRes.kind)
					i++
				}

				cniCmResource := rtest.GetResource(resources, "cni-config", "calico-system", "", "v1", "ConfigMap")
				Expect(cniCmResource).ToNot(BeNil())
				cniCm := cniCmResource.(*corev1.ConfigMap)
				Expect(cniCm.Data["config"]).To(MatchJSON(fmt.Sprintf(`{
  "name": "k8s-pod-network",
  "cniVersion": "1.0.0",
  "plugins": [
    {
      "type": "calico",
      "calico_api_group": "",
      "datastore_type": "kubernetes",
      "mtu": 0,
      "nodename_file_optional": false,
      "log_level": "Debug",
      "log_file_path": "/var/log/calico/cni/cni.log",
      "log_file_max_size": 1,
      "log_file_max_age": 5,
      "log_file_max_count": 5,
      "ipam": {
        "type": "calico-ipam",
        "assign_ipv4": "%t",
        "assign_ipv6": "%t"
      },
      "container_settings": {
        "allow_ip_forwarding": false
      },
      "policy": {
        "type": "k8s"
      },
      "policy_setup_timeout_seconds": 0,
      "endpoint_status_dir": "/var/run/calico/endpoint-status",
      "kubernetes": {
        "kubeconfig": "__KUBECONFIG_FILEPATH__"
      }
    },
    {
      "type": "portmap",
      "snat": true,
      "capabilities": {
        "portMappings": true
      }
    }
  ]
}`, enableIPv4, enableIPv6)))

				dsResource := rtest.GetResource(resources, "calico-node", "calico-system", "apps", "v1", "DaemonSet")
				Expect(dsResource).ToNot(BeNil())

				// The DaemonSet should have the correct configuration.
				ds := dsResource.(*appsv1.DaemonSet)

				// The pod template should have node critical priority
				Expect(ds.Spec.Template.Spec.PriorityClassName).To(Equal(render.NodePriorityClassName))

				rtest.ExpectEnv(ds.Spec.Template.Spec.Containers[0].Env, "NO_DEFAULT_POOLS", "true")

				// Node image override results in correct image.
				calicoNodeImage := fmt.Sprintf("quay.io/%s%s:%s", components.CalicoImagePath, components.ComponentCalicoNode.Image, components.ComponentCalicoNode.Version)
				Expect(ds.Spec.Template.Spec.Containers[0].Image).To(Equal(calicoNodeImage))

				verifyInitContainers(ds, defaultInstance)
				// Verify env
				expectedNodeEnv := []corev1.EnvVar{
					{Name: "DATASTORE_TYPE", Value: "kubernetes"},
					{Name: "WAIT_FOR_DATASTORE", Value: "true"},
					{Name: "CALICO_NETWORKING_BACKEND", Value: "bird"},
					{Name: "CALICO_MANAGE_CNI", Value: "true"},
					{Name: "CALICO_DISABLE_FILE_LOGGING", Value: "false"},
					{Name: "CLUSTER_TYPE", Value: "k8s,operator,bgp"},
					{Name: "FELIX_DEFAULTENDPOINTTOHOSTACTION", Value: "ACCEPT"},
					{Name: "FELIX_HEALTHENABLED", Value: "true"},
					{Name: "FELIX_HEALTHPORT", Value: "9099"},
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
					{Name: "FELIX_TYPHAK8SNAMESPACE", Value: "calico-system"},
					{Name: "FELIX_TYPHAK8SSERVICENAME", Value: "calico-typha"},
					{Name: "FELIX_TYPHACAFILE", Value: certificatemanagement.TrustedCertBundleMountPath},
					{Name: "FELIX_TYPHACERTFILE", Value: "/node-certs/tls.crt"},
					{Name: "FELIX_TYPHACN", Value: "typha-server"},
					{Name: "FELIX_TYPHAKEYFILE", Value: "/node-certs/tls.key"},
					{Name: "NO_DEFAULT_POOLS", Value: "true"},
				}
				expectedNodeEnv = configureExpectedNodeEnvIPVersions(expectedNodeEnv, defaultInstance, enableIPv4, enableIPv6)
				Expect(ds.Spec.Template.Spec.Containers[0].Env).To(ConsistOf(expectedNodeEnv))
				// Expect the SECURITY_GROUP env variables to not be set
				Expect(ds.Spec.Template.Spec.Containers[0].Env).NotTo(ContainElement(gstruct.MatchFields(gstruct.IgnoreExtras, gstruct.Fields{"Name": Equal("TIGERA_DEFAULT_SECURITY_GROUPS")})))
				Expect(ds.Spec.Template.Spec.Containers[0].Env).NotTo(ContainElement(gstruct.MatchFields(gstruct.IgnoreExtras, gstruct.Fields{"Name": Equal("TIGERA_POD_SECURITY_GROUP")})))

				// Verify volumes.
				fileOrCreate := corev1.HostPathFileOrCreate
				dirOrCreate := corev1.HostPathDirectoryOrCreate
				dirMustExist := corev1.HostPathDirectory
				expectedVols := []corev1.Volume{
					{Name: "lib-modules", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/lib/modules"}}},
					{Name: "var-run-calico", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/var/run/calico", Type: &dirOrCreate}}},
					{Name: "var-lib-calico", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/var/lib/calico", Type: &dirOrCreate}}},
					{Name: "xtables-lock", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/run/xtables.lock", Type: &fileOrCreate}}},
					{Name: "cni-bin-dir", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/opt/cni/bin", Type: &dirOrCreate}}},
					{Name: "cni-net-dir", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/etc/cni/net.d"}}},
					{Name: "cni-log-dir", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/var/log/calico/cni"}}},
					{Name: "cni-plugins-stage", VolumeSource: corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{}}},
					{Name: "sys-fs", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/sys/fs", Type: &dirOrCreate}}},
					{Name: "bpffs", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/sys/fs/bpf", Type: &dirMustExist}}},
					{Name: "sys-kernel-security", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/sys/kernel/security"}}},
					{Name: "nodeproc", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/proc"}}},
					{Name: "policysync", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/var/run/nodeagent", Type: &dirOrCreate}}},
					{
						Name: "tigera-ca-bundle",
						VolumeSource: corev1.VolumeSource{
							ConfigMap: &corev1.ConfigMapVolumeSource{
								LocalObjectReference: corev1.LocalObjectReference{
									Name: "tigera-ca-bundle",
								},
							},
						},
					},
					{
						Name: render.NodeTLSSecretName,
						VolumeSource: corev1.VolumeSource{
							Secret: &corev1.SecretVolumeSource{
								SecretName:  render.NodeTLSSecretName,
								DefaultMode: &defaultMode,
							},
						},
					},
					{Name: "flexvol-driver-host", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/usr/libexec/kubernetes/kubelet-plugins/volume/exec/nodeagent~uds", Type: &dirOrCreate}}},
				}
				Expect(ds.Spec.Template.Spec.Volumes).To(ConsistOf(expectedVols))

				// Verify volume mounts.
				expectedNodeVolumeMounts := []corev1.VolumeMount{
					{MountPath: "/lib/modules", Name: "lib-modules", ReadOnly: true},
					{MountPath: "/host/etc/cni/net.d", Name: "cni-net-dir"},
					{MountPath: "/run/xtables.lock", Name: "xtables-lock"},
					{MountPath: "/var/run/calico", Name: "var-run-calico"},
					{MountPath: "/var/lib/calico", Name: "var-lib-calico"},
					{MountPath: "/var/run/nodeagent", Name: "policysync"},
					{MountPath: "/etc/pki/tls/certs", Name: "tigera-ca-bundle", ReadOnly: true},
					{MountPath: "/node-certs", Name: render.NodeTLSSecretName, ReadOnly: true},
					{MountPath: "/var/log/calico/cni", Name: "cni-log-dir", ReadOnly: false},
					{MountPath: "/sys/fs/bpf", Name: "bpffs"},
					{MountPath: "/sys/kernel/security", Name: "sys-kernel-security", ReadOnly: true},
				}
				Expect(ds.Spec.Template.Spec.Containers[0].VolumeMounts).To(ConsistOf(expectedNodeVolumeMounts))

				// Verify tolerations.
				Expect(ds.Spec.Template.Spec.Tolerations).To(ConsistOf(rmeta.TolerateAll))

				verifyProbesAndLifecycle(ds, false, false)
			})

			It("should render a pinned CNI spec version in the CNI config", func() {
				pinned := operatorv1.CNISpecVersion031
				defaultInstance.CNI.SpecVersion = &pinned

				component := render.Node(&cfg)
				Expect(component.ResolveImages(nil)).To(BeNil())
				resources, _ := component.Objects()

				cniCmResource := rtest.GetResource(resources, "cni-config", "calico-system", "", "v1", "ConfigMap")
				Expect(cniCmResource).ToNot(BeNil())
				cniCm := cniCmResource.(*corev1.ConfigMap)
				Expect(cniCm.Data["config"]).To(ContainSubstring(`"cniVersion": "0.3.1"`))
			})

			It("should render the Auto CNI spec version as 1.0.0", func() {
				auto := operatorv1.CNISpecVersionAuto
				defaultInstance.CNI.SpecVersion = &auto

				component := render.Node(&cfg)
				Expect(component.ResolveImages(nil)).To(BeNil())
				resources, _ := component.Objects()

				cniCmResource := rtest.GetResource(resources, "cni-config", "calico-system", "", "v1", "ConfigMap")
				Expect(cniCmResource).ToNot(BeNil())
				cniCm := cniCmResource.(*corev1.ConfigMap)
				Expect(cniCm.Data["config"]).To(ContainSubstring(`"cniVersion": "1.0.0"`))
			})

			It("should properly render an explicitly configured MTU", func() {
				mtu := int32(1450)
				defaultInstance.FlexVolumePath = "/usr/libexec/kubernetes/kubelet-plugins/volume/exec/"
				defaultInstance.CalicoNetwork.MTU = &mtu

				component := render.Node(&cfg)
				Expect(component.ResolveImages(nil)).To(BeNil())
				resources, _ := component.Objects()

				// Make sure the configmap is populated correctly with the MTU.
				cniCmResource := rtest.GetResource(resources, "cni-config", "calico-system", "", "v1", "ConfigMap")
				Expect(cniCmResource).ToNot(BeNil())
				cniCm := cniCmResource.(*corev1.ConfigMap)
				Expect(cniCm.Data["config"]).To(MatchJSON(fmt.Sprintf(`{
  "name": "k8s-pod-network",
  "cniVersion": "1.0.0",
  "plugins": [
    {
      "type": "calico",
      "calico_api_group": "",
      "datastore_type": "kubernetes",
      "mtu": 1450,
      "nodename_file_optional": false,
      "log_level": "Debug",
      "log_file_path": "/var/log/calico/cni/cni.log",
      "log_file_max_size": 1,
      "log_file_max_age": 5,
      "log_file_max_count": 5,
      "ipam": {
          "type": "calico-ipam",
          "assign_ipv4" : "%t",
          "assign_ipv6" : "%t"
      },
      "container_settings": {
          "allow_ip_forwarding": false
      },
      "policy": {
          "type": "k8s"
      },
      "policy_setup_timeout_seconds": 0,
      "endpoint_status_dir": "/var/run/calico/endpoint-status",
      "kubernetes": {
          "kubeconfig": "__KUBECONFIG_FILEPATH__"
      }
    },
    {"type": "portmap", "snat": true, "capabilities": {"portMappings": true}}
  ]
}`, enableIPv4, enableIPv6)))

				// Make sure daemonset has the MTU set as well.
				dsResource := rtest.GetResource(resources, "calico-node", "calico-system", "apps", "v1", "DaemonSet")
				Expect(dsResource).ToNot(BeNil())
				ds := dsResource.(*appsv1.DaemonSet)

				// Verify env
				expectedNodeEnv := []corev1.EnvVar{
					{Name: "NO_DEFAULT_POOLS", Value: "true"},
				}
				if enableIPv4 {
					expectedNodeEnv = append(expectedNodeEnv, []corev1.EnvVar{
						{Name: "FELIX_IPINIPMTU", Value: "1450"},
						{Name: "FELIX_VXLANMTU", Value: "1450"},
						{Name: "FELIX_WIREGUARDMTU", Value: "1450"},
					}...)
				}
				if enableIPv6 {
					expectedNodeEnv = append(expectedNodeEnv, []corev1.EnvVar{
						{Name: "FELIX_VXLANMTUV6", Value: "1450"},
						{Name: "FELIX_WIREGUARDMTUV6", Value: "1450"},
					}...)
				}
				for _, e := range expectedNodeEnv {
					Expect(ds.Spec.Template.Spec.Containers[0].Env).To(ContainElement(e))
				}
			})

			It("should render all resources for a default configuration using CalicoEnterprise", func() {
				expectedResources := []struct {
					name    string
					ns      string
					group   string
					version string
					kind    string
				}{
					{name: "calico-node", ns: common.CalicoNamespace, group: "", version: "v1", kind: "ServiceAccount"},
					{name: "calico-node", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
					{name: "calico-node", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
					{name: "calico-cni-plugin", ns: common.CalicoNamespace, group: "", version: "v1", kind: "ServiceAccount"},
					{name: "calico-cni-plugin", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
					{name: "calico-cni-plugin", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
					{name: "calico-node-metrics", ns: "calico-system", group: "", version: "v1", kind: "Service"},
					{name: "cni-config", ns: common.CalicoNamespace, group: "", version: "v1", kind: "ConfigMap"},
					{name: common.NodeDaemonSetName, ns: common.CalicoNamespace, group: "apps", version: "v1", kind: "DaemonSet"},
				}
				defaultInstance.Variant = operatorv1.CalicoEnterprise
				cfg.NodeReporterMetricsPort = 9081

				component := render.Node(&cfg)
				Expect(component.ResolveImages(nil)).To(BeNil())
				resources, _ := component.Objects()
				Expect(len(resources)).To(Equal(len(expectedResources)))

				// Should render the correct resources.
				i := 0
				for _, expectedRes := range expectedResources {
					rtest.ExpectResourceTypeAndObjectMetadata(resources[i], expectedRes.name, expectedRes.ns, expectedRes.group, expectedRes.version, expectedRes.kind)
					i++
				}

				// The DaemonSet should have the correct configuration.
				ds := rtest.GetResource(resources, "calico-node", "calico-system", "apps", "v1", "DaemonSet").(*appsv1.DaemonSet)

				// The pod template should have node critical priority
				Expect(ds.Spec.Template.Spec.PriorityClassName).To(Equal(render.NodePriorityClassName))
				Expect(ds.Spec.Template.Spec.Containers[0].Image).To(Equal(components.TigeraRegistry + "tigera/node:" + components.ComponentTigeraNode.Version))
				verifyInitContainers(ds, defaultInstance)

				expectedNodeEnv := []corev1.EnvVar{
					// Default envvars.
					{Name: "DATASTORE_TYPE", Value: "kubernetes"},
					{Name: "WAIT_FOR_DATASTORE", Value: "true"},
					{Name: "CALICO_MANAGE_CNI", Value: "true"},
					{Name: "CALICO_NETWORKING_BACKEND", Value: "bird"},
					{Name: "CLUSTER_TYPE", Value: "k8s,operator,bgp"},
					{Name: "CALICO_DISABLE_FILE_LOGGING", Value: "false"},
					{Name: "FELIX_DEFAULTENDPOINTTOHOSTACTION", Value: "ACCEPT"},
					{Name: "FELIX_HEALTHENABLED", Value: "true"},
					{Name: "FELIX_HEALTHPORT", Value: "9099"},
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
					{Name: "FELIX_TYPHAK8SNAMESPACE", Value: "calico-system"},
					{Name: "FELIX_TYPHAK8SSERVICENAME", Value: "calico-typha"},
					{Name: "FELIX_TYPHACAFILE", Value: certificatemanagement.TrustedCertBundleMountPath},
					{Name: "FELIX_TYPHACERTFILE", Value: "/node-certs/tls.crt"},
					{Name: "FELIX_TYPHACN", Value: "typha-server"},
					{Name: "FELIX_TYPHAKEYFILE", Value: "/node-certs/tls.key"},
					// Tigera-specific envvars
					{Name: "FELIX_PROMETHEUSREPORTERENABLED", Value: "true"},
					{Name: "FELIX_PROMETHEUSREPORTERPORT", Value: "9081"},
					{Name: "FELIX_FLOWLOGSFILEENABLED", Value: "true"},
					{Name: "FELIX_FLOWLOGSFILEINCLUDELABELS", Value: "true"},
					{Name: "FELIX_FLOWLOGSFILEINCLUDEPOLICIES", Value: "true"},
					{Name: "FELIX_FLOWLOGSFILEINCLUDESERVICE", Value: "true"},
					{Name: "FELIX_FLOWLOGSENABLENETWORKSETS", Value: "true"},
					{Name: "FELIX_FLOWLOGSCOLLECTPROCESSINFO", Value: "true"},
					{Name: "FELIX_DNSLOGSFILEENABLED", Value: "true"},
					{Name: "FELIX_DNSLOGSFILEPERNODELIMIT", Value: "1000"},
					{Name: "MULTI_INTERFACE_MODE", Value: operatorv1.MultiInterfaceModeNone.Value()},
					{Name: "NO_DEFAULT_POOLS", Value: "true"},
				}
				expectedNodeEnv = configureExpectedNodeEnvIPVersions(expectedNodeEnv, defaultInstance, enableIPv4, enableIPv6)
				Expect(ds.Spec.Template.Spec.Containers[0].Env).To(ConsistOf(expectedNodeEnv))
				Expect(len(ds.Spec.Template.Spec.Containers[0].Env)).To(Equal(len(expectedNodeEnv)))

				// Expect 2 Ports when FelixPrometheusMetricsEnabled is false
				ms := rtest.GetResource(resources, "calico-node-metrics", "calico-system", "", "v1", "Service").(*corev1.Service)
				Expect(len(ms.Spec.Ports)).To(Equal(2))

				dirMustExist := corev1.HostPathDirectory
				bpfVol := corev1.Volume{Name: "bpffs", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/sys/fs/bpf", Type: &dirMustExist}}}
				Expect(ds.Spec.Template.Spec.Volumes).To(ContainElement(bpfVol))

				bpfVolMount := corev1.VolumeMount{MountPath: "/sys/fs/bpf", Name: "bpffs"}
				Expect(ds.Spec.Template.Spec.Containers[0].VolumeMounts).To(ContainElement(bpfVolMount))

				verifyProbesAndLifecycle(ds, false, true)
			})

			It("should render felix service metric with FelixPrometheusMetricPort when FelixPrometheusMetricsEnabled is true", func() {
				defaultInstance.Variant = operatorv1.CalicoEnterprise
				cfg.NodeReporterMetricsPort = 9081
				cfg.FelixPrometheusMetricsEnabled = true

				component := render.Node(&cfg)
				Expect(component.ResolveImages(nil)).To(BeNil())
				resources, _ := component.Objects()

				expectedServicePorts := []corev1.ServicePort{
					{
						Name:       "calico-metrics-port",
						Port:       int32(cfg.NodeReporterMetricsPort),
						TargetPort: intstr.FromInt(cfg.NodeReporterMetricsPort),
						Protocol:   corev1.ProtocolTCP,
					},
					{
						Name:       "calico-bgp-metrics-port",
						Port:       9900,
						TargetPort: intstr.FromInt(int(9900)),
						Protocol:   corev1.ProtocolTCP,
					},
					{
						Name:       "felix-metrics-port",
						Port:       9098,
						TargetPort: intstr.FromInt(int(9098)),
						Protocol:   corev1.ProtocolTCP,
					},
				}

				// Expect 3 Ports when FelixPrometheusMetricsEnabled is true
				ms := rtest.GetResource(resources, "calico-node-metrics", "calico-system", "", "v1", "Service").(*corev1.Service)
				Expect(ms.Spec.Ports).To(Equal(expectedServicePorts))
			})

			It("should render all resources when using Calico CNI on EKS", func() {
				expectedResources := []struct {
					name    string
					ns      string
					group   string
					version string
					kind    string
				}{
					{name: "calico-node", ns: common.CalicoNamespace, group: "", version: "v1", kind: "ServiceAccount"},
					{name: "calico-node", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
					{name: "calico-node", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
					{name: "calico-cni-plugin", ns: common.CalicoNamespace, group: "", version: "v1", kind: "ServiceAccount"},
					{name: "calico-cni-plugin", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
					{name: "calico-cni-plugin", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
					{name: "cni-config", ns: common.CalicoNamespace, group: "", version: "v1", kind: "ConfigMap"},
					{name: common.NodeDaemonSetName, ns: common.CalicoNamespace, group: "apps", version: "v1", kind: "DaemonSet"},
				}

				defaultInstance.FlexVolumePath = "/usr/libexec/kubernetes/kubelet-plugins/volume/exec/"
				defaultInstance.KubernetesProvider = operatorv1.ProviderEKS
				defaultInstance.CalicoNetwork.BGP = &bgpDisabled
				defaultInstance.CalicoNetwork.IPPools[0].Encapsulation = operatorv1.EncapsulationVXLAN
				cfg.IPPools = defaultInstance.CalicoNetwork.IPPools
				component := render.Node(&cfg)
				Expect(component.ResolveImages(nil)).To(BeNil())
				resources, _ := component.Objects()
				Expect(len(resources)).To(Equal(len(expectedResources)))

				// Should render the correct resources.
				i := 0
				for _, expectedRes := range expectedResources {
					rtest.ExpectResourceTypeAndObjectMetadata(resources[i], expectedRes.name, expectedRes.ns, expectedRes.group, expectedRes.version, expectedRes.kind)
					i++
				}

				cniCmResource := rtest.GetResource(resources, "cni-config", "calico-system", "", "v1", "ConfigMap")
				Expect(cniCmResource).ToNot(BeNil())
				cniCm := cniCmResource.(*corev1.ConfigMap)
				Expect(cniCm.Data["config"]).To(MatchJSON(fmt.Sprintf(`{
  "name": "k8s-pod-network",
  "cniVersion": "1.0.0",
  "plugins": [
    {
      "type": "calico",
      "calico_api_group": "",
      "datastore_type": "kubernetes",
      "mtu": 0,
      "nodename_file_optional": false,
      "log_level": "Debug",
      "log_file_path": "/var/log/calico/cni/cni.log",
      "log_file_max_size": 1,
      "log_file_max_age": 5,
      "log_file_max_count": 5,
      "ipam": {
          "type": "calico-ipam",
          "assign_ipv4" : "%t",
          "assign_ipv6" : "%t"
      },
      "container_settings": {
          "allow_ip_forwarding": false
      },
      "policy": {
          "type": "k8s"
      },
      "policy_setup_timeout_seconds": 0,
      "endpoint_status_dir": "/var/run/calico/endpoint-status",
      "kubernetes": {
          "kubeconfig": "__KUBECONFIG_FILEPATH__"
      }
    },
    {"type": "portmap", "snat": true, "capabilities": {"portMappings": true}}
  ]
}`, enableIPv4, enableIPv6)))

				dsResource := rtest.GetResource(resources, "calico-node", "calico-system", "apps", "v1", "DaemonSet")
				Expect(dsResource).ToNot(BeNil())

				// The DaemonSet should have the correct configuration.
				ds := dsResource.(*appsv1.DaemonSet)

				// The pod template should have node critical priority
				Expect(ds.Spec.Template.Spec.PriorityClassName).To(Equal(render.NodePriorityClassName))

				rtest.ExpectEnv(ds.Spec.Template.Spec.Containers[0].Env, "NO_DEFAULT_POOLS", "true")

				// Node image override results in correct image.
				Expect(ds.Spec.Template.Spec.Containers[0].Image).To(Equal(fmt.Sprintf("quay.io/%s%s:%s", components.CalicoImagePath, components.ComponentCalicoNode.Image, components.ComponentCalicoNode.Version)))

				verifyInitContainers(ds, defaultInstance)
				// Verify env
				expectedNodeEnv := []corev1.EnvVar{
					{Name: "DATASTORE_TYPE", Value: "kubernetes"},
					{Name: "WAIT_FOR_DATASTORE", Value: "true"},
					{Name: "CALICO_MANAGE_CNI", Value: "true"},
					{Name: "CALICO_NETWORKING_BACKEND", Value: "vxlan"},
					{Name: "CALICO_DISABLE_FILE_LOGGING", Value: "false"},
					{Name: "CLUSTER_TYPE", Value: "k8s,operator,ecs"},
					{Name: "FELIX_DEFAULTENDPOINTTOHOSTACTION", Value: "ACCEPT"},
					{Name: "FELIX_HEALTHENABLED", Value: "true"},
					{Name: "FELIX_HEALTHPORT", Value: "9099"},
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
					{Name: "FELIX_TYPHAK8SNAMESPACE", Value: "calico-system"},
					{Name: "FELIX_TYPHAK8SSERVICENAME", Value: "calico-typha"},
					{Name: "FELIX_TYPHACAFILE", Value: certificatemanagement.TrustedCertBundleMountPath},
					{Name: "FELIX_TYPHACERTFILE", Value: "/node-certs/tls.crt"},
					{Name: "FELIX_TYPHACN", Value: "typha-server"},
					{Name: "FELIX_TYPHAKEYFILE", Value: "/node-certs/tls.key"},
					{Name: "NO_DEFAULT_POOLS", Value: "true"},
				}
				expectedNodeEnv = configureExpectedNodeEnvIPVersions(expectedNodeEnv, defaultInstance, enableIPv4, enableIPv6)
				Expect(ds.Spec.Template.Spec.Containers[0].Env).To(ConsistOf(expectedNodeEnv))
				// Expect the SECURITY_GROUP env variables to not be set
				Expect(ds.Spec.Template.Spec.Containers[0].Env).NotTo(ContainElement(gstruct.MatchFields(gstruct.IgnoreExtras, gstruct.Fields{"Name": Equal("TIGERA_DEFAULT_SECURITY_GROUPS")})))
				Expect(ds.Spec.Template.Spec.Containers[0].Env).NotTo(ContainElement(gstruct.MatchFields(gstruct.IgnoreExtras, gstruct.Fields{"Name": Equal("TIGERA_POD_SECURITY_GROUP")})))

				// Verify volumes.
				fileOrCreate := corev1.HostPathFileOrCreate
				dirOrCreate := corev1.HostPathDirectoryOrCreate
				dirMustExist := corev1.HostPathDirectory
				expectedVols := []corev1.Volume{
					{Name: "lib-modules", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/lib/modules"}}},
					{Name: "var-run-calico", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/var/run/calico", Type: &dirOrCreate}}},
					{Name: "var-lib-calico", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/var/lib/calico", Type: &dirOrCreate}}},
					{Name: "xtables-lock", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/run/xtables.lock", Type: &fileOrCreate}}},
					{Name: "cni-bin-dir", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/opt/cni/bin", Type: &dirOrCreate}}},
					{Name: "cni-net-dir", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/etc/cni/net.d"}}},
					{Name: "cni-log-dir", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/var/log/calico/cni"}}},
					{Name: "cni-plugins-stage", VolumeSource: corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{}}},
					{Name: "policysync", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/var/run/nodeagent", Type: &dirOrCreate}}},
					{Name: "sys-fs", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/sys/fs", Type: &dirOrCreate}}},
					{Name: "bpffs", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/sys/fs/bpf", Type: &dirMustExist}}},
					{Name: "sys-kernel-security", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/sys/kernel/security"}}},
					{Name: "nodeproc", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/proc"}}},
					{
						Name: "tigera-ca-bundle",
						VolumeSource: corev1.VolumeSource{
							ConfigMap: &corev1.ConfigMapVolumeSource{
								LocalObjectReference: corev1.LocalObjectReference{
									Name: "tigera-ca-bundle",
								},
							},
						},
					},
					{
						Name: render.NodeTLSSecretName,
						VolumeSource: corev1.VolumeSource{
							Secret: &corev1.SecretVolumeSource{
								SecretName:  render.NodeTLSSecretName,
								DefaultMode: &defaultMode,
							},
						},
					},
					{Name: "flexvol-driver-host", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/usr/libexec/kubernetes/kubelet-plugins/volume/exec/nodeagent~uds", Type: &dirOrCreate}}},
				}
				Expect(ds.Spec.Template.Spec.Volumes).To(ConsistOf(expectedVols))

				// Verify volume mounts.
				expectedNodeVolumeMounts := []corev1.VolumeMount{
					{MountPath: "/lib/modules", Name: "lib-modules", ReadOnly: true},
					{MountPath: "/host/etc/cni/net.d", Name: "cni-net-dir"},
					{MountPath: "/run/xtables.lock", Name: "xtables-lock"},
					{MountPath: "/var/run/calico", Name: "var-run-calico"},
					{MountPath: "/var/lib/calico", Name: "var-lib-calico"},
					{MountPath: "/var/run/nodeagent", Name: "policysync"},
					{MountPath: "/etc/pki/tls/certs", Name: "tigera-ca-bundle", ReadOnly: true},
					{MountPath: "/node-certs", Name: render.NodeTLSSecretName, ReadOnly: true},
					{MountPath: "/var/log/calico/cni", Name: "cni-log-dir", ReadOnly: false},
					{MountPath: "/sys/fs/bpf", Name: "bpffs"},
					{MountPath: "/sys/kernel/security", Name: "sys-kernel-security", ReadOnly: true},
				}
				Expect(ds.Spec.Template.Spec.Containers[0].VolumeMounts).To(ConsistOf(expectedNodeVolumeMounts))

				// Verify tolerations.
				Expect(ds.Spec.Template.Spec.Tolerations).To(ConsistOf(rmeta.TolerateAll))

				// Verify readiness and liveness probes.

				verifyProbesAndLifecycle(ds, false, false)
			})

			It("should properly render a configuration using the AmazonVPC CNI plugin", func() {
				// Override the installation with one configured for AmazonVPC CNI.
				amazonVPCInstalllation := &operatorv1.InstallationSpec{
					KubernetesProvider: operatorv1.ProviderEKS,
					CNI:                &operatorv1.CNISpec{Type: operatorv1.PluginAmazonVPC},
					FlexVolumePath:     "/usr/libexec/kubernetes/kubelet-plugins/volume/exec/",
				}
				cfg.Installation = amazonVPCInstalllation

				component := render.Node(&cfg)
				Expect(component.ResolveImages(nil)).To(BeNil())
				resources, _ := component.Objects()
				Expect(len(resources)).To(Equal(defaultNumExpectedResources - 1))

				// Should render the correct resources.
				Expect(rtest.GetResource(resources, "calico-node", "calico-system", "", "v1", "ServiceAccount")).ToNot(BeNil())
				Expect(rtest.GetResource(resources, "calico-node", "", "rbac.authorization.k8s.io", "v1", "ClusterRole")).ToNot(BeNil())
				Expect(rtest.GetResource(resources, "calico-node", "", "rbac.authorization.k8s.io", "v1", "ClusterRoleBinding")).ToNot(BeNil())
				Expect(rtest.GetResource(resources, "calico-node", "calico-system", "apps", "v1", "DaemonSet")).ToNot(BeNil())
				dsResource := rtest.GetResource(resources, "calico-node", "calico-system", "apps", "v1", "DaemonSet")
				Expect(dsResource).ToNot(BeNil())

				// Should not render CNI configuration.
				cniCmResource := rtest.GetResource(resources, "cni-config", "calico-system", "", "v1", "ConfigMap")
				Expect(cniCmResource).To(BeNil())

				// The DaemonSet should have the correct configuration.
				ds := dsResource.(*appsv1.DaemonSet)

				// The pod template should have node critical priority
				Expect(ds.Spec.Template.Spec.PriorityClassName).To(Equal(render.NodePriorityClassName))

				verifyInitContainers(ds, amazonVPCInstalllation)
				// Verify env
				expectedNodeEnv := []corev1.EnvVar{
					{Name: "DATASTORE_TYPE", Value: "kubernetes"},
					{Name: "WAIT_FOR_DATASTORE", Value: "true"},
					{Name: "CALICO_NETWORKING_BACKEND", Value: "none"},
					{Name: "CALICO_DISABLE_FILE_LOGGING", Value: "false"},
					{Name: "CLUSTER_TYPE", Value: "k8s,operator,ecs"},
					{Name: "IP", Value: "none"},
					{Name: "IP6", Value: "none"},
					{Name: "NO_DEFAULT_POOLS", Value: "true"},
					{Name: "CALICO_MANAGE_CNI", Value: "false"},
					{Name: "FELIX_DEFAULTENDPOINTTOHOSTACTION", Value: "ACCEPT"},
					{Name: "FELIX_IPV6SUPPORT", Value: "false"},
					{Name: "FELIX_HEALTHENABLED", Value: "true"},
					{Name: "FELIX_HEALTHPORT", Value: "9099"},
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
					{Name: "FELIX_TYPHAK8SNAMESPACE", Value: "calico-system"},
					{Name: "FELIX_TYPHAK8SSERVICENAME", Value: "calico-typha"},
					{Name: "FELIX_TYPHACAFILE", Value: certificatemanagement.TrustedCertBundleMountPath},
					{Name: "FELIX_TYPHACERTFILE", Value: "/node-certs/tls.crt"},
					{Name: "FELIX_TYPHACN", Value: "typha-server"},
					{Name: "FELIX_TYPHAKEYFILE", Value: "/node-certs/tls.key"},
					{Name: "FELIX_INTERFACEPREFIX", Value: "eni"},
					{Name: "FELIX_IPTABLESMANGLEALLOWACTION", Value: "Return"},
					{Name: "FELIX_ROUTESOURCE", Value: "WorkloadIPs"},
					{Name: "FELIX_BPFEXTTOSERVICECONNMARK", Value: "0x80"},
					{Name: "FELIX_WIREGUARDHOSTENCRYPTIONENABLED", Value: "true"},
				}
				Expect(ds.Spec.Template.Spec.Containers[0].Env).To(ConsistOf(expectedNodeEnv))

				// Expect the SECURITY_GROUP env variables to not be set
				Expect(ds.Spec.Template.Spec.Containers[0].Env).NotTo(ContainElement(gstruct.MatchFields(gstruct.IgnoreExtras, gstruct.Fields{"Name": Equal("TIGERA_DEFAULT_SECURITY_GROUPS")})))
				Expect(ds.Spec.Template.Spec.Containers[0].Env).NotTo(ContainElement(gstruct.MatchFields(gstruct.IgnoreExtras, gstruct.Fields{"Name": Equal("TIGERA_POD_SECURITY_GROUP")})))

				// Verify volumes.
				fileOrCreate := corev1.HostPathFileOrCreate
				dirOrCreate := corev1.HostPathDirectoryOrCreate
				dirMustExist := corev1.HostPathDirectory
				expectedVols := []corev1.Volume{
					{Name: "lib-modules", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/lib/modules"}}},
					{Name: "var-run-calico", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/var/run/calico", Type: &dirOrCreate}}},
					{Name: "var-lib-calico", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/var/lib/calico", Type: &dirOrCreate}}},
					{Name: "xtables-lock", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/run/xtables.lock", Type: &fileOrCreate}}},
					{Name: "policysync", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/var/run/nodeagent", Type: &dirOrCreate}}},
					{Name: "sys-fs", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/sys/fs", Type: &dirOrCreate}}},
					{Name: "bpffs", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/sys/fs/bpf", Type: &dirMustExist}}},
					{Name: "sys-kernel-security", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/sys/kernel/security"}}},
					{Name: "nodeproc", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/proc"}}},
					{
						Name: "tigera-ca-bundle",
						VolumeSource: corev1.VolumeSource{
							ConfigMap: &corev1.ConfigMapVolumeSource{
								LocalObjectReference: corev1.LocalObjectReference{
									Name: "tigera-ca-bundle",
								},
							},
						},
					},
					{
						Name: render.NodeTLSSecretName,
						VolumeSource: corev1.VolumeSource{
							Secret: &corev1.SecretVolumeSource{
								SecretName:  render.NodeTLSSecretName,
								DefaultMode: &defaultMode,
							},
						},
					},
					{Name: "flexvol-driver-host", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/usr/libexec/kubernetes/kubelet-plugins/volume/exec/nodeagent~uds", Type: &dirOrCreate}}},
				}
				Expect(ds.Spec.Template.Spec.Volumes).To(ConsistOf(expectedVols))

				// Verify volume mounts.
				expectedNodeVolumeMounts := []corev1.VolumeMount{
					{MountPath: "/lib/modules", Name: "lib-modules", ReadOnly: true},
					{MountPath: "/run/xtables.lock", Name: "xtables-lock"},
					{MountPath: "/var/run/calico", Name: "var-run-calico"},
					{MountPath: "/var/lib/calico", Name: "var-lib-calico"},
					{MountPath: "/var/run/nodeagent", Name: "policysync"},
					{MountPath: "/etc/pki/tls/certs", Name: "tigera-ca-bundle", ReadOnly: true},
					{MountPath: "/node-certs", Name: render.NodeTLSSecretName, ReadOnly: true},
					{MountPath: "/sys/fs/bpf", Name: "bpffs"},
					{MountPath: "/sys/kernel/security", Name: "sys-kernel-security", ReadOnly: true},
				}
				Expect(ds.Spec.Template.Spec.Containers[0].VolumeMounts).To(ConsistOf(expectedNodeVolumeMounts))

				// Verify tolerations.
				Expect(ds.Spec.Template.Spec.Tolerations).To(ConsistOf(rmeta.TolerateAll))

				// Verify readiness and liveness probes.
				verifyProbesAndLifecycle(ds, false, false)
			})

			It("should return customized CNI directories when specified", func() {
				customBinDir, customConfDir := "/custom/cni/bin", "/custom/cni/net.d"
				cfg.Installation.CNI.BinDir = &customBinDir
				cfg.Installation.CNI.ConfDir = &customConfDir
				component := render.Node(&cfg)
				Expect(component.ResolveImages(nil)).To(BeNil())
				resources, _ := component.Objects()
				dsResource := rtest.GetResource(resources, "calico-node", "calico-system", "apps", "v1", "DaemonSet")
				Expect(dsResource).ToNot(BeNil())

				// The DaemonSet should have the correct configuration.
				ds := dsResource.(*appsv1.DaemonSet)

				dirOrCreate := corev1.HostPathDirectoryOrCreate
				expectedVols := []corev1.Volume{
					{Name: "cni-bin-dir", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/custom/cni/bin", Type: &dirOrCreate}}},
					{Name: "cni-net-dir", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/custom/cni/net.d"}}},
					{Name: "cni-log-dir", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/var/log/calico/cni"}}},
					{Name: "cni-plugins-stage", VolumeSource: corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{}}},
				}
				Expect(ds.Spec.Template.Spec.Volumes).To(ContainElements(expectedVols))
				verifyInitContainers(ds, cfg.Installation)
			})

			DescribeTable("should properly render configuration using non-Calico CNI plugin",
				func(cni operatorv1.CNIPluginType, ipam operatorv1.IPAMPluginType, expectedEnvs []corev1.EnvVar) {
					installation := &operatorv1.InstallationSpec{
						CNI: &operatorv1.CNISpec{
							Type: cni,
							IPAM: &operatorv1.IPAMSpec{Type: ipam},
						},
						FlexVolumePath: "/usr/libexec/kubernetes/kubelet-plugins/volume/exec/",
					}
					cfg.Installation = installation

					component := render.Node(&cfg)
					Expect(component.ResolveImages(nil)).To(BeNil())
					resources, _ := component.Objects()

					// Should render the correct resources.
					Expect(rtest.GetResource(resources, "calico-node", "calico-system", "apps", "v1", "DaemonSet")).ToNot(BeNil())
					dsResource := rtest.GetResource(resources, "calico-node", "calico-system", "apps", "v1", "DaemonSet")
					Expect(dsResource).ToNot(BeNil())

					// Should not render CNI configuration.
					cniCmResource := rtest.GetResource(resources, "cni-config", "calico-system", "", "v1", "ConfigMap")
					Expect(cniCmResource).To(BeNil())

					// The DaemonSet should have the correct configuration.
					ds := dsResource.(*appsv1.DaemonSet)

					// The pod template should have node critical priority
					Expect(ds.Spec.Template.Spec.PriorityClassName).To(Equal(render.NodePriorityClassName))

					verifyInitContainers(ds, installation)
					// Verify env
					expectedEnvs = append(expectedEnvs,
						corev1.EnvVar{Name: "CALICO_NETWORKING_BACKEND", Value: "none"},
						corev1.EnvVar{Name: "NO_DEFAULT_POOLS", Value: "true"},
						corev1.EnvVar{Name: "FELIX_DEFAULTENDPOINTTOHOSTACTION", Value: "ACCEPT"},
					)
					for _, expected := range expectedEnvs {
						Expect(ds.Spec.Template.Spec.Containers[0].Env).To(ContainElement(expected))
					}

					// Verify readiness and liveness probes.
					verifyProbesAndLifecycle(ds, false, false)
				},
				Entry("GKE", operatorv1.PluginGKE, operatorv1.IPAMPluginHostLocal, []corev1.EnvVar{
					{Name: "FELIX_INTERFACEPREFIX", Value: "gke"},
					{Name: "FELIX_IPTABLESMANGLEALLOWACTION", Value: "Return"},
					{Name: "FELIX_IPTABLESFILTERALLOWACTION", Value: "Return"},
				}),
				Entry("AmazonVPC", operatorv1.PluginAmazonVPC, operatorv1.IPAMPluginAmazonVPC, []corev1.EnvVar{
					{Name: "FELIX_INTERFACEPREFIX", Value: "eni"},
					{Name: "FELIX_IPTABLESMANGLEALLOWACTION", Value: "Return"},
				}),
				Entry("AzureVNET", operatorv1.PluginAzureVNET, operatorv1.IPAMPluginAzureVNET, []corev1.EnvVar{
					{Name: "FELIX_INTERFACEPREFIX", Value: "azv"},
				}),
			)
			It("should render all resources when using Calico CNI on EKS", func() {
				expectedResources := []struct {
					name    string
					ns      string
					group   string
					version string
					kind    string
				}{
					{name: "calico-node", ns: common.CalicoNamespace, group: "", version: "v1", kind: "ServiceAccount"},
					{name: "calico-node", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
					{name: "calico-node", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
					{name: "calico-cni-plugin", ns: common.CalicoNamespace, group: "", version: "v1", kind: "ServiceAccount"},
					{name: "calico-cni-plugin", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
					{name: "calico-cni-plugin", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
					{name: "cni-config", ns: common.CalicoNamespace, group: "", version: "v1", kind: "ConfigMap"},
					{name: common.NodeDaemonSetName, ns: common.CalicoNamespace, group: "apps", version: "v1", kind: "DaemonSet"},
				}

				disabled := operatorv1.BGPDisabled
				defaultInstance.FlexVolumePath = "/usr/libexec/kubernetes/kubelet-plugins/volume/exec/"
				defaultInstance.KubernetesProvider = operatorv1.ProviderEKS
				defaultInstance.CalicoNetwork.BGP = &disabled
				defaultInstance.CalicoNetwork.IPPools[0].Encapsulation = operatorv1.EncapsulationVXLAN
				cfg.IPPools = defaultInstance.CalicoNetwork.IPPools
				component := render.Node(&cfg)
				Expect(component.ResolveImages(nil)).To(BeNil())
				resources, _ := component.Objects()
				Expect(len(resources)).To(Equal(len(expectedResources)))

				// Should render the correct resources.
				i := 0
				for _, expectedRes := range expectedResources {
					rtest.ExpectResourceTypeAndObjectMetadata(resources[i], expectedRes.name, expectedRes.ns, expectedRes.group, expectedRes.version, expectedRes.kind)
					i++
				}

				cniCmResource := rtest.GetResource(resources, "cni-config", "calico-system", "", "v1", "ConfigMap")
				Expect(cniCmResource).ToNot(BeNil())
				cniCm := cniCmResource.(*corev1.ConfigMap)
				Expect(cniCm.Data["config"]).To(MatchJSON(fmt.Sprintf(`{
  "name": "k8s-pod-network",
  "cniVersion": "1.0.0",
  "plugins": [
    {
      "type": "calico",
      "calico_api_group": "",
      "datastore_type": "kubernetes",
      "mtu": 0,
      "nodename_file_optional": false,
      "log_level": "Debug",
      "log_file_path": "/var/log/calico/cni/cni.log",
      "log_file_max_size": 1,
      "log_file_max_age": 5,
      "log_file_max_count": 5,
      "ipam": {
          "type": "calico-ipam",
          "assign_ipv4" : "%t",
          "assign_ipv6" : "%t"
      },
      "container_settings": {
          "allow_ip_forwarding": false
      },
      "policy": {
          "type": "k8s"
      },
      "policy_setup_timeout_seconds": 0,
      "endpoint_status_dir": "/var/run/calico/endpoint-status",
      "kubernetes": {
          "kubeconfig": "__KUBECONFIG_FILEPATH__"
      }
    },
    {"type": "portmap", "snat": true, "capabilities": {"portMappings": true}}
  ]
}`, enableIPv4, enableIPv6)))

				dsResource := rtest.GetResource(resources, "calico-node", "calico-system", "apps", "v1", "DaemonSet")
				Expect(dsResource).ToNot(BeNil())

				// The DaemonSet should have the correct configuration.
				ds := dsResource.(*appsv1.DaemonSet)

				// The pod template should have node critical priority
				Expect(ds.Spec.Template.Spec.PriorityClassName).To(Equal(render.NodePriorityClassName))

				rtest.ExpectEnv(ds.Spec.Template.Spec.Containers[0].Env, "NO_DEFAULT_POOLS", "true")

				// Node image override results in correct image.
				Expect(ds.Spec.Template.Spec.Containers[0].Image).To(Equal(fmt.Sprintf("quay.io/%s%s:%s", components.CalicoImagePath, components.ComponentCalicoNode.Image, components.ComponentCalicoNode.Version)))

				verifyInitContainers(ds, defaultInstance)
				// Verify env
				expectedNodeEnv := []corev1.EnvVar{
					{Name: "DATASTORE_TYPE", Value: "kubernetes"},
					{Name: "WAIT_FOR_DATASTORE", Value: "true"},
					{Name: "CALICO_MANAGE_CNI", Value: "true"},
					{Name: "CALICO_NETWORKING_BACKEND", Value: "vxlan"},
					{Name: "CALICO_DISABLE_FILE_LOGGING", Value: "false"},
					{Name: "CLUSTER_TYPE", Value: "k8s,operator,ecs"},
					{Name: "FELIX_DEFAULTENDPOINTTOHOSTACTION", Value: "ACCEPT"},
					{Name: "FELIX_HEALTHENABLED", Value: "true"},
					{Name: "FELIX_HEALTHPORT", Value: "9099"},
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
					{Name: "FELIX_TYPHAK8SNAMESPACE", Value: "calico-system"},
					{Name: "FELIX_TYPHAK8SSERVICENAME", Value: "calico-typha"},
					{Name: "FELIX_TYPHACAFILE", Value: certificatemanagement.TrustedCertBundleMountPath},
					{Name: "FELIX_TYPHACERTFILE", Value: "/node-certs/tls.crt"},
					{Name: "FELIX_TYPHACN", Value: "typha-server"},
					{Name: "FELIX_TYPHAKEYFILE", Value: "/node-certs/tls.key"},
					{Name: "NO_DEFAULT_POOLS", Value: "true"},
				}
				expectedNodeEnv = configureExpectedNodeEnvIPVersions(expectedNodeEnv, defaultInstance, enableIPv4, enableIPv6)
				Expect(ds.Spec.Template.Spec.Containers[0].Env).To(ConsistOf(expectedNodeEnv))
				// Expect the SECURITY_GROUP env variables to not be set
				Expect(ds.Spec.Template.Spec.Containers[0].Env).NotTo(ContainElement(gstruct.MatchFields(gstruct.IgnoreExtras, gstruct.Fields{"Name": Equal("TIGERA_DEFAULT_SECURITY_GROUPS")})))
				Expect(ds.Spec.Template.Spec.Containers[0].Env).NotTo(ContainElement(gstruct.MatchFields(gstruct.IgnoreExtras, gstruct.Fields{"Name": Equal("TIGERA_POD_SECURITY_GROUP")})))
				// Verify volumes.
				fileOrCreate := corev1.HostPathFileOrCreate
				dirOrCreate := corev1.HostPathDirectoryOrCreate
				dirMustExist := corev1.HostPathDirectory
				expectedVols := []corev1.Volume{
					{Name: "lib-modules", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/lib/modules"}}},
					{Name: "var-run-calico", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/var/run/calico", Type: &dirOrCreate}}},
					{Name: "var-lib-calico", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/var/lib/calico", Type: &dirOrCreate}}},
					{Name: "xtables-lock", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/run/xtables.lock", Type: &fileOrCreate}}},
					{Name: "cni-bin-dir", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/opt/cni/bin", Type: &dirOrCreate}}},
					{Name: "cni-net-dir", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/etc/cni/net.d"}}},
					{Name: "cni-log-dir", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/var/log/calico/cni"}}},
					{Name: "cni-plugins-stage", VolumeSource: corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{}}},
					{Name: "policysync", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/var/run/nodeagent", Type: &dirOrCreate}}},
					{Name: "sys-fs", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/sys/fs", Type: &dirOrCreate}}},
					{Name: "bpffs", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/sys/fs/bpf", Type: &dirMustExist}}},
					{Name: "sys-kernel-security", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/sys/kernel/security"}}},
					{Name: "nodeproc", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/proc"}}},
					{
						Name: "tigera-ca-bundle",
						VolumeSource: corev1.VolumeSource{
							ConfigMap: &corev1.ConfigMapVolumeSource{
								LocalObjectReference: corev1.LocalObjectReference{
									Name: "tigera-ca-bundle",
								},
							},
						},
					},
					{
						Name: render.NodeTLSSecretName,
						VolumeSource: corev1.VolumeSource{
							Secret: &corev1.SecretVolumeSource{
								SecretName:  render.NodeTLSSecretName,
								DefaultMode: &defaultMode,
							},
						},
					},
					{Name: "flexvol-driver-host", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/usr/libexec/kubernetes/kubelet-plugins/volume/exec/nodeagent~uds", Type: &dirOrCreate}}},
				}
				Expect(ds.Spec.Template.Spec.Volumes).To(ConsistOf(expectedVols))

				// Verify volume mounts.
				expectedNodeVolumeMounts := []corev1.VolumeMount{
					{MountPath: "/lib/modules", Name: "lib-modules", ReadOnly: true},
					{MountPath: "/host/etc/cni/net.d", Name: "cni-net-dir"},
					{MountPath: "/run/xtables.lock", Name: "xtables-lock"},
					{MountPath: "/var/run/calico", Name: "var-run-calico"},
					{MountPath: "/var/lib/calico", Name: "var-lib-calico"},
					{MountPath: "/var/run/nodeagent", Name: "policysync"},
					{MountPath: "/etc/pki/tls/certs", Name: "tigera-ca-bundle", ReadOnly: true},
					{MountPath: "/node-certs", Name: render.NodeTLSSecretName, ReadOnly: true},
					{MountPath: "/var/log/calico/cni", Name: "cni-log-dir", ReadOnly: false},
					{MountPath: "/sys/fs/bpf", Name: "bpffs"},
					{MountPath: "/sys/kernel/security", Name: "sys-kernel-security", ReadOnly: true},
				}
				Expect(ds.Spec.Template.Spec.Containers[0].VolumeMounts).To(ConsistOf(expectedNodeVolumeMounts))

				// Verify tolerations.
				Expect(ds.Spec.Template.Spec.Tolerations).To(ConsistOf(rmeta.TolerateAll))

				// Verify readiness and liveness probes.
				verifyProbesAndLifecycle(ds, false, false)
			})

			It("should properly render a configuration using the AmazonVPC CNI plugin", func() {
				cfg.Installation = &operatorv1.InstallationSpec{
					KubernetesProvider: operatorv1.ProviderEKS,
					CNI:                &operatorv1.CNISpec{Type: operatorv1.PluginAmazonVPC},
					FlexVolumePath:     "/usr/libexec/kubernetes/kubelet-plugins/volume/exec/",
				}

				component := render.Node(&cfg)
				Expect(component.ResolveImages(nil)).To(BeNil())
				resources, _ := component.Objects()
				Expect(len(resources)).To(Equal(defaultNumExpectedResources - 1))

				// Should render the correct resources.
				Expect(rtest.GetResource(resources, "calico-node", "calico-system", "", "v1", "ServiceAccount")).ToNot(BeNil())
				Expect(rtest.GetResource(resources, "calico-node", "", "rbac.authorization.k8s.io", "v1", "ClusterRole")).ToNot(BeNil())
				Expect(rtest.GetResource(resources, "calico-node", "", "rbac.authorization.k8s.io", "v1", "ClusterRoleBinding")).ToNot(BeNil())
				Expect(rtest.GetResource(resources, "calico-node", "calico-system", "apps", "v1", "DaemonSet")).ToNot(BeNil())
				dsResource := rtest.GetResource(resources, "calico-node", "calico-system", "apps", "v1", "DaemonSet")
				Expect(dsResource).ToNot(BeNil())

				// Should not render CNI configuration.
				cniCmResource := rtest.GetResource(resources, "cni-config", "calico-system", "", "v1", "ConfigMap")
				Expect(cniCmResource).To(BeNil())

				// The DaemonSet should have the correct configuration.
				ds := dsResource.(*appsv1.DaemonSet)

				// The pod template should have node critical priority
				Expect(ds.Spec.Template.Spec.PriorityClassName).To(Equal(render.NodePriorityClassName))

				verifyInitContainers(ds, cfg.Installation)
				// Verify env
				expectedNodeEnv := []corev1.EnvVar{
					{Name: "DATASTORE_TYPE", Value: "kubernetes"},
					{Name: "WAIT_FOR_DATASTORE", Value: "true"},
					{Name: "CALICO_NETWORKING_BACKEND", Value: "none"},
					{Name: "CALICO_DISABLE_FILE_LOGGING", Value: "false"},
					{Name: "CLUSTER_TYPE", Value: "k8s,operator,ecs"},
					{Name: "IP", Value: "none"},
					{Name: "IP6", Value: "none"},
					{Name: "NO_DEFAULT_POOLS", Value: "true"},
					{Name: "CALICO_MANAGE_CNI", Value: "false"},
					{Name: "FELIX_DEFAULTENDPOINTTOHOSTACTION", Value: "ACCEPT"},
					{Name: "FELIX_IPV6SUPPORT", Value: "false"},
					{Name: "FELIX_HEALTHENABLED", Value: "true"},
					{Name: "FELIX_HEALTHPORT", Value: "9099"},
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
					{Name: "FELIX_TYPHAK8SNAMESPACE", Value: "calico-system"},
					{Name: "FELIX_TYPHAK8SSERVICENAME", Value: "calico-typha"},
					{Name: "FELIX_TYPHACAFILE", Value: certificatemanagement.TrustedCertBundleMountPath},
					{Name: "FELIX_TYPHACERTFILE", Value: "/node-certs/tls.crt"},
					{Name: "FELIX_TYPHACN", Value: "typha-server"},
					{Name: "FELIX_TYPHAKEYFILE", Value: "/node-certs/tls.key"},
					{Name: "FELIX_INTERFACEPREFIX", Value: "eni"},
					{Name: "FELIX_IPTABLESMANGLEALLOWACTION", Value: "Return"},
					{Name: "FELIX_ROUTESOURCE", Value: "WorkloadIPs"},
					{Name: "FELIX_BPFEXTTOSERVICECONNMARK", Value: "0x80"},
					{Name: "FELIX_WIREGUARDHOSTENCRYPTIONENABLED", Value: "true"},
				}
				Expect(ds.Spec.Template.Spec.Containers[0].Env).To(ConsistOf(expectedNodeEnv))

				// Expect the SECURITY_GROUP env variables to not be set
				Expect(ds.Spec.Template.Spec.Containers[0].Env).NotTo(ContainElement(gstruct.MatchFields(gstruct.IgnoreExtras, gstruct.Fields{"Name": Equal("TIGERA_DEFAULT_SECURITY_GROUPS")})))
				Expect(ds.Spec.Template.Spec.Containers[0].Env).NotTo(ContainElement(gstruct.MatchFields(gstruct.IgnoreExtras, gstruct.Fields{"Name": Equal("TIGERA_POD_SECURITY_GROUP")})))

				// Verify volumes.
				fileOrCreate := corev1.HostPathFileOrCreate
				dirOrCreate := corev1.HostPathDirectoryOrCreate
				dirMustExist := corev1.HostPathDirectory
				expectedVols := []corev1.Volume{
					{Name: "lib-modules", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/lib/modules"}}},
					{Name: "var-run-calico", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/var/run/calico", Type: &dirOrCreate}}},
					{Name: "var-lib-calico", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/var/lib/calico", Type: &dirOrCreate}}},
					{Name: "xtables-lock", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/run/xtables.lock", Type: &fileOrCreate}}},
					{Name: "policysync", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/var/run/nodeagent", Type: &dirOrCreate}}},
					{Name: "sys-fs", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/sys/fs", Type: &dirOrCreate}}},
					{Name: "bpffs", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/sys/fs/bpf", Type: &dirMustExist}}},
					{Name: "sys-kernel-security", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/sys/kernel/security"}}},
					{Name: "nodeproc", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/proc"}}},
					{
						Name: "tigera-ca-bundle",
						VolumeSource: corev1.VolumeSource{
							ConfigMap: &corev1.ConfigMapVolumeSource{
								LocalObjectReference: corev1.LocalObjectReference{
									Name: "tigera-ca-bundle",
								},
							},
						},
					},
					{
						Name: render.NodeTLSSecretName,
						VolumeSource: corev1.VolumeSource{
							Secret: &corev1.SecretVolumeSource{
								SecretName:  render.NodeTLSSecretName,
								DefaultMode: &defaultMode,
							},
						},
					},
					{Name: "flexvol-driver-host", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/usr/libexec/kubernetes/kubelet-plugins/volume/exec/nodeagent~uds", Type: &dirOrCreate}}},
				}
				Expect(ds.Spec.Template.Spec.Volumes).To(ConsistOf(expectedVols))

				// Verify volume mounts.
				expectedNodeVolumeMounts := []corev1.VolumeMount{
					{MountPath: "/lib/modules", Name: "lib-modules", ReadOnly: true},
					{MountPath: "/run/xtables.lock", Name: "xtables-lock"},
					{MountPath: "/var/run/calico", Name: "var-run-calico"},
					{MountPath: "/var/lib/calico", Name: "var-lib-calico"},
					{MountPath: "/var/run/nodeagent", Name: "policysync"},
					{MountPath: "/etc/pki/tls/certs", Name: "tigera-ca-bundle", ReadOnly: true},
					{MountPath: "/node-certs", Name: render.NodeTLSSecretName, ReadOnly: true},
					{MountPath: "/sys/fs/bpf", Name: "bpffs"},
					{MountPath: "/sys/kernel/security", Name: "sys-kernel-security", ReadOnly: true},
				}
				Expect(ds.Spec.Template.Spec.Containers[0].VolumeMounts).To(ConsistOf(expectedNodeVolumeMounts))

				// Verify tolerations.
				Expect(ds.Spec.Template.Spec.Tolerations).To(ConsistOf(rmeta.TolerateAll))

				// Verify readiness and liveness probes.
				verifyProbesAndLifecycle(ds, false, false)
			})

			It("should render all resources when running on openshift", func() {
				expectedResources := []struct {
					name    string
					ns      string
					group   string
					version string
					kind    string
				}{
					{name: "calico-node", ns: common.CalicoNamespace, group: "", version: "v1", kind: "ServiceAccount"},
					{name: "calico-node", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
					{name: "calico-node", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
					{name: "calico-cni-plugin", ns: common.CalicoNamespace, group: "", version: "v1", kind: "ServiceAccount"},
					{name: "calico-cni-plugin", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
					{name: "calico-cni-plugin", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
					{name: "cni-config", ns: common.CalicoNamespace, group: "", version: "v1", kind: "ConfigMap"},
					{name: common.NodeDaemonSetName, ns: common.CalicoNamespace, group: "apps", version: "v1", kind: "DaemonSet"},
				}

				defaultInstance.FlexVolumePath = "/etc/kubernetes/kubelet-plugins/volume/exec/"
				defaultInstance.KubernetesProvider = operatorv1.ProviderOpenShift
				defaultCNIConfDir, defaultCNIBinDir := render.DefaultCNIDirectories(defaultInstance.KubernetesProvider)
				defaultInstance.CNI.ConfDir, defaultInstance.CNI.BinDir = &defaultCNIConfDir, &defaultCNIBinDir
				cfg.FelixHealthPort = 9199
				component := render.Node(&cfg)
				Expect(component.ResolveImages(nil)).To(BeNil())
				resources, _ := component.Objects()
				Expect(len(resources)).To(Equal(len(expectedResources)))

				// Should render the correct resources.
				i := 0
				for _, expectedRes := range expectedResources {
					rtest.ExpectResourceTypeAndObjectMetadata(resources[i], expectedRes.name, expectedRes.ns, expectedRes.group, expectedRes.version, expectedRes.kind)
					i++
				}

				// calico-node clusterRole should have openshift securitycontextconstraints PolicyRule
				nodeRole := rtest.GetResource(resources, "calico-node", "", "rbac.authorization.k8s.io", "v1", "ClusterRole").(*rbacv1.ClusterRole)
				Expect(nodeRole.Rules).To(ContainElement(rbacv1.PolicyRule{
					APIGroups:     []string{"security.openshift.io"},
					Resources:     []string{"securitycontextconstraints"},
					Verbs:         []string{"use"},
					ResourceNames: []string{"privileged"},
				}))

				// The DaemonSet should have the correct configuration.
				ds := rtest.GetResource(resources, "calico-node", "calico-system", "apps", "v1", "DaemonSet").(*appsv1.DaemonSet)
				Expect(ds.Spec.Template.Spec.Containers[0].Image).To(Equal(fmt.Sprintf("quay.io/%s%s:%s", components.CalicoImagePath, components.ComponentCalicoNode.Image, components.ComponentCalicoNode.Version)))

				// The pod template should have node critical priority
				Expect(ds.Spec.Template.Spec.PriorityClassName).To(Equal(render.NodePriorityClassName))

				verifyInitContainers(ds, defaultInstance)
				// Verify volumes. In particular, we want to make sure the flexvol-driver-host volume uses the right
				// host path for flexvolume drivers.
				fileOrCreate := corev1.HostPathFileOrCreate
				dirOrCreate := corev1.HostPathDirectoryOrCreate
				dirMustExist := corev1.HostPathDirectory
				expectedVols := []corev1.Volume{
					{Name: "lib-modules", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/lib/modules"}}},
					{Name: "var-run-calico", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/var/run/calico", Type: &dirOrCreate}}},
					{Name: "var-lib-calico", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/var/lib/calico", Type: &dirOrCreate}}},
					{Name: "xtables-lock", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/run/xtables.lock", Type: &fileOrCreate}}},
					{Name: "cni-bin-dir", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/var/lib/cni/bin", Type: &dirOrCreate}}},
					{Name: "cni-net-dir", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/var/run/multus/cni/net.d"}}},
					{Name: "cni-log-dir", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/var/log/calico/cni"}}},
					{Name: "cni-plugins-stage", VolumeSource: corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{}}},
					{Name: "policysync", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/var/run/nodeagent", Type: &dirOrCreate}}},
					{Name: "flexvol-driver-host", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/etc/kubernetes/kubelet-plugins/volume/exec/nodeagent~uds", Type: &dirOrCreate}}},
					{Name: "sys-fs", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/sys/fs", Type: &dirOrCreate}}},
					{Name: "bpffs", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/sys/fs/bpf", Type: &dirMustExist}}},
					{Name: "sys-kernel-security", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/sys/kernel/security"}}},
					{Name: "nodeproc", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/proc"}}},
					{
						Name: "tigera-ca-bundle",
						VolumeSource: corev1.VolumeSource{
							ConfigMap: &corev1.ConfigMapVolumeSource{
								LocalObjectReference: corev1.LocalObjectReference{
									Name: "tigera-ca-bundle",
								},
							},
						},
					},
					{
						Name: render.NodeTLSSecretName,
						VolumeSource: corev1.VolumeSource{
							Secret: &corev1.SecretVolumeSource{
								SecretName:  render.NodeTLSSecretName,
								DefaultMode: &defaultMode,
							},
						},
					},
				}
				Expect(ds.Spec.Template.Spec.Volumes).To(ConsistOf(expectedVols))

				expectedNodeEnv := []corev1.EnvVar{
					// Default envvars.
					{Name: "DATASTORE_TYPE", Value: "kubernetes"},
					{Name: "WAIT_FOR_DATASTORE", Value: "true"},
					{Name: "CALICO_MANAGE_CNI", Value: "true"},
					{Name: "CALICO_NETWORKING_BACKEND", Value: "bird"},
					{Name: "CLUSTER_TYPE", Value: "k8s,operator,openshift,bgp"},
					{Name: "CALICO_DISABLE_FILE_LOGGING", Value: "false"},
					{Name: "FELIX_DEFAULTENDPOINTTOHOSTACTION", Value: "ACCEPT"},
					{Name: "FELIX_HEALTHENABLED", Value: "true"},
					{Name: "FELIX_HEALTHPORT", Value: "9199"},
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
					{Name: "FELIX_TYPHAK8SNAMESPACE", Value: "calico-system"},
					{Name: "FELIX_TYPHAK8SSERVICENAME", Value: "calico-typha"},
					{Name: "FELIX_TYPHACAFILE", Value: certificatemanagement.TrustedCertBundleMountPath},
					{Name: "FELIX_TYPHACERTFILE", Value: "/node-certs/tls.crt"},
					{Name: "FELIX_TYPHACN", Value: "typha-server"},
					{Name: "FELIX_TYPHAKEYFILE", Value: "/node-certs/tls.key"},
					{Name: "NO_DEFAULT_POOLS", Value: "true"},
				}
				expectedNodeEnv = configureExpectedNodeEnvIPVersions(expectedNodeEnv, defaultInstance, enableIPv4, enableIPv6)
				Expect(ds.Spec.Template.Spec.Containers[0].Env).To(ConsistOf(expectedNodeEnv))
				Expect(len(ds.Spec.Template.Spec.Containers[0].Env)).To(Equal(len(expectedNodeEnv)))

				verifyProbesAndLifecycle(ds, true, false)
			})

			It("should render all resources when variant is CalicoEnterprise and running on openshift", func() {
				expectedResources := []struct {
					name    string
					ns      string
					group   string
					version string
					kind    string
				}{
					{name: "calico-node", ns: common.CalicoNamespace, group: "", version: "v1", kind: "ServiceAccount"},
					{name: "calico-node", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
					{name: "calico-node", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
					{name: "calico-cni-plugin", ns: common.CalicoNamespace, group: "", version: "v1", kind: "ServiceAccount"},
					{name: "calico-cni-plugin", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
					{name: "calico-cni-plugin", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
					{name: "calico-node-metrics", ns: "calico-system", group: "", version: "v1", kind: "Service"},
					{name: "cni-config", ns: common.CalicoNamespace, group: "", version: "v1", kind: "ConfigMap"},
					{name: common.NodeDaemonSetName, ns: common.CalicoNamespace, group: "apps", version: "v1", kind: "DaemonSet"},
				}

				defaultInstance.Variant = operatorv1.CalicoEnterprise
				defaultInstance.KubernetesProvider = operatorv1.ProviderOpenShift
				defaultCNIConfDir, defaultCNIBinDir := render.DefaultCNIDirectories(defaultInstance.KubernetesProvider)
				defaultInstance.CNI.ConfDir, defaultInstance.CNI.BinDir = &defaultCNIConfDir, &defaultCNIBinDir
				cfg.NodeReporterMetricsPort = 9081
				cfg.FelixHealthPort = 9199

				component := render.Node(&cfg)
				Expect(component.ResolveImages(nil)).To(BeNil())
				resources, _ := component.Objects()
				Expect(len(resources)).To(Equal(len(expectedResources)))

				// Should render the correct resources.
				i := 0
				for _, expectedRes := range expectedResources {
					rtest.ExpectResourceTypeAndObjectMetadata(resources[i], expectedRes.name, expectedRes.ns, expectedRes.group, expectedRes.version, expectedRes.kind)
					i++
				}

				// calico-node clusterRole should have openshift securitycontextconstraints PolicyRule
				nodeRole := rtest.GetResource(resources, "calico-node", "", "rbac.authorization.k8s.io", "v1", "ClusterRole").(*rbacv1.ClusterRole)
				Expect(nodeRole.Rules).To(ContainElement(rbacv1.PolicyRule{
					APIGroups:     []string{"security.openshift.io"},
					Resources:     []string{"securitycontextconstraints"},
					Verbs:         []string{"use"},
					ResourceNames: []string{"privileged"},
				}))

				// The DaemonSet should have the correct configuration.
				ds := rtest.GetResource(resources, "calico-node", "calico-system", "apps", "v1", "DaemonSet").(*appsv1.DaemonSet)
				Expect(ds.Spec.Template.Spec.Containers[0].Image).To(Equal(components.TigeraRegistry + "tigera/node:" + components.ComponentTigeraNode.Version))

				// The pod template should have node critical priority
				Expect(ds.Spec.Template.Spec.PriorityClassName).To(Equal(render.NodePriorityClassName))

				verifyInitContainers(ds, defaultInstance)
				expectedNodeEnv := []corev1.EnvVar{
					// Default envvars.
					{Name: "DATASTORE_TYPE", Value: "kubernetes"},
					{Name: "WAIT_FOR_DATASTORE", Value: "true"},
					{Name: "CALICO_MANAGE_CNI", Value: "true"},
					{Name: "CALICO_NETWORKING_BACKEND", Value: "bird"},
					{Name: "CLUSTER_TYPE", Value: "k8s,operator,openshift,bgp"},
					{Name: "CALICO_DISABLE_FILE_LOGGING", Value: "false"},
					{Name: "FELIX_DEFAULTENDPOINTTOHOSTACTION", Value: "ACCEPT"},
					{Name: "FELIX_HEALTHENABLED", Value: "true"},
					{Name: "FELIX_HEALTHPORT", Value: "9199"},
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
					{Name: "FELIX_TYPHAK8SNAMESPACE", Value: "calico-system"},
					{Name: "FELIX_TYPHAK8SSERVICENAME", Value: "calico-typha"},
					{Name: "FELIX_TYPHACAFILE", Value: certificatemanagement.TrustedCertBundleMountPath},
					{Name: "FELIX_TYPHACERTFILE", Value: "/node-certs/tls.crt"},
					{Name: "FELIX_TYPHACN", Value: "typha-server"},
					{Name: "FELIX_TYPHAKEYFILE", Value: "/node-certs/tls.key"},
					// Tigera-specific envvars
					{Name: "FELIX_PROMETHEUSREPORTERENABLED", Value: "true"},
					{Name: "FELIX_PROMETHEUSREPORTERPORT", Value: "9081"},
					{Name: "FELIX_FLOWLOGSFILEENABLED", Value: "true"},
					{Name: "FELIX_FLOWLOGSFILEINCLUDELABELS", Value: "true"},
					{Name: "FELIX_FLOWLOGSFILEINCLUDEPOLICIES", Value: "true"},
					{Name: "FELIX_FLOWLOGSFILEINCLUDESERVICE", Value: "true"},
					{Name: "FELIX_FLOWLOGSENABLENETWORKSETS", Value: "true"},
					{Name: "FELIX_FLOWLOGSCOLLECTPROCESSINFO", Value: "true"},
					{Name: "FELIX_DNSLOGSFILEENABLED", Value: "true"},
					{Name: "FELIX_DNSLOGSFILEPERNODELIMIT", Value: "1000"},
					{Name: "MULTI_INTERFACE_MODE", Value: operatorv1.MultiInterfaceModeNone.Value()},
					{Name: "NO_DEFAULT_POOLS", Value: "true"},
				}
				expectedNodeEnv = configureExpectedNodeEnvIPVersions(expectedNodeEnv, defaultInstance, enableIPv4, enableIPv6)
				Expect(ds.Spec.Template.Spec.Containers[0].Env).To(ConsistOf(expectedNodeEnv))
				Expect(len(ds.Spec.Template.Spec.Containers[0].Env)).To(Equal(len(expectedNodeEnv)))

				verifyProbesAndLifecycle(ds, true, true)
			})

			It("should render all resources when variant is CalicoEnterprise and running on RKE2", func() {
				expectedResources := []struct {
					name    string
					ns      string
					group   string
					version string
					kind    string
				}{
					{name: "calico-node", ns: common.CalicoNamespace, group: "", version: "v1", kind: "ServiceAccount"},
					{name: "calico-node", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
					{name: "calico-node", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
					{name: "calico-cni-plugin", ns: common.CalicoNamespace, group: "", version: "v1", kind: "ServiceAccount"},
					{name: "calico-cni-plugin", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
					{name: "calico-cni-plugin", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
					{name: "calico-node-metrics", ns: "calico-system", group: "", version: "v1", kind: "Service"},
					{name: "cni-config", ns: common.CalicoNamespace, group: "", version: "v1", kind: "ConfigMap"},
					{name: common.NodeDaemonSetName, ns: common.CalicoNamespace, group: "apps", version: "v1", kind: "DaemonSet"},
				}

				defaultInstance.Variant = operatorv1.CalicoEnterprise
				defaultInstance.KubernetesProvider = operatorv1.ProviderRKE2
				defaultCNIConfDir, defaultCNIBinDir := render.DefaultCNIDirectories(defaultInstance.KubernetesProvider)
				defaultInstance.CNI.ConfDir, defaultInstance.CNI.BinDir = &defaultCNIConfDir, &defaultCNIBinDir
				cfg.NodeReporterMetricsPort = 9081
				cfg.FelixHealthPort = 9199

				component := render.Node(&cfg)
				Expect(component.ResolveImages(nil)).To(BeNil())
				resources, _ := component.Objects()
				Expect(len(resources)).To(Equal(len(expectedResources)), fmt.Sprintf("Actual resources: %#v", resources))

				// Should render the correct resources.
				i := 0
				for _, expectedRes := range expectedResources {
					rtest.ExpectResourceTypeAndObjectMetadata(resources[i], expectedRes.name, expectedRes.ns, expectedRes.group, expectedRes.version, expectedRes.kind)
					i++
				}

				// The DaemonSet should have the correct configuration.
				ds := rtest.GetResource(resources, "calico-node", "calico-system", "apps", "v1", "DaemonSet").(*appsv1.DaemonSet)
				Expect(ds.Spec.Template.Spec.Containers[0].Image).To(Equal(components.TigeraRegistry + "tigera/node:" + components.ComponentTigeraNode.Version))

				// The pod template should have node critical priority
				Expect(ds.Spec.Template.Spec.PriorityClassName).To(Equal(render.NodePriorityClassName))

				verifyInitContainers(ds, defaultInstance)

				expectedNodeEnv := []corev1.EnvVar{
					// Default envvars.
					{Name: "DATASTORE_TYPE", Value: "kubernetes"},
					{Name: "WAIT_FOR_DATASTORE", Value: "true"},
					{Name: "CALICO_MANAGE_CNI", Value: "true"},
					{Name: "CALICO_NETWORKING_BACKEND", Value: "bird"},
					{Name: "CLUSTER_TYPE", Value: "k8s,operator,bgp"},
					{Name: "CALICO_DISABLE_FILE_LOGGING", Value: "false"},
					{Name: "FELIX_DEFAULTENDPOINTTOHOSTACTION", Value: "ACCEPT"},
					{Name: "FELIX_HEALTHENABLED", Value: "true"},
					{Name: "FELIX_HEALTHPORT", Value: "9199"},
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
					{Name: "FELIX_TYPHAK8SNAMESPACE", Value: "calico-system"},
					{Name: "FELIX_TYPHAK8SSERVICENAME", Value: "calico-typha"},
					{Name: "FELIX_TYPHACAFILE", Value: certificatemanagement.TrustedCertBundleMountPath},
					{Name: "FELIX_TYPHACERTFILE", Value: "/node-certs/tls.crt"},
					{Name: "FELIX_TYPHACN", Value: "typha-server"},
					{Name: "FELIX_TYPHAKEYFILE", Value: "/node-certs/tls.key"},
					{Name: "NO_DEFAULT_POOLS", Value: "true"},
					// Tigera-specific envvars
					{Name: "FELIX_PROMETHEUSREPORTERENABLED", Value: "true"},
					{Name: "FELIX_PROMETHEUSREPORTERPORT", Value: "9081"},
					{Name: "FELIX_FLOWLOGSFILEENABLED", Value: "true"},
					{Name: "FELIX_FLOWLOGSFILEINCLUDELABELS", Value: "true"},
					{Name: "FELIX_FLOWLOGSFILEINCLUDEPOLICIES", Value: "true"},
					{Name: "FELIX_FLOWLOGSFILEINCLUDESERVICE", Value: "true"},
					{Name: "FELIX_FLOWLOGSENABLENETWORKSETS", Value: "true"},
					{Name: "FELIX_FLOWLOGSCOLLECTPROCESSINFO", Value: "true"},
					{Name: "FELIX_DNSLOGSFILEENABLED", Value: "true"},
					{Name: "FELIX_DNSLOGSFILEPERNODELIMIT", Value: "1000"},

					// The RKE2 envvar overrides.
					{Name: "MULTI_INTERFACE_MODE", Value: operatorv1.MultiInterfaceModeNone.Value()},
				}
				expectedNodeEnv = configureExpectedNodeEnvIPVersions(expectedNodeEnv, defaultInstance, enableIPv4, enableIPv6)
				Expect(ds.Spec.Template.Spec.Containers[0].Env).To(ConsistOf(expectedNodeEnv))
				Expect(len(ds.Spec.Template.Spec.Containers[0].Env)).To(Equal(len(expectedNodeEnv)))

				verifyProbesAndLifecycle(ds, true, true)

				// The metrics service should have the correct configuration.
				ms := rtest.GetResource(resources, "calico-node-metrics", "calico-system", "", "v1", "Service").(*corev1.Service)
				Expect(ms.Spec.ClusterIP).To(Equal("None"), "metrics service should be headless to prevent kube-proxy from rendering too many iptables rules")
			})

			It("should render volumes and node volumemounts when bird templates are provided", func() {
				expectedResources := []struct {
					name    string
					ns      string
					group   string
					version string
					kind    string
				}{
					{name: "calico-node", ns: common.CalicoNamespace, group: "", version: "v1", kind: "ServiceAccount"},
					{name: "calico-node", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
					{name: "calico-node", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
					{name: "calico-cni-plugin", ns: common.CalicoNamespace, group: "", version: "v1", kind: "ServiceAccount"},
					{name: "calico-cni-plugin", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
					{name: "calico-cni-plugin", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
					{name: "cni-config", ns: common.CalicoNamespace, group: "", version: "v1", kind: "ConfigMap"},
					{name: render.BirdTemplatesConfigMapName, ns: common.CalicoNamespace, group: "", version: "v1", kind: "ConfigMap"},
					{name: common.NodeDaemonSetName, ns: common.CalicoNamespace, group: "apps", version: "v1", kind: "DaemonSet"},
				}

				cfg.BirdTemplates = map[string]string{
					"template-1.yaml": "dataforTemplate1 that is not used here",
				}
				defaultInstance.KubernetesProvider = operatorv1.ProviderOpenShift
				defaultCNIConfDir, defaultCNIBinDir := render.DefaultCNIDirectories(defaultInstance.KubernetesProvider)
				defaultInstance.CNI.ConfDir, defaultInstance.CNI.BinDir = &defaultCNIConfDir, &defaultCNIBinDir
				component := render.Node(&cfg)
				Expect(component.ResolveImages(nil)).To(BeNil())
				resources, _ := component.Objects()
				Expect(len(resources)).To(Equal(len(expectedResources)))

				// Should render the correct resources.
				i := 0
				for _, expectedRes := range expectedResources {
					rtest.ExpectResourceTypeAndObjectMetadata(resources[i], expectedRes.name, expectedRes.ns, expectedRes.group, expectedRes.version, expectedRes.kind)
					i++
				}

				// The DaemonSet should have the correct configuration.
				ds := rtest.GetResource(resources, "calico-node", "calico-system", "apps", "v1", "DaemonSet").(*appsv1.DaemonSet)

				// The pod template should have node critical priority
				Expect(ds.Spec.Template.Spec.PriorityClassName).To(Equal(render.NodePriorityClassName))

				volumes := ds.Spec.Template.Spec.Volumes
				// Expect(ds.Spec.Template.Spec.Volumes).To(Equal())
				Expect(volumes).To(ContainElement(
					corev1.Volume{
						Name: "bird-templates",
						VolumeSource: corev1.VolumeSource{
							ConfigMap: &corev1.ConfigMapVolumeSource{
								LocalObjectReference: corev1.LocalObjectReference{
									Name: "bird-templates",
								},
							},
						},
					}))

				volumeMounts := ds.Spec.Template.Spec.Containers[0].VolumeMounts
				Expect(volumeMounts).To(ContainElement(
					corev1.VolumeMount{
						Name:      "bird-templates",
						ReadOnly:  true,
						MountPath: "/etc/calico/confd/templates/template-1.yaml",
						SubPath:   "template-1.yaml",
					}))
			})
			Describe("AKS", func() {
				It("should avoid virtual nodes", func() {
					defaultInstance.KubernetesProvider = operatorv1.ProviderAKS
					defaultCNIConfDir, defaultCNIBinDir := render.DefaultCNIDirectories(defaultInstance.KubernetesProvider)
					defaultInstance.CNI.ConfDir, defaultInstance.CNI.BinDir = &defaultCNIConfDir, &defaultCNIBinDir
					component := render.Node(&cfg)
					Expect(component.ResolveImages(nil)).To(BeNil())
					resources, _ := component.Objects()
					dsResource := rtest.GetResource(resources, "calico-node", "calico-system", "apps", "v1", "DaemonSet")
					Expect(dsResource).ToNot(BeNil())

					// The DaemonSet should have the correct configuration.
					ds := dsResource.(*appsv1.DaemonSet)

					// The pod template should have node critical priority
					Expect(ds.Spec.Template.Spec.PriorityClassName).To(Equal(render.NodePriorityClassName))

					Expect(ds.Spec.Template.Spec.Affinity.NodeAffinity.RequiredDuringSchedulingIgnoredDuringExecution.NodeSelectorTerms).To(ContainElement(
						corev1.NodeSelectorTerm{
							MatchExpressions: []corev1.NodeSelectorRequirement{{
								Key:      "type",
								Operator: corev1.NodeSelectorOpNotIn,
								Values:   []string{"virtual-kubelet"},
							}},
						},
					))
				})
			})
			Describe("EKS", func() {
				It("should avoid virtual fargate nodes", func() {
					defaultInstance.KubernetesProvider = operatorv1.ProviderEKS
					defaultCNIConfDir, defaultCNIBinDir := render.DefaultCNIDirectories(defaultInstance.KubernetesProvider)
					defaultInstance.CNI.ConfDir, defaultInstance.CNI.BinDir = &defaultCNIConfDir, &defaultCNIBinDir
					component := render.Node(&cfg)
					Expect(component.ResolveImages(nil)).To(BeNil())
					resources, _ := component.Objects()
					dsResource := rtest.GetResource(resources, "calico-node", "calico-system", "apps", "v1", "DaemonSet")
					Expect(dsResource).ToNot(BeNil())

					// The DaemonSet should have the correct configuration.
					ds := dsResource.(*appsv1.DaemonSet)

					// The pod template should have node critical priority
					Expect(ds.Spec.Template.Spec.PriorityClassName).To(Equal(render.NodePriorityClassName))

					Expect(ds.Spec.Template.Spec.Affinity.NodeAffinity.RequiredDuringSchedulingIgnoredDuringExecution.NodeSelectorTerms).To(ContainElement(
						corev1.NodeSelectorTerm{
							MatchExpressions: []corev1.NodeSelectorRequirement{{
								Key:      "eks.amazonaws.com/compute-type",
								Operator: corev1.NodeSelectorOpNotIn,
								Values:   []string{"fargate"},
							}},
						},
					))
				})
			})
			Describe("test IP auto detection", func() {
				It("should support canReach", func() {
					defaultInstance.CalicoNetwork.NodeAddressAutodetectionV4.FirstFound = nil
					defaultInstance.CalicoNetwork.NodeAddressAutodetectionV4.CanReach = "1.1.1.1"
					component := render.Node(&cfg)
					Expect(component.ResolveImages(nil)).To(BeNil())
					resources, _ := component.Objects()
					Expect(len(resources)).To(Equal(defaultNumExpectedResources))

					dsResource := rtest.GetResource(resources, "calico-node", "calico-system", "apps", "v1", "DaemonSet")
					Expect(dsResource).ToNot(BeNil())

					// The DaemonSet should have the correct configuration.
					ds := dsResource.(*appsv1.DaemonSet)
					rtest.ExpectEnv(ds.Spec.Template.Spec.Containers[0].Env, "IP_AUTODETECTION_METHOD", "can-reach=1.1.1.1")
				})

				It("should support interface regex", func() {
					defaultInstance.CalicoNetwork.NodeAddressAutodetectionV4.FirstFound = nil
					defaultInstance.CalicoNetwork.NodeAddressAutodetectionV4.Interface = "eth*"
					component := render.Node(&cfg)
					Expect(component.ResolveImages(nil)).To(BeNil())
					resources, _ := component.Objects()
					Expect(len(resources)).To(Equal(defaultNumExpectedResources))

					dsResource := rtest.GetResource(resources, "calico-node", "calico-system", "apps", "v1", "DaemonSet")
					Expect(dsResource).ToNot(BeNil())

					// The DaemonSet should have the correct configuration.
					ds := dsResource.(*appsv1.DaemonSet)

					// The pod template should have node critical priority
					Expect(ds.Spec.Template.Spec.PriorityClassName).To(Equal(render.NodePriorityClassName))

					rtest.ExpectEnv(ds.Spec.Template.Spec.Containers[0].Env, "IP_AUTODETECTION_METHOD", "interface=eth*")
				})

				It("should support skip-interface regex", func() {
					defaultInstance.CalicoNetwork.NodeAddressAutodetectionV4.FirstFound = nil
					defaultInstance.CalicoNetwork.NodeAddressAutodetectionV4.SkipInterface = "eth*"
					component := render.Node(&cfg)
					Expect(component.ResolveImages(nil)).To(BeNil())
					resources, _ := component.Objects()
					Expect(len(resources)).To(Equal(defaultNumExpectedResources))

					dsResource := rtest.GetResource(resources, "calico-node", "calico-system", "apps", "v1", "DaemonSet")
					Expect(dsResource).ToNot(BeNil())

					// The DaemonSet should have the correct configuration.
					ds := dsResource.(*appsv1.DaemonSet)

					// The pod template should have node critical priority
					Expect(ds.Spec.Template.Spec.PriorityClassName).To(Equal(render.NodePriorityClassName))

					rtest.ExpectEnv(ds.Spec.Template.Spec.Containers[0].Env, "IP_AUTODETECTION_METHOD", "skip-interface=eth*")
				})

				It("should support cidr", func() {
					defaultInstance.CalicoNetwork.NodeAddressAutodetectionV4.FirstFound = nil
					defaultInstance.CalicoNetwork.NodeAddressAutodetectionV4.CIDRS = []string{"10.0.1.0/24", "10.0.2.0/24"}
					component := render.Node(&cfg)
					Expect(component.ResolveImages(nil)).To(BeNil())
					resources, _ := component.Objects()
					Expect(len(resources)).To(Equal(defaultNumExpectedResources))

					dsResource := rtest.GetResource(resources, "calico-node", "calico-system", "apps", "v1", "DaemonSet")
					Expect(dsResource).ToNot(BeNil())

					// The DaemonSet should have the correct configuration.
					ds := dsResource.(*appsv1.DaemonSet)

					// The pod template should have node critical priority
					Expect(ds.Spec.Template.Spec.PriorityClassName).To(Equal(render.NodePriorityClassName))

					rtest.ExpectEnv(ds.Spec.Template.Spec.Containers[0].Env, "IP_AUTODETECTION_METHOD", "cidr=10.0.1.0/24,10.0.2.0/24")
				})
			})

			It("should include updates needed for the core upgrade", func() {
				defaultInstance.KubernetesProvider = operatorv1.ProviderOpenShift
				defaultCNIConfDir, defaultCNIBinDir := render.DefaultCNIDirectories(defaultInstance.KubernetesProvider)
				defaultInstance.CNI.ConfDir, defaultInstance.CNI.BinDir = &defaultCNIConfDir, &defaultCNIBinDir
				cfg.MigrateNamespaces = true
				component := render.Node(&cfg)
				Expect(component.ResolveImages(nil)).To(BeNil())
				resources, _ := component.Objects()
				// +2 for temporary calico-node ClusterRole and ClusterRoleBinding during namespace migration
				Expect(len(resources)).To(Equal(defaultNumExpectedResources+2), fmt.Sprintf("resources are %v", resources))

				// Should render the correct resources.
				Expect(rtest.GetResource(resources, "calico-node", "calico-system", "", "v1", "ServiceAccount")).ToNot(BeNil())
				Expect(rtest.GetResource(resources, "calico-node", "", "rbac.authorization.k8s.io", "v1", "ClusterRole")).ToNot(BeNil())

				crbResource := rtest.GetResource(resources, "calico-node", "", "rbac.authorization.k8s.io", "v1", "ClusterRoleBinding")
				Expect(crbResource).ToNot(BeNil())
				crb := crbResource.(*rbacv1.ClusterRoleBinding)
				Expect(crb.Subjects).To(ContainElement(
					rbacv1.Subject{
						Kind:      "ServiceAccount",
						Name:      "calico-node",
						Namespace: "kube-system",
					},
				))

				cniCrbResource := rtest.GetResource(resources, "calico-cni-plugin", "", "rbac.authorization.k8s.io", "v1", "ClusterRoleBinding")
				Expect(cniCrbResource).ToNot(BeNil())
				cniCrb := cniCrbResource.(*rbacv1.ClusterRoleBinding)
				Expect(cniCrb.Subjects).To(ContainElement(
					rbacv1.Subject{
						Kind:      "ServiceAccount",
						Name:      "calico-cni-plugin",
						Namespace: "kube-system",
					},
				))

				Expect(rtest.GetResource(resources, "cni-config", "calico-system", "", "v1", "ConfigMap")).ToNot(BeNil())

				dsResource := rtest.GetResource(resources, "calico-node", "calico-system", "apps", "v1", "DaemonSet")
				Expect(dsResource).ToNot(BeNil())

				// The DaemonSet should have the correct configuration.
				ds := dsResource.(*appsv1.DaemonSet)

				// The pod template should have node critical priority
				Expect(ds.Spec.Template.Spec.PriorityClassName).To(Equal(render.NodePriorityClassName))

				ns := ds.Spec.Template.Spec.NodeSelector
				Expect(ns).To(HaveKey("projectcalico.org/operator-node-migration"))
				Expect(ns["projectcalico.org/operator-node-migration"]).To(Equal("migrated"))
			})

			It("should not enable prometheus metrics if NodeMetricsPort is nil", func() {
				defaultInstance.Variant = operatorv1.CalicoEnterprise
				defaultInstance.NodeMetricsPort = nil
				cfg.NodeReporterMetricsPort = 9081

				component := render.Node(&cfg)
				Expect(component.ResolveImages(nil)).To(BeNil())
				resources, _ := component.Objects()
				Expect(len(resources)).To(Equal(defaultNumExpectedResources + 1))

				dsResource := rtest.GetResource(resources, "calico-node", "calico-system", "apps", "v1", "DaemonSet")
				Expect(dsResource).ToNot(BeNil())

				notExpectedEnvVar := corev1.EnvVar{Name: "FELIX_PROMETHEUSMETRICSPORT"}
				ds := dsResource.(*appsv1.DaemonSet)
				Expect(ds.Spec.Template.Spec.Containers[0].Env).ToNot(ContainElement(notExpectedEnvVar))

				// It should have the reporter port, though.
				expected := corev1.EnvVar{Name: "FELIX_PROMETHEUSREPORTERPORT"}
				Expect(ds.Spec.Template.Spec.Containers[0].Env).ToNot(ContainElement(expected))
			})

			It("should set FELIX_PROMETHEUSMETRICSPORT with a custom value if NodeMetricsPort is set", func() {
				var nodeMetricsPort int32 = 1234
				defaultInstance.Variant = operatorv1.CalicoEnterprise
				defaultInstance.NodeMetricsPort = &nodeMetricsPort
				component := render.Node(&cfg)
				Expect(component.ResolveImages(nil)).To(BeNil())
				resources, _ := component.Objects()
				Expect(len(resources)).To(Equal(defaultNumExpectedResources + 1))

				dsResource := rtest.GetResource(resources, "calico-node", "calico-system", "apps", "v1", "DaemonSet")
				Expect(dsResource).ToNot(BeNil())

				// Assert on expected env vars.
				expectedEnvVars := []corev1.EnvVar{
					{Name: "FELIX_PROMETHEUSMETRICSPORT", Value: "1234"},
					{Name: "FELIX_PROMETHEUSMETRICSENABLED", Value: "true"},
				}
				ds := dsResource.(*appsv1.DaemonSet)
				for _, v := range expectedEnvVars {
					Expect(ds.Spec.Template.Spec.Containers[0].Env).To(ContainElement(v))
				}

				// Assert we set annotations properly.
				Expect(ds.Spec.Template.Annotations["prometheus.io/scrape"]).To(Equal("true"))
				Expect(ds.Spec.Template.Annotations["prometheus.io/port"]).To(Equal("1234"))
			})

			It("should not render a FlexVolume container if FlexVolumePath is set to None", func() {
				defaultInstance.FlexVolumePath = "None"
				component := render.Node(&cfg)
				Expect(component.ResolveImages(nil)).To(BeNil())
				resources, _ := component.Objects()
				Expect(len(resources)).To(Equal(defaultNumExpectedResources))

				dsResource := rtest.GetResource(resources, "calico-node", "calico-system", "apps", "v1", "DaemonSet")
				Expect(dsResource).ToNot(BeNil())
				ds := dsResource.(*appsv1.DaemonSet)
				Expect(ds).ToNot(BeNil())
				verifyInitContainers(ds, defaultInstance)
			})

			It("should omit the cni-plugins init container when CNI.InstallMode is CalicoOnly", func() {
				mode := operatorv1.CNIInstallModeCalicoOnly
				defaultInstance.CNI.InstallMode = &mode
				component := render.Node(&cfg)
				Expect(component.ResolveImages(nil)).To(BeNil())
				resources, _ := component.Objects()

				dsResource := rtest.GetResource(resources, "calico-node", "calico-system", "apps", "v1", "DaemonSet")
				Expect(dsResource).ToNot(BeNil())
				ds := dsResource.(*appsv1.DaemonSet)
				Expect(ds).ToNot(BeNil())

				// cni-plugins init container is absent and install-cni does not mount
				// the staging volume.
				Expect(rtest.GetContainer(ds.Spec.Template.Spec.InitContainers, "cni-plugins")).To(BeNil())
				installCNI := rtest.GetContainer(ds.Spec.Template.Spec.InitContainers, "install-cni")
				Expect(installCNI).NotTo(BeNil())
				for _, m := range installCNI.VolumeMounts {
					Expect(m.Name).NotTo(Equal("cni-plugins-stage"))
				}
				// Pod has no cni-plugins-stage volume.
				for _, v := range ds.Spec.Template.Spec.Volumes {
					Expect(v.Name).NotTo(Equal("cni-plugins-stage"))
				}

				verifyInitContainers(ds, defaultInstance)
			})

			It("should render MaxUnavailable if a custom value was set", func() {
				two := intstr.FromInt(2)
				defaultInstance.NodeUpdateStrategy.RollingUpdate.MaxUnavailable = &two
				component := render.Node(&cfg)
				Expect(component.ResolveImages(nil)).To(BeNil())
				resources, _ := component.Objects()
				Expect(len(resources)).To(Equal(defaultNumExpectedResources))

				dsResource := rtest.GetResource(resources, "calico-node", "calico-system", "apps", "v1", "DaemonSet")
				Expect(dsResource).ToNot(BeNil())
				ds := dsResource.(*appsv1.DaemonSet)
				Expect(ds).ToNot(BeNil())

				Expect(ds.Spec.UpdateStrategy.RollingUpdate.MaxUnavailable).To(Equal(&two))
			})

			It("should render LinuxPolicySetupTimeoutSeconds if a custom value was set", func() {
				two := int32(2)
				defaultInstance.CalicoNetwork.LinuxPolicySetupTimeoutSeconds = &two
				component := render.Node(&cfg)
				Expect(component.ResolveImages(nil)).To(BeNil())
				resources, _ := component.Objects()
				Expect(len(resources)).To(Equal(defaultNumExpectedResources))

				dsResource := rtest.GetResource(resources, "calico-node", "calico-system", "apps", "v1", "DaemonSet")
				Expect(dsResource).ToNot(BeNil())
				ds := dsResource.(*appsv1.DaemonSet)
				Expect(ds).ToNot(BeNil())

				for _, c := range ds.Spec.Template.Spec.Containers {
					Expect(c.Env).To(ContainElement(corev1.EnvVar{
						Name:  "FELIX_ENDPOINTSTATUSPATHPREFIX",
						Value: "/var/run/calico",
					}))
				}
			})

			It("should render cni config without portmap when HostPorts disabled", func() {
				expectedResources := []struct {
					name    string
					ns      string
					group   string
					version string
					kind    string
				}{
					{name: "calico-node", ns: common.CalicoNamespace, group: "", version: "v1", kind: "ServiceAccount"},
					{name: "calico-node", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
					{name: "calico-node", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
					{name: "calico-cni-plugin", ns: common.CalicoNamespace, group: "", version: "v1", kind: "ServiceAccount"},
					{name: "calico-cni-plugin", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
					{name: "calico-cni-plugin", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
					{name: "cni-config", ns: common.CalicoNamespace, group: "", version: "v1", kind: "ConfigMap"},
					{name: common.NodeDaemonSetName, ns: common.CalicoNamespace, group: "apps", version: "v1", kind: "DaemonSet"},
				}

				defaultInstance.FlexVolumePath = "/usr/libexec/kubernetes/kubelet-plugins/volume/exec/"
				hpd := operatorv1.HostPortsDisabled
				defaultInstance.CalicoNetwork.HostPorts = &hpd
				component := render.Node(&cfg)
				Expect(component.ResolveImages(nil)).To(BeNil())
				resources, _ := component.Objects()
				Expect(len(resources)).To(Equal(len(expectedResources)))

				// Should render the correct resources.
				i := 0
				for _, expectedRes := range expectedResources {
					rtest.ExpectResourceTypeAndObjectMetadata(resources[i], expectedRes.name, expectedRes.ns, expectedRes.group, expectedRes.version, expectedRes.kind)
					i++
				}

				cniCmResource := rtest.GetResource(resources, "cni-config", "calico-system", "", "v1", "ConfigMap")
				Expect(cniCmResource).ToNot(BeNil())
				cniCm := cniCmResource.(*corev1.ConfigMap)
				Expect(cniCm.Data["config"]).To(MatchJSON(fmt.Sprintf(`{
  "name": "k8s-pod-network",
  "cniVersion": "1.0.0",
  "plugins": [
    {
      "type": "calico",
      "calico_api_group": "",
      "datastore_type": "kubernetes",
      "mtu": 0,
      "nodename_file_optional": false,
      "log_level": "Debug",
      "log_file_path": "/var/log/calico/cni/cni.log",
      "log_file_max_size": 1,
      "log_file_max_age": 5,
      "log_file_max_count": 5,
      "ipam": {
          "type": "calico-ipam",
          "assign_ipv4" : "%t",
          "assign_ipv6" : "%t"
      },
      "container_settings": {
          "allow_ip_forwarding": false
      },
      "policy": {
          "type": "k8s"
      },
      "policy_setup_timeout_seconds": 0,
      "endpoint_status_dir": "/var/run/calico/endpoint-status",
      "kubernetes": {
          "kubeconfig": "__KUBECONFIG_FILEPATH__"
      }
    }
  ]
}`, enableIPv4, enableIPv6)))

				// The DaemonSet should have the correct configuration.
				ds := rtest.GetResource(resources, "calico-node", "calico-system", "apps", "v1", "DaemonSet").(*appsv1.DaemonSet)

				// The pod template should have node critical priority
				Expect(ds.Spec.Template.Spec.PriorityClassName).To(Equal(render.NodePriorityClassName))

				verifyInitContainers(ds, defaultInstance)
				Expect(ds.Spec.Template.Spec.Volumes).To(ContainElement(
					corev1.Volume{Name: "cni-net-dir", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/etc/cni/net.d"}}}))
			})

			It("should render cni config with sysctl parameters", func() {
				sysctl := []operatorv1.Sysctl{
					{
						Key:   "net.ipv4.tcp_keepalive_intvl",
						Value: "15",
					},
					{
						Key:   "net.ipv4.tcp_keepalive_probes",
						Value: "6",
					},
					{
						Key:   "net.ipv4.tcp_keepalive_time",
						Value: "40",
					},
				}
				defaultInstance.CalicoNetwork.Sysctl = sysctl
				component := render.Node(&cfg)
				Expect(component.ResolveImages(nil)).To(BeNil())
				resources, _ := component.Objects()
				Expect(len(resources)).To(Equal(defaultNumExpectedResources))

				// Should render the correct resources.
				cniCmResource := rtest.GetResource(resources, "cni-config", "calico-system", "", "v1", "ConfigMap")
				Expect(cniCmResource).ToNot(BeNil())
				cniCm := cniCmResource.(*corev1.ConfigMap)
				Expect(cniCm.Data["config"]).To(MatchJSON(fmt.Sprintf(`{
  "name": "k8s-pod-network",
  "cniVersion": "1.0.0",
  "plugins": [
    {
      "container_settings": {
        "allow_ip_forwarding": false
      },
      "calico_api_group": "",
      "datastore_type": "kubernetes",
        "ipam": {
          "assign_ipv4":  "%t",
          "assign_ipv6":  "%t",
          "type": "calico-ipam"
      },
      "kubernetes": {
        "kubeconfig": "__KUBECONFIG_FILEPATH__"
      },
      "log_file_max_age": 5,
      "log_file_max_count": 5,
      "log_file_max_size": 1,
      "log_file_path": "/var/log/calico/cni/cni.log",
      "log_level": "Debug",
      "mtu": 0,
      "nodename_file_optional": false,
      "policy": {
        "type": "k8s"
      },
      "policy_setup_timeout_seconds": 0,
      "endpoint_status_dir": "/var/run/calico/endpoint-status",
      "type": "calico"
    },
    {
      "capabilities": {
        "portMappings": true
      },
      "snat": true,
      "type": "portmap"
    },
    {
      "sysctl":
		  {
			"net.ipv4.tcp_keepalive_intvl": "15",
			"net.ipv4.tcp_keepalive_probes": "6",
			"net.ipv4.tcp_keepalive_time": "40"
		  },
      "type": "tuning"
	}
  ]
  }`, enableIPv4, enableIPv6)))
			})

			It("should render a proper 'policy_setup_timeout_seconds' setting in the cni config", func() {
				one := int32(1)
				defaultInstance.CalicoNetwork.LinuxPolicySetupTimeoutSeconds = &one
				component := render.Node(&cfg)
				Expect(component.ResolveImages(nil)).To(BeNil())
				resources, _ := component.Objects()
				Expect(len(resources)).To(Equal(defaultNumExpectedResources))

				// Should render the correct resources.
				cniCmResource := rtest.GetResource(resources, "cni-config", "calico-system", "", "v1", "ConfigMap")
				Expect(cniCmResource).ToNot(BeNil())
				cniCm := cniCmResource.(*corev1.ConfigMap)
				Expect(cniCm.Data["config"]).To(MatchJSON(fmt.Sprintf(`{
  "name": "k8s-pod-network",
  "cniVersion": "1.0.0",
  "plugins": [
    {
      "type": "calico",
      "calico_api_group": "",
      "datastore_type": "kubernetes",
      "mtu": 0,
      "nodename_file_optional": false,
      "log_level": "Debug",
      "log_file_path": "/var/log/calico/cni/cni.log",
      "log_file_max_size": 1,
      "log_file_max_age": 5,
      "log_file_max_count": 5,
      "ipam": {
          "type": "calico-ipam",
          "assign_ipv4" : "%t",
          "assign_ipv6" : "%t"
      },
      "container_settings": {
          "allow_ip_forwarding": false
      },
      "policy_setup_timeout_seconds": 1,
      "endpoint_status_dir": "/var/run/calico/endpoint-status",
      "policy": {
          "type": "k8s"
      },
      "kubernetes": {
          "kubeconfig": "__KUBECONFIG_FILEPATH__"
      }
    },
    {"type": "portmap", "snat": true, "capabilities": {"portMappings": true}}
  ]
}`, enableIPv4, enableIPv6)))
			})

			It("should render a proper 'allow_ip_forwarding' container setting in the cni config", func() {
				cif := operatorv1.ContainerIPForwardingEnabled
				defaultInstance.CalicoNetwork.ContainerIPForwarding = &cif
				component := render.Node(&cfg)
				Expect(component.ResolveImages(nil)).To(BeNil())
				resources, _ := component.Objects()
				Expect(len(resources)).To(Equal(defaultNumExpectedResources))

				// Should render the correct resources.
				cniCmResource := rtest.GetResource(resources, "cni-config", "calico-system", "", "v1", "ConfigMap")
				Expect(cniCmResource).ToNot(BeNil())
				cniCm := cniCmResource.(*corev1.ConfigMap)
				Expect(cniCm.Data["config"]).To(MatchJSON(fmt.Sprintf(`{
  "name": "k8s-pod-network",
  "cniVersion": "1.0.0",
  "plugins": [
    {
      "type": "calico",
      "calico_api_group": "",
      "datastore_type": "kubernetes",
      "mtu": 0,
      "nodename_file_optional": false,
      "log_level": "Debug",
      "log_file_path": "/var/log/calico/cni/cni.log",
      "log_file_max_size": 1,
      "log_file_max_age": 5,
      "log_file_max_count": 5,
      "ipam": {
          "type": "calico-ipam",
          "assign_ipv4" : "%t",
          "assign_ipv6" : "%t"
      },
      "container_settings": {
          "allow_ip_forwarding": true
      },
      "policy_setup_timeout_seconds": 0,
      "endpoint_status_dir": "/var/run/calico/endpoint-status",
      "policy": {
          "type": "k8s"
      },
      "kubernetes": {
          "kubeconfig": "__KUBECONFIG_FILEPATH__"
      }
    },
    {"type": "portmap", "snat": true, "capabilities": {"portMappings": true}}
  ]
}`, enableIPv4, enableIPv6)))
			})

			It("should render device_type=netkit in the cni config when LinuxPodInterface is Netkit", func() {
				nk := operatorv1.LinuxPodInterfaceNetkit
				defaultInstance.CalicoNetwork.LinuxPodInterfaceType = &nk
				component := render.Node(&cfg)
				Expect(component.ResolveImages(nil)).To(BeNil())
				resources, _ := component.Objects()
				Expect(len(resources)).To(Equal(defaultNumExpectedResources))

				cniCmResource := rtest.GetResource(resources, "cni-config", "calico-system", "", "v1", "ConfigMap")
				Expect(cniCmResource).ToNot(BeNil())
				cniCm := cniCmResource.(*corev1.ConfigMap)
				Expect(cniCm.Data["config"]).To(MatchJSON(fmt.Sprintf(`{
  "name": "k8s-pod-network",
  "cniVersion": "1.0.0",
  "plugins": [
    {
      "type": "calico",
      "calico_api_group": "",
      "datastore_type": "kubernetes",
      "mtu": 0,
      "nodename_file_optional": false,
      "log_level": "Debug",
      "log_file_path": "/var/log/calico/cni/cni.log",
      "log_file_max_size": 1,
      "log_file_max_age": 5,
      "log_file_max_count": 5,
      "device_type": "netkit",
      "ipam": {
          "type": "calico-ipam",
          "assign_ipv4" : "%t",
          "assign_ipv6" : "%t"
      },
      "container_settings": {
          "allow_ip_forwarding": false
      },
      "policy_setup_timeout_seconds": 0,
      "endpoint_status_dir": "/var/run/calico/endpoint-status",
      "policy": {
          "type": "k8s"
      },
      "kubernetes": {
          "kubeconfig": "__KUBECONFIG_FILEPATH__"
      }
    },
    {"type": "portmap", "snat": true, "capabilities": {"portMappings": true}}
  ]
}`, enableIPv4, enableIPv6)))
			})

			It("should not emit device_type in the cni config when LinuxPodInterface is Veth (default)", func() {
				veth := operatorv1.LinuxPodInterfaceVeth
				defaultInstance.CalicoNetwork.LinuxPodInterfaceType = &veth
				component := render.Node(&cfg)
				Expect(component.ResolveImages(nil)).To(BeNil())
				resources, _ := component.Objects()
				Expect(len(resources)).To(Equal(defaultNumExpectedResources))

				cniCmResource := rtest.GetResource(resources, "cni-config", "calico-system", "", "v1", "ConfigMap")
				Expect(cniCmResource).ToNot(BeNil())
				cniCm := cniCmResource.(*corev1.ConfigMap)
				Expect(cniCm.Data["config"]).NotTo(ContainSubstring("device_type"))
			})

			It("should render cni config with host-local", func() {
				defaultInstance.CNI.IPAM.Type = operatorv1.IPAMPluginHostLocal
				component := render.Node(&cfg)
				Expect(component.ResolveImages(nil)).To(BeNil())
				resources, _ := component.Objects()
				Expect(len(resources)).To(Equal(defaultNumExpectedResources))

				// Should render the correct resources.
				cniCmResource := rtest.GetResource(resources, "cni-config", "calico-system", "", "v1", "ConfigMap")
				Expect(cniCmResource).ToNot(BeNil())
				cniCm := cniCmResource.(*corev1.ConfigMap)

				// Assemble subnet JSON based on whether IPv4 and/or IPv6 are enabled
				var subnetStr string
				if enableIPv4 && enableIPv6 {
					subnetStr = `"ranges": [
                  [
                    {
                      "subnet": "usePodCidr"
                    }
                  ],
                  [
                    {
                      "subnet": "usePodCidrIPv6"
                    }
                  ]
                ]`
				} else if enableIPv4 {
					subnetStr = `"subnet" : "usePodCidr"`
				} else if enableIPv6 {
					subnetStr = `"subnet" : "usePodCidrIPv6"`
				}

				Expect(cniCm.Data["config"]).To(MatchJSON(fmt.Sprintf(`{
  "name": "k8s-pod-network",
  "cniVersion": "1.0.0",
  "plugins": [
    {
      "type": "calico",
      "calico_api_group": "",
      "datastore_type": "kubernetes",
      "mtu": 0,
      "nodename_file_optional": false,
      "log_level": "Debug",
      "log_file_path": "/var/log/calico/cni/cni.log",
      "log_file_max_size": 1,
      "log_file_max_age": 5,
      "log_file_max_count": 5,
      "ipam": {
          "type": "host-local",
          %s
      },
      "policy_setup_timeout_seconds": 0,
      "endpoint_status_dir": "/var/run/calico/endpoint-status",
      "container_settings": { "allow_ip_forwarding": false },
      "policy": { "type": "k8s" },
      "kubernetes": { "kubeconfig": "__KUBECONFIG_FILEPATH__" }
    },
    {"type": "portmap", "snat": true, "capabilities": {"portMappings": true}}
  ]
}`, subnetStr)))
			})

			It("should render cni config with host-local (dual-stack)", func() {
				defaultInstance.CNI.IPAM.Type = operatorv1.IPAMPluginHostLocal
				defaultInstance.CalicoNetwork.IPPools = []operatorv1.IPPool{
					{
						CIDR:          "192.168.0.0/24",
						Encapsulation: operatorv1.EncapsulationNone,
						NATOutgoing:   operatorv1.NATOutgoingEnabled,
						NodeSelector:  "all()",
					},
					{
						CIDR:          "fe80:00::00/64",
						Encapsulation: operatorv1.EncapsulationNone,
						NATOutgoing:   operatorv1.NATOutgoingEnabled,
						NodeSelector:  "all()",
					},
				}
				cfg.IPPools = defaultInstance.CalicoNetwork.IPPools

				component := render.Node(&cfg)
				Expect(component.ResolveImages(nil)).To(BeNil())
				resources, _ := component.Objects()
				Expect(len(resources)).To(Equal(defaultNumExpectedResources))

				// Should render the correct resources.
				cniCmResource := rtest.GetResource(resources, "cni-config", "calico-system", "", "v1", "ConfigMap")
				Expect(cniCmResource).ToNot(BeNil())
				cniCm := cniCmResource.(*corev1.ConfigMap)
				Expect(cniCm.Data["config"]).To(MatchJSON(`{
  "name": "k8s-pod-network",
  "cniVersion": "1.0.0",
  "plugins": [
    {
      "type": "calico",
      "calico_api_group": "",
      "datastore_type": "kubernetes",
      "mtu": 0,
      "nodename_file_optional": false,
      "log_level": "Debug",
      "log_file_path": "/var/log/calico/cni/cni.log",
      "log_file_max_size": 1,
      "log_file_max_age": 5,
      "log_file_max_count": 5,
      "ipam": {
          "type": "host-local",
          "ranges": [[{"subnet": "usePodCidr"}], [{"subnet": "usePodCidrIPv6"}]]
      },
      "policy_setup_timeout_seconds": 0,
      "endpoint_status_dir": "/var/run/calico/endpoint-status",
      "container_settings": { "allow_ip_forwarding": false },
      "policy": { "type": "k8s" },
      "kubernetes": { "kubeconfig": "__KUBECONFIG_FILEPATH__" }
    },
    {"type": "portmap", "snat": true, "capabilities": {"portMappings": true}}
  ]
}`))
			})

			It("should render cni config with host-local (v6-only)", func() {
				defaultInstance.CNI.IPAM.Type = operatorv1.IPAMPluginHostLocal
				defaultInstance.CalicoNetwork.IPPools = []operatorv1.IPPool{
					{
						CIDR:          "fe80:00::00/64",
						Encapsulation: operatorv1.EncapsulationNone,
						NATOutgoing:   operatorv1.NATOutgoingEnabled,
						NodeSelector:  "all()",
					},
				}
				cfg.IPPools = defaultInstance.CalicoNetwork.IPPools

				component := render.Node(&cfg)
				Expect(component.ResolveImages(nil)).To(BeNil())
				resources, _ := component.Objects()
				Expect(len(resources)).To(Equal(defaultNumExpectedResources))

				// Should render the correct resources.
				cniCmResource := rtest.GetResource(resources, "cni-config", "calico-system", "", "v1", "ConfigMap")
				Expect(cniCmResource).ToNot(BeNil())
				cniCm := cniCmResource.(*corev1.ConfigMap)
				Expect(cniCm.Data["config"]).To(MatchJSON(`{
  "name": "k8s-pod-network",
  "cniVersion": "1.0.0",
  "plugins": [
    {
      "type": "calico",
      "calico_api_group": "",
      "datastore_type": "kubernetes",
      "mtu": 0,
      "nodename_file_optional": false,
      "log_level": "Debug",
      "log_file_path": "/var/log/calico/cni/cni.log",
      "log_file_max_size": 1,
      "log_file_max_age": 5,
      "log_file_max_count": 5,
      "ipam": {
          "type": "host-local",
          "subnet" : "usePodCidrIPv6"
      },
      "policy_setup_timeout_seconds": 0,
      "endpoint_status_dir": "/var/run/calico/endpoint-status",
      "container_settings": { "allow_ip_forwarding": false },
      "policy": { "type": "k8s" },
      "kubernetes": { "kubeconfig": "__KUBECONFIG_FILEPATH__" }
    },
    {"type": "portmap", "snat": true, "capabilities": {"portMappings": true}}
  ]
}`))
			})

			It("should render cni config with k8s endpoint", func() {
				k8sServiceEp.Host = "k8shost"
				k8sServiceEp.Port = "1234"
				cfg.K8sServiceEp = k8sServiceEp
				component := render.Node(&cfg)
				Expect(component.ResolveImages(nil)).To(BeNil())
				resources, _ := component.Objects()
				Expect(len(resources)).To(Equal(defaultNumExpectedResources))

				// Should render the correct resources.
				cniCmResource := rtest.GetResource(resources, "cni-config", "calico-system", "", "v1", "ConfigMap")
				Expect(cniCmResource).ToNot(BeNil())
				cniCm := cniCmResource.(*corev1.ConfigMap)
				Expect(cniCm.Data["config"]).To(MatchJSON(fmt.Sprintf(`{
  "name": "k8s-pod-network",
  "cniVersion": "1.0.0",
  "plugins": [
    {
      "type": "calico",
      "calico_api_group": "",
      "policy_setup_timeout_seconds": 0,
      "endpoint_status_dir": "/var/run/calico/endpoint-status",
      "datastore_type": "kubernetes",
      "mtu": 0,
      "nodename_file_optional": false,
      "log_level": "Debug",
      "log_file_path": "/var/log/calico/cni/cni.log",
      "log_file_max_size": 1,
      "log_file_max_age": 5,
      "log_file_max_count": 5,
      "ipam": {
        "type": "calico-ipam",
        "assign_ipv4" : "%t",
        "assign_ipv6" : "%t"
      },
      "container_settings": {
        "allow_ip_forwarding": false
      },
      "policy": {
        "type": "k8s"
      },
      "kubernetes": {
        "k8s_api_root": "https://k8shost:1234",
        "kubeconfig": "__KUBECONFIG_FILEPATH__"
      }
    },
    {
      "type": "portmap",
      "snat": true,
      "capabilities": {
        "portMappings": true
      }
    }
  ]
}`, enableIPv4, enableIPv6)))
			})

			It("should render seccomp profiles", func() {
				seccompProf := "localhost/calico-node-v1"
				cfg.NodeAppArmorProfile = seccompProf
				component := render.Node(&cfg)
				Expect(component.ResolveImages(nil)).To(BeNil())
				resources, _ := component.Objects()

				dsResource := rtest.GetResource(resources, "calico-node", "calico-system", "apps", "v1", "DaemonSet")
				Expect(dsResource).ToNot(BeNil())
				ds := dsResource.(*appsv1.DaemonSet)
				Expect(ds).ToNot(BeNil())

				Expect(ds.Spec.Template.Annotations["container.apparmor.security.beta.kubernetes.io/calico-node"]).To(Equal(seccompProf))
			})

			It("should render resourcerequirements", func() {
				rr := &corev1.ResourceRequirements{
					Requests: corev1.ResourceList{
						corev1.ResourceCPU:    resource.MustParse("250m"),
						corev1.ResourceMemory: resource.MustParse("64Mi"),
					},
					Limits: corev1.ResourceList{
						corev1.ResourceCPU:    resource.MustParse("500m"),
						corev1.ResourceMemory: resource.MustParse("500Mi"),
					},
				}

				defaultInstance.ComponentResources = []operatorv1.ComponentResource{
					{
						ComponentName:        operatorv1.ComponentNameNode,
						ResourceRequirements: rr,
					},
				}

				component := render.Node(&cfg)
				Expect(component.ResolveImages(nil)).To(BeNil())
				resources, _ := component.Objects()

				dsResource := rtest.GetResource(resources, "calico-node", "calico-system", "apps", "v1", "DaemonSet")
				Expect(dsResource).ToNot(BeNil())
				ds := dsResource.(*appsv1.DaemonSet)

				passed := false
				for _, container := range ds.Spec.Template.Spec.Containers {
					if container.Name == "calico-node" {
						Expect(container.Resources).To(Equal(*rr))
						passed = true
					}
				}
				Expect(passed).To(Equal(true))
			})

			It("should render when configured to use cloud routes with host-local", func() {
				expectedResources := []struct {
					name    string
					ns      string
					group   string
					version string
					kind    string
				}{
					{name: "calico-node", ns: common.CalicoNamespace, group: "", version: "v1", kind: "ServiceAccount"},
					{name: "calico-node", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
					{name: "calico-node", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
					{name: "calico-cni-plugin", ns: common.CalicoNamespace, group: "", version: "v1", kind: "ServiceAccount"},
					{name: "calico-cni-plugin", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
					{name: "calico-cni-plugin", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
					{name: "cni-config", ns: common.CalicoNamespace, group: "", version: "v1", kind: "ConfigMap"},
					{name: common.NodeDaemonSetName, ns: common.CalicoNamespace, group: "apps", version: "v1", kind: "DaemonSet"},
				}

				disabled := operatorv1.BGPDisabled
				defaultInstance.CalicoNetwork.BGP = &disabled
				defaultInstance.CNI.Type = operatorv1.PluginCalico
				defaultInstance.CNI.IPAM.Type = operatorv1.IPAMPluginHostLocal
				defaultInstance.CalicoNetwork.IPPools = []operatorv1.IPPool{{
					CIDR:          "192.168.1.0/16",
					Encapsulation: operatorv1.EncapsulationNone,
					NATOutgoing:   operatorv1.NATOutgoingEnabled,
				}}
				cfg.IPPools = defaultInstance.CalicoNetwork.IPPools
				component := render.Node(&cfg)
				Expect(component.ResolveImages(nil)).To(BeNil())
				resources, _ := component.Objects()
				Expect(len(resources)).To(Equal(len(expectedResources)))

				// Should render the correct resources.
				i := 0
				for _, expectedRes := range expectedResources {
					rtest.ExpectResourceTypeAndObjectMetadata(resources[i], expectedRes.name, expectedRes.ns, expectedRes.group, expectedRes.version, expectedRes.kind)
					i++
				}

				cniCmResource := rtest.GetResource(resources, "cni-config", "calico-system", "", "v1", "ConfigMap")
				Expect(cniCmResource).ToNot(BeNil())
				cniCm := cniCmResource.(*corev1.ConfigMap)
				Expect(cniCm.Data["config"]).To(MatchJSON(`{
  "name": "k8s-pod-network",
  "cniVersion": "1.0.0",
  "plugins": [
    {
      "type": "calico",
      "calico_api_group": "",
      "policy_setup_timeout_seconds": 0,
      "endpoint_status_dir": "/var/run/calico/endpoint-status",
      "datastore_type": "kubernetes",
      "mtu": 0,
      "nodename_file_optional": false,
      "log_level": "Debug",
      "log_file_path": "/var/log/calico/cni/cni.log",
      "log_file_max_size": 1,
      "log_file_max_age": 5,
      "log_file_max_count": 5,
      "ipam": {
          "type": "host-local",
          "subnet": "usePodCidr"
      },
      "container_settings": {
          "allow_ip_forwarding": false
      },
      "policy": {
          "type": "k8s"
      },
      "kubernetes": {
          "kubeconfig": "__KUBECONFIG_FILEPATH__"
      }
    },
    {"type": "portmap", "snat": true, "capabilities": {"portMappings": true}}
  ]
}`))

				dsResource := rtest.GetResource(resources, "calico-node", "calico-system", "apps", "v1", "DaemonSet")
				Expect(dsResource).ToNot(BeNil())

				// The DaemonSet should have the correct configuration.
				ds := dsResource.(*appsv1.DaemonSet)

				// The pod template should have node critical priority
				Expect(ds.Spec.Template.Spec.PriorityClassName).To(Equal(render.NodePriorityClassName))

				rtest.ExpectEnv(ds.Spec.Template.Spec.Containers[0].Env, "NO_DEFAULT_POOLS", "true")

				// Node image override results in correct image.
				Expect(ds.Spec.Template.Spec.Containers[0].Image).To(Equal(fmt.Sprintf("quay.io/%s%s:%s", components.CalicoImagePath, components.ComponentCalicoNode.Image, components.ComponentCalicoNode.Version)))

				verifyInitContainers(ds, defaultInstance)
				// Verify env
				expectedNodeEnv := []corev1.EnvVar{
					{Name: "DATASTORE_TYPE", Value: "kubernetes"},
					{Name: "WAIT_FOR_DATASTORE", Value: "true"},
					{Name: "CALICO_NETWORKING_BACKEND", Value: "none"},
					{Name: "CALICO_MANAGE_CNI", Value: "true"},
					{Name: "CALICO_DISABLE_FILE_LOGGING", Value: "false"},
					{Name: "CLUSTER_TYPE", Value: "k8s,operator"},
					{Name: "USE_POD_CIDR", Value: "true"},
					{Name: "FELIX_DEFAULTENDPOINTTOHOSTACTION", Value: "ACCEPT"},
					{Name: "FELIX_HEALTHENABLED", Value: "true"},
					{Name: "FELIX_HEALTHPORT", Value: "9099"},
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
					{Name: "FELIX_TYPHAK8SNAMESPACE", Value: "calico-system"},
					{Name: "FELIX_TYPHAK8SSERVICENAME", Value: "calico-typha"},
					{Name: "FELIX_TYPHACAFILE", Value: certificatemanagement.TrustedCertBundleMountPath},
					{Name: "FELIX_TYPHACERTFILE", Value: "/node-certs/tls.crt"},
					{Name: "FELIX_TYPHACN", Value: "typha-server"},
					{Name: "FELIX_TYPHAKEYFILE", Value: "/node-certs/tls.key"},
					{Name: "NO_DEFAULT_POOLS", Value: "true"},
				}
				expectedNodeEnv = configureExpectedNodeEnvIPVersions(expectedNodeEnv, defaultInstance, enableIPv4, enableIPv6)
				Expect(ds.Spec.Template.Spec.Containers[0].Env).To(ConsistOf(expectedNodeEnv))

				// Verify readiness and liveness probes.
				verifyProbesAndLifecycle(ds, false, false)
			})

			DescribeTable("test node probes",
				func(isOpenshift, isEnterprise bool, bgpOption operatorv1.BGPOption) {
					if isOpenshift {
						defaultInstance.KubernetesProvider = operatorv1.ProviderOpenShift
						defaultCNIConfDir, defaultCNIBinDir := render.DefaultCNIDirectories(defaultInstance.KubernetesProvider)
						defaultInstance.CNI.ConfDir, defaultInstance.CNI.BinDir = &defaultCNIConfDir, &defaultCNIBinDir
						cfg.FelixHealthPort = 9199
					}

					if isEnterprise {
						defaultInstance.Variant = operatorv1.CalicoEnterprise
					}

					defaultInstance.CalicoNetwork.BGP = &bgpOption

					component := render.Node(&cfg)
					Expect(component.ResolveImages(nil)).To(BeNil())
					resources, _ := component.Objects()
					dsResource := rtest.GetResource(resources, "calico-node", "calico-system", "apps", "v1", "DaemonSet")
					Expect(dsResource).ToNot(BeNil())

					ds := dsResource.(*appsv1.DaemonSet)
					verifyProbesAndLifecycle(ds, isOpenshift, isEnterprise)
				},

				Entry("k8s Calico OS no BGP", false, false, operatorv1.BGPDisabled),
				Entry("k8s Calico OS w/ BGP", false, false, operatorv1.BGPEnabled),
				Entry("k8s Enterprise no BGP", false, true, operatorv1.BGPDisabled),
				Entry("k8s Enterprise w/ BGP", false, true, operatorv1.BGPEnabled),
				Entry("OCP Calico OS no BGP", true, false, operatorv1.BGPDisabled),
				Entry("OCP Calico OSS w/ BGP", true, false, operatorv1.BGPEnabled),
				Entry("OCP Enterprise no BGP", true, true, operatorv1.BGPDisabled),
				Entry("OCP Enterprise w/ BGP", true, true, operatorv1.BGPEnabled),
			)

			Context("With VPP dataplane", func() {
				It("should set cluster type correctly", func() {
					vpp := operatorv1.LinuxDataplaneVPP
					cfg.Installation.CalicoNetwork.LinuxDataplane = &vpp
					component := render.Node(&cfg)
					Expect(component.ResolveImages(nil)).To(BeNil())
					resources, _ := component.Objects()
					Expect(len(resources)).To(Equal(defaultNumExpectedResources))

					dsResource := rtest.GetResource(resources, "calico-node", "calico-system", "apps", "v1", "DaemonSet")
					ds := dsResource.(*appsv1.DaemonSet)

					Expect(ds.Spec.Template.Spec.Containers[0].Env).To(ContainElement(
						corev1.EnvVar{Name: "CLUSTER_TYPE", Value: "k8s,operator,bgp,vpp"},
					))
				})
			})

			Context("with k8s overrides set", func() {
				It("should override k8s endpoints", func() {
					cfg.K8sServiceEp = k8sapi.ServiceEndpoint{
						Host: "k8shost",
						Port: "1234",
					}
					component := render.Node(&cfg)
					Expect(component.ResolveImages(nil)).To(BeNil())
					resources, _ := component.Objects()
					Expect(len(resources)).To(Equal(defaultNumExpectedResources))

					dsResource := rtest.GetResource(resources, "calico-node", "calico-system", "apps", "v1", "DaemonSet")
					ds := dsResource.(*appsv1.DaemonSet)

					// FIXME update gomega to include ContainElements
					Expect(ds.Spec.Template.Spec.Containers[0].Env).To(ContainElement(
						corev1.EnvVar{Name: "KUBERNETES_SERVICE_HOST", Value: "k8shost"},
					))
					Expect(ds.Spec.Template.Spec.Containers[0].Env).To(ContainElement(
						corev1.EnvVar{Name: "KUBERNETES_SERVICE_PORT", Value: "1234"},
					))

					var cni corev1.Container

					for _, c := range ds.Spec.Template.Spec.InitContainers {
						if c.Name == "install-cni" {
							cni = c
							break
						}
					}
					Expect(cni).NotTo(BeNil())

					Expect(cni.Env).To(ContainElement(
						corev1.EnvVar{Name: "KUBERNETES_SERVICE_HOST", Value: "k8shost"},
					))
					Expect(cni.Env).To(ContainElement(
						corev1.EnvVar{Name: "KUBERNETES_SERVICE_PORT", Value: "1234"},
					))
				})
			})

			It("should render extra resources when certificate management is enabled", func() {
				ca, _ := tls2.MakeCA(rmeta.DefaultOperatorCASignerName())
				cert, _, _ := ca.Config.GetPEMBytes() // create a valid pem block
				cfg.Installation.CertificateManagement = &operatorv1.CertificateManagement{SignerName: "a.b/c", CACert: cert}

				certificateManager, err := certificatemanager.Create(cli, cfg.Installation, clusterDomain, common.OperatorNamespace(), certificatemanager.AllowCACreation())
				Expect(err).NotTo(HaveOccurred())

				cfg.TLS = getTyphaNodeTLS(cli, certificateManager)
				expectedResources := []struct {
					name    string
					ns      string
					group   string
					version string
					kind    string
				}{
					{name: "calico-node", ns: common.CalicoNamespace, group: "", version: "v1", kind: "ServiceAccount"},
					{name: "calico-node", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
					{name: "calico-node", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
					{name: "calico-cni-plugin", ns: common.CalicoNamespace, group: "", version: "v1", kind: "ServiceAccount"},
					{name: "calico-cni-plugin", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
					{name: "calico-cni-plugin", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
					{name: "cni-config", ns: common.CalicoNamespace, group: "", version: "v1", kind: "ConfigMap"},
					{name: common.NodeDaemonSetName, ns: common.CalicoNamespace, group: "apps", version: "v1", kind: "DaemonSet"},
				}

				component := render.Node(&cfg)
				Expect(component.ResolveImages(nil)).To(BeNil())
				resources, _ := component.Objects()

				// Should render the correct resources.
				i := 0
				for _, expectedRes := range expectedResources {
					rtest.ExpectResourceTypeAndObjectMetadata(resources[i], expectedRes.name, expectedRes.ns, expectedRes.group, expectedRes.version, expectedRes.kind)
					i++
				}
				Expect(len(resources)).To(Equal(len(expectedResources)))

				dep := rtest.GetResource(resources, common.NodeDaemonSetName, common.CalicoNamespace, "apps", "v1", "DaemonSet")
				Expect(dep).ToNot(BeNil())
				deploy, ok := dep.(*appsv1.DaemonSet)
				Expect(ok).To(BeTrue())
				verifyInitContainers(deploy, cfg.Installation)
			})

			It("should handle BGP layout", func() {
				cfg.BGPLayouts = &corev1.ConfigMap{Data: map[string]string{"test": "data"}}
				component := render.Node(&cfg)
				resources, _ := component.Objects()

				dep := rtest.GetResource(resources, common.NodeDaemonSetName, common.CalicoNamespace, "apps", "v1", "DaemonSet")
				Expect(dep).ToNot(BeNil())
				deploy, ok := dep.(*appsv1.DaemonSet)
				Expect(ok).To(BeTrue())
				Expect(deploy.Spec.Template.Annotations).To(HaveKey("hash.operator.tigera.io/bgp-layout"))
				Expect(deploy.Spec.Template.Annotations["hash.operator.tigera.io/bgp-layout"]).To(Equal("46aec5c60cd6c6fc95979e247a8370bdb9f23b0f"))
				Expect(deploy.Spec.Template.Spec.Volumes).To(ContainElement(corev1.Volume{
					Name: render.BGPLayoutVolumeName,
					VolumeSource: corev1.VolumeSource{
						ConfigMap: &corev1.ConfigMapVolumeSource{
							LocalObjectReference: corev1.LocalObjectReference{
								Name: render.BGPLayoutConfigMapName,
							},
						},
					},
				}))
				Expect(deploy.Spec.Template.Spec.Containers[0].VolumeMounts).To(ContainElement(corev1.VolumeMount{
					Name:      render.BGPLayoutVolumeName,
					ReadOnly:  true,
					MountPath: render.BGPLayoutPath,
					SubPath:   render.BGPLayoutConfigMapKey,
				}))
				rtest.ExpectEnv(deploy.Spec.Template.Spec.Containers[0].Env, "CALICO_EARLY_NETWORKING", render.BGPLayoutPath)
			})

			Context("With calico-node DaemonSet overrides", func() {
				rr1 := corev1.ResourceRequirements{
					Limits: corev1.ResourceList{
						"cpu":     resource.MustParse("2"),
						"memory":  resource.MustParse("300Mi"),
						"storage": resource.MustParse("20Gi"),
					},
					Requests: corev1.ResourceList{
						"cpu":     resource.MustParse("1"),
						"memory":  resource.MustParse("150Mi"),
						"storage": resource.MustParse("10Gi"),
					},
				}
				rr2 := corev1.ResourceRequirements{
					Requests: corev1.ResourceList{
						corev1.ResourceCPU:    resource.MustParse("250m"),
						corev1.ResourceMemory: resource.MustParse("64Mi"),
					},
					Limits: corev1.ResourceList{
						corev1.ResourceCPU:    resource.MustParse("500m"),
						corev1.ResourceMemory: resource.MustParse("500Mi"),
					},
				}

				It("should handle calicoNodeDaemonSet overrides", func() {
					var minReadySeconds int32 = 20

					affinity := &corev1.Affinity{
						NodeAffinity: &corev1.NodeAffinity{
							RequiredDuringSchedulingIgnoredDuringExecution: &corev1.NodeSelector{
								NodeSelectorTerms: []corev1.NodeSelectorTerm{{
									MatchExpressions: []corev1.NodeSelectorRequirement{{
										Key:      "custom-affinity-key",
										Operator: corev1.NodeSelectorOpExists,
									}},
								}},
							},
						},
					}
					toleration := corev1.Toleration{
						Key:      "foo",
						Operator: corev1.TolerationOpEqual,
						Value:    "bar",
					}

					defaultInstance.CalicoNodeDaemonSet = &operatorv1.CalicoNodeDaemonSet{
						Metadata: &operatorv1.Metadata{
							Labels:      map[string]string{"top-level": "label1"},
							Annotations: map[string]string{"top-level": "annot1"},
						},
						Spec: &operatorv1.CalicoNodeDaemonSetSpec{
							MinReadySeconds: &minReadySeconds,
							Template: &operatorv1.CalicoNodeDaemonSetPodTemplateSpec{
								Metadata: &operatorv1.Metadata{
									Labels:      map[string]string{"template-level": "label2"},
									Annotations: map[string]string{"template-level": "annot2"},
								},
								Spec: &operatorv1.CalicoNodeDaemonSetPodSpec{
									DNSPolicy: ptr.To(corev1.DNSNone),
									DNSConfig: &corev1.PodDNSConfig{
										Nameservers: []string{"5.5.5.5"},
										Searches:    []string{"ns1.svc.cluster.local"},
										Options: []corev1.PodDNSConfigOption{{
											Name:  "ndots",
											Value: ptr.To("2"),
										}},
									},
									Containers: []operatorv1.CalicoNodeDaemonSetContainer{
										{
											Name:      "calico-node",
											Resources: &rr1,
										},
									},
									NodeSelector: map[string]string{
										"custom-node-selector": "value",
									},
									Affinity:    affinity,
									Tolerations: []corev1.Toleration{toleration},
								},
							},
						},
					}

					component := render.Node(&cfg)
					resources, _ := component.Objects()
					dsResource := rtest.GetResource(resources, "calico-node", "calico-system", "apps", "v1", "DaemonSet")
					Expect(dsResource).ToNot(BeNil())

					ds := dsResource.(*appsv1.DaemonSet)

					Expect(ds.Labels).To(HaveLen(1))
					Expect(ds.Labels["top-level"]).To(Equal("label1"))
					Expect(ds.Annotations).To(HaveLen(2))
					Expect(ds.Annotations["top-level"]).To(Equal("annot1"))
					// The render package records the applied resource override in an annotation.
					Expect(ds.Annotations["operator.tigera.io/custom-overrides"]).To(Equal("resources"))

					Expect(ds.Spec.MinReadySeconds).To(Equal(minReadySeconds))

					// At runtime, the operator's setStandardSelectorAndLabels helper
					// adds standard labels such as "k8s-app=calico-node" and the
					// host-networked marker. The daemonset object produced by the
					// render itself only carries the override-supplied template-level
					// label; the rest are layered on during apply.
					Expect(ds.Spec.Template.Labels).To(HaveLen(1))
					Expect(ds.Spec.Template.Labels["template-level"]).To(Equal("label2"))

					// With the default instance we expect 3 template-level annotations
					// - 2 added by the operator by default
					// - 1 added by the calicoNodeDaemonSet override
					Expect(ds.Spec.Template.Annotations).To(HaveLen(3))
					Expect(ds.Spec.Template.Annotations).To(HaveKey("tigera-operator.hash.operator.tigera.io/tigera-ca-private"))
					Expect(ds.Spec.Template.Annotations).To(HaveKey("hash.operator.tigera.io/cni-config"))
					Expect(ds.Spec.Template.Annotations["template-level"]).To(Equal("annot2"))

					Expect(ds.Spec.Template.Spec.Containers).To(HaveLen(1))
					Expect(ds.Spec.Template.Spec.Containers[0].Resources).To(Equal(rr1))

					Expect(ds.Spec.Template.Spec.NodeSelector).To(HaveLen(1))
					Expect(ds.Spec.Template.Spec.NodeSelector).To(HaveKeyWithValue("custom-node-selector", "value"))

					Expect(ds.Spec.Template.Spec.Tolerations).To(HaveLen(1))
					Expect(ds.Spec.Template.Spec.Tolerations[0]).To(Equal(toleration))

					// Verify DNS policy and config.
					Expect(ds.Spec.Template.Spec.DNSPolicy).To(Equal(corev1.DNSNone))
					Expect(ds.Spec.Template.Spec.DNSConfig).ToNot(BeNil())
					Expect(ds.Spec.Template.Spec.DNSConfig.Nameservers).To(HaveLen(1))
					Expect(ds.Spec.Template.Spec.DNSConfig.Nameservers[0]).To(Equal("5.5.5.5"))
					Expect(ds.Spec.Template.Spec.DNSConfig.Searches).To(HaveLen(1))
					Expect(ds.Spec.Template.Spec.DNSConfig.Searches[0]).To(Equal("ns1.svc.cluster.local"))
					Expect(ds.Spec.Template.Spec.DNSConfig.Options).To(HaveLen(1))
					Expect(ds.Spec.Template.Spec.DNSConfig.Options[0].Name).To(Equal("ndots"))
					Expect(*ds.Spec.Template.Spec.DNSConfig.Options[0].Value).To(Equal("2"))
				})

				It("should override ComponentResources", func() {
					defaultInstance.ComponentResources = []operatorv1.ComponentResource{
						{
							ComponentName:        operatorv1.ComponentNameNode,
							ResourceRequirements: &rr1,
						},
					}

					defaultInstance.CalicoNodeDaemonSet = &operatorv1.CalicoNodeDaemonSet{
						Spec: &operatorv1.CalicoNodeDaemonSetSpec{
							Template: &operatorv1.CalicoNodeDaemonSetPodTemplateSpec{
								Spec: &operatorv1.CalicoNodeDaemonSetPodSpec{
									Containers: []operatorv1.CalicoNodeDaemonSetContainer{
										{
											Name:      "calico-node",
											Resources: &rr2,
										},
									},
								},
							},
						},
					}

					component := render.Node(&cfg)
					resources, _ := component.Objects()
					dsResource := rtest.GetResource(resources, "calico-node", "calico-system", "apps", "v1", "DaemonSet")
					Expect(dsResource).ToNot(BeNil())

					ds := dsResource.(*appsv1.DaemonSet)
					Expect(ds.Spec.Template.Spec.Containers).To(HaveLen(1))
					Expect(ds.Spec.Template.Spec.Containers[0].Resources).To(Equal(rr2))
				})
			})
		})
	}
})

// verifyProbesAndLifecycle asserts the expected node liveness and readiness probe plus pod lifecycle settings.
func verifyProbesAndLifecycle(ds *appsv1.DaemonSet, isOpenshift, isEnterprise bool) {
	// Verify readiness and liveness probes.
	expectedReadiness := &corev1.Probe{
		PeriodSeconds:  10,
		TimeoutSeconds: 5,
	}
	expectedLiveness := &corev1.Probe{
		ProbeHandler: corev1.ProbeHandler{
			HTTPGet: &corev1.HTTPGetAction{
				Host: "localhost",
				Path: "/liveness",
				Port: intstr.FromInt(9099),
			},
		},
		TimeoutSeconds: 10,
	}

	if isOpenshift {
		expectedLiveness.HTTPGet.Port = intstr.FromInt(9199)
	}

	var found bool
	var bgp bool
	for _, env := range ds.Spec.Template.Spec.Containers[0].Env {
		if env.Name == "CLUSTER_TYPE" {
			if strings.Contains(env.Value, ",bgp") {
				bgp = true
			}
			found = true
			break
		}
	}
	ExpectWithOffset(1, found).To(BeTrue())

	var expectedReadinessCmd []string
	switch {
	case !bgp:
		expectedReadinessCmd = []string{"/usr/bin/calico", "component", "node", "health", "--felix-ready"}
	case bgp && isEnterprise:
		expectedReadinessCmd = []string{"/usr/bin/calico", "component", "node", "health", "--bird-ready", "--felix-ready", "--bgp-metrics-ready"}
	case bgp:
		expectedReadinessCmd = []string{"/usr/bin/calico", "component", "node", "health", "--bird-ready", "--felix-ready"}
	}
	expectedReadiness.ProbeHandler = corev1.ProbeHandler{Exec: &corev1.ExecAction{Command: expectedReadinessCmd}}

	ExpectWithOffset(1, ds.Spec.Template.Spec.Containers[0].ReadinessProbe).To(Equal(expectedReadiness))
	ExpectWithOffset(1, ds.Spec.Template.Spec.Containers[0].LivenessProbe).To(Equal(expectedLiveness))

	expectedLifecycle := &corev1.Lifecycle{
		PreStop: &corev1.LifecycleHandler{Exec: &corev1.ExecAction{
			Command: []string{"/usr/bin/calico", "component", "node", "shutdown"},
		}},
	}
	ExpectWithOffset(1, ds.Spec.Template.Spec.Containers[0].Lifecycle).To(Equal(expectedLifecycle))

	ExpectWithOffset(1, int(*ds.Spec.Template.Spec.TerminationGracePeriodSeconds)).To(Equal(5))
}

// configureExpectedNodeEnvIPVersions is a helper function to configure the right expected calico-node env var values based on if IPv4 and/or IPv6 are enabled
func configureExpectedNodeEnvIPVersions(expectedNodeEnv []corev1.EnvVar, defaultInstance *operatorv1.InstallationSpec, enableIPv4, enableIPv6 bool) []corev1.EnvVar {
	if enableIPv4 {
		expectedNodeEnv = append(expectedNodeEnv, []corev1.EnvVar{
			{Name: "IP", Value: "autodetect"},
			{Name: "IP_AUTODETECTION_METHOD", Value: "first-found"},
		}...)
	} else {
		expectedNodeEnv = append(expectedNodeEnv, corev1.EnvVar{Name: "IP", Value: "none"})
	}

	if enableIPv6 {
		expectedNodeEnv = append(expectedNodeEnv, []corev1.EnvVar{
			{Name: "FELIX_IPV6SUPPORT", Value: "true"},
			{Name: "IP6", Value: "autodetect"},
			{Name: "IP6_AUTODETECTION_METHOD", Value: "first-found"},
		}...)
		if !enableIPv4 && defaultInstance.CalicoNetwork.BGP == &bgpEnabled {
			expectedNodeEnv = append(expectedNodeEnv, corev1.EnvVar{Name: "CALICO_ROUTER_ID", Value: "hash"})
		}
	} else {
		expectedNodeEnv = append(expectedNodeEnv, []corev1.EnvVar{
			{Name: "FELIX_IPV6SUPPORT", Value: "false"},
			{Name: "IP6", Value: "none"},
		}...)
	}

	return expectedNodeEnv
}

func verifyInitContainers(ds *appsv1.DaemonSet, instance *operatorv1.InstallationSpec) {
	// Validate correct number of init containers.
	numInitContainers := 1
	isCalicoCNI := instance.CNI != nil && instance.CNI.Type == operatorv1.PluginCalico
	// Default to InstallMode=All when unset.
	installUpstreamPlugins := isCalicoCNI &&
		(instance.CNI.InstallMode == nil || *instance.CNI.InstallMode != operatorv1.CNIInstallModeCalicoOnly)
	if isCalicoCNI {
		numInitContainers++
	}
	if installUpstreamPlugins {
		numInitContainers++
	}
	// Certificate management adds an additional key/cert init container.
	if instance.CertificateManagement != nil {
		numInitContainers++
	}
	// FlexVolume adds an additional FlexVolume init container.
	if instance.FlexVolumePath != "None" {
		numInitContainers++
	}
	Expect(ds.Spec.Template.Spec.InitContainers).To(HaveLen(numInitContainers))

	// Verify the key/cert init container is correct when certificate management is enabled.
	if instance.CertificateManagement != nil {
		certInit := rtest.GetContainer(ds.Spec.Template.Spec.InitContainers, fmt.Sprintf("%s-key-cert-provisioner", render.NodeTLSSecretName))
		Expect(certInit).NotTo(BeNil())
		rtest.ExpectEnv(certInit.Env, "SIGNER", instance.CertificateManagement.SignerName)
	}

	// Verify the CNI install container is correct when using Calico CNI.
	cniContainer := rtest.GetContainer(ds.Spec.Template.Spec.InitContainers, "install-cni")
	if isCalicoCNI {
		Expect(cniContainer).NotTo(BeNil())
		rtest.ExpectEnv(cniContainer.Env, "CNI_CONF_NAME", "10-calico.conflist")
		rtest.ExpectEnv(cniContainer.Env, "SLEEP", "false")
		cniImage := fmt.Sprintf("quay.io/%s%s:%s", components.CalicoImagePath, components.ComponentCalico.Image, components.ComponentCalico.Version)
		if instance.Variant.IsEnterprise() {
			cniImage = fmt.Sprintf("%s%s%s:%s", components.TigeraRegistry, components.TigeraImagePath, components.ComponentTigeraCalico.Image, components.ComponentTigeraCalico.Version)
		}
		Expect(cniContainer.Image).To(Equal(cniImage))
		Expect(cniContainer.Command).To(Equal([]string{"/usr/bin/calico", "component", "cni", "install"}))
		Expect(*cniContainer.SecurityContext.AllowPrivilegeEscalation).To(BeTrue())
		Expect(*cniContainer.SecurityContext.Privileged).To(BeTrue())
		Expect(*cniContainer.SecurityContext.RunAsGroup).To(BeEquivalentTo(0))
		Expect(*cniContainer.SecurityContext.RunAsNonRoot).To(BeFalse())
		Expect(*cniContainer.SecurityContext.RunAsUser).To(BeEquivalentTo(0))
		Expect(cniContainer.SecurityContext.Capabilities).To(Equal(
			&corev1.Capabilities{
				Drop: []corev1.Capability{"ALL"},
			},
		))
		Expect(cniContainer.SecurityContext.SeccompProfile).To(Equal(
			&corev1.SeccompProfile{
				Type: corev1.SeccompProfileTypeRuntimeDefault,
			}))
		expectedCNIEnv := []corev1.EnvVar{
			{Name: "CNI_CONF_NAME", Value: "10-calico.conflist"},
			{Name: "SLEEP", Value: "false"},
			{Name: "CNI_NET_DIR", Value: *instance.CNI.ConfDir},
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
		if instance.Variant.IsEnterprise() {
			if instance.CalicoNetwork != nil && instance.CalicoNetwork.MultiInterfaceMode != nil {
				expectedCNIEnv = append(expectedCNIEnv, corev1.EnvVar{Name: "MULTI_INTERFACE_MODE", Value: instance.CalicoNetwork.MultiInterfaceMode.Value()})
			}
		}
		Expect(cniContainer.Env).To(ConsistOf(expectedCNIEnv))
		expectedCNIVolumeMounts := []corev1.VolumeMount{
			{MountPath: "/host/opt/cni/bin", Name: "cni-bin-dir"},
			{MountPath: "/host/etc/cni/net.d", Name: "cni-net-dir"},
		}
		if installUpstreamPlugins {
			expectedCNIVolumeMounts = append(expectedCNIVolumeMounts, corev1.VolumeMount{MountPath: "/opt/cni/bin", Name: "cni-plugins-stage"})
		}
		Expect(cniContainer.VolumeMounts).To(ConsistOf(expectedCNIVolumeMounts))
	} else {
		Expect(cniContainer).To(BeNil())
	}

	// Verify the cni-plugins init container is present and runs before
	// install-cni when using Calico CNI with the default InstallMode.
	cniPluginsContainer := rtest.GetContainer(ds.Spec.Template.Spec.InitContainers, "cni-plugins")
	if installUpstreamPlugins {
		Expect(cniPluginsContainer).NotTo(BeNil())
		expectedImage := fmt.Sprintf("quay.io/%s%s:%s", components.CalicoImagePath, components.ComponentCalicoCNIPlugins.Image, components.ComponentCalicoCNIPlugins.Version)
		if instance.Variant.IsEnterprise() {
			expectedImage = fmt.Sprintf("%s%s%s:%s", components.TigeraRegistry, components.TigeraImagePath, components.ComponentTigeraCNIPlugins.Image, components.ComponentTigeraCNIPlugins.Version)
		}
		Expect(cniPluginsContainer.Image).To(Equal(expectedImage))
		Expect(cniPluginsContainer.VolumeMounts).To(ConsistOf([]corev1.VolumeMount{
			{MountPath: "/stage", Name: "cni-plugins-stage"},
		}))
		// cni-plugins must come before install-cni so it populates the staging
		// volume before install-cni reads from it.
		var pluginsIdx, installIdx = -1, -1
		for i, ic := range ds.Spec.Template.Spec.InitContainers {
			switch ic.Name {
			case "cni-plugins":
				pluginsIdx = i
			case "install-cni":
				installIdx = i
			}
		}
		Expect(pluginsIdx).To(BeNumerically(">=", 0))
		Expect(installIdx).To(BeNumerically(">=", 0))
		Expect(pluginsIdx).To(BeNumerically("<", installIdx))
	} else {
		Expect(cniPluginsContainer).To(BeNil())
	}

	// Verify the ebpf-bootstrap container image and security context.
	ebpfBootstrap := rtest.GetContainer(ds.Spec.Template.Spec.InitContainers, "ebpf-bootstrap")
	Expect(ebpfBootstrap).NotTo(BeNil())
	ebpfImage := fmt.Sprintf("quay.io/%s%s:%s", components.CalicoImagePath, components.ComponentCalicoNode.Image, components.ComponentCalicoNode.Version)
	if instance.Variant.IsEnterprise() {
		ebpfImage = components.TigeraRegistry + "tigera/node:" + components.ComponentTigeraNode.Version
	}
	Expect(ebpfBootstrap.Image).To(Equal(ebpfImage))
	if instance.CalicoNetwork != nil {
		bpf := instance.CalicoNetwork.LinuxDataplane != nil && *instance.CalicoNetwork.LinuxDataplane == operatorv1.LinuxDataplaneBPF
		expectedEbpfCmd := []string{"/usr/bin/calico", "component", "node", "init"}
		if !bpf {
			expectedEbpfCmd = append(expectedEbpfCmd, "--best-effort")
		}
		Expect(ebpfBootstrap.Command).To(Equal(expectedEbpfCmd))
	}
	Expect(*ebpfBootstrap.SecurityContext.AllowPrivilegeEscalation).To(BeTrue())
	Expect(*ebpfBootstrap.SecurityContext.Privileged).To(BeTrue())
	Expect(*ebpfBootstrap.SecurityContext.RunAsGroup).To(BeEquivalentTo(0))
	Expect(*ebpfBootstrap.SecurityContext.RunAsNonRoot).To(BeFalse())
	Expect(*ebpfBootstrap.SecurityContext.RunAsUser).To(BeEquivalentTo(0))
	Expect(ebpfBootstrap.SecurityContext.Capabilities).To(Equal(
		&corev1.Capabilities{
			Drop: []corev1.Capability{"ALL"},
		},
	))
	Expect(ebpfBootstrap.SecurityContext.SeccompProfile).To(Equal(
		&corev1.SeccompProfile{
			Type: corev1.SeccompProfileTypeRuntimeDefault,
		}))

	// Verify the Flex volume container image.
	flexvolContainer := rtest.GetContainer(ds.Spec.Template.Spec.InitContainers, "flexvol-driver")
	if instance.FlexVolumePath != "None" {
		Expect(flexvolContainer).NotTo(BeNil())
		if instance.Variant.IsEnterprise() {
			Expect(flexvolContainer.Image).To(Equal(fmt.Sprintf("%s%s%s:%s", components.TigeraRegistry, components.TigeraImagePath, components.ComponentTigeraCalico.Image, components.ComponentTigeraCalico.Version)))
		} else {
			Expect(flexvolContainer.Image).To(Equal(fmt.Sprintf("quay.io/%s%s:%s", components.CalicoImagePath, components.ComponentCalico.Image, components.ComponentCalico.Version)))
		}
		Expect(flexvolContainer.Command).To(Equal([]string{"/usr/bin/calico", "component", "flexvol", "install", "--target", "/host/driver/uds"}))

		Expect(*flexvolContainer.SecurityContext.AllowPrivilegeEscalation).To(BeTrue())
		Expect(*flexvolContainer.SecurityContext.Privileged).To(BeTrue())
		Expect(*flexvolContainer.SecurityContext.RunAsGroup).To(BeEquivalentTo(0))
		Expect(*flexvolContainer.SecurityContext.RunAsNonRoot).To(BeFalse())
		Expect(*flexvolContainer.SecurityContext.RunAsUser).To(BeEquivalentTo(0))
		Expect(flexvolContainer.SecurityContext.Capabilities).To(Equal(
			&corev1.Capabilities{
				Drop: []corev1.Capability{"ALL"},
			},
		))
		Expect(flexvolContainer.SecurityContext.SeccompProfile).To(Equal(
			&corev1.SeccompProfile{
				Type: corev1.SeccompProfileTypeRuntimeDefault,
			}))
	} else {
		Expect(flexvolContainer).To(BeNil())
	}
}
