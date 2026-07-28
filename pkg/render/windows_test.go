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

package render_test

import (
	"fmt"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/onsi/gomega/gstruct"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/intstr"
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
	"github.com/tigera/operator/pkg/tls/certificatemanagement"
)

var _ = Describe("Windows rendering tests", func() {
	var defaultInstance *operatorv1.InstallationSpec
	var typhaNodeTLS *render.TyphaNodeTLS
	var k8sServiceEp k8sapi.ServiceEndpoint
	one := intstr.FromInt(1)
	defaultNumExpectedResources := 2
	const defaultClusterDomain = "svc.cluster.local"
	var defaultMode int32 = 420
	var cfg render.WindowsConfiguration
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
			WindowsNodes: &operatorv1.WindowsNodeSpec{
				CNIBinDir:    "/opt/cni/bin",
				CNIConfigDir: "/etc/cni/net.d",
				CNILogDir:    "/var/log/calico/cni",
			},
		}
		defaultInstance.CalicoNetwork.IPPools = append(defaultInstance.CalicoNetwork.IPPools, operatorv1.IPPool{CIDR: "192.168.1.0/16", Encapsulation: operatorv1.EncapsulationVXLAN})
		defaultInstance.CalicoNetwork.NodeAddressAutodetectionV4 = &operatorv1.NodeAddressAutodetection{FirstFound: &ff}
		defaultInstance.ServiceCIDRs = []string{"10.96.0.0/12"}
		scheme := runtime.NewScheme()
		Expect(apis.AddToScheme(scheme, false)).NotTo(HaveOccurred())
		cli = ctrlrfake.DefaultFakeClientBuilder(scheme).Build()
		certificateManager, err := certificatemanager.Create(cli, nil, clusterDomain, common.OperatorNamespace(), certificatemanager.AllowCACreation())
		Expect(err).NotTo(HaveOccurred())
		// Create a dummy secret to pass as input.
		typhaNodeTLS = getTyphaNodeTLS(cli, certificateManager)

		// Dummy service endpoint for k8s API.
		k8sServiceEp = k8sapi.ServiceEndpoint{
			Host: "1.2.3.4",
			Port: "6443",
		}

		// Create a default configuration.
		cfg = render.WindowsConfiguration{
			K8sServiceEp:  k8sServiceEp,
			K8sDNSServers: []string{"10.96.0.10"},
			Installation:  defaultInstance,
			ClusterDomain: defaultClusterDomain,
			TLS:           typhaNodeTLS,
			VXLANVNI:      4096,
		}
	})

	It("should render all resources for a default configuration", func() {
		type testConf struct {
			EnableBGP   bool
			EnableVXLAN bool
		}
		for _, testConfig := range []testConf{
			{true, false},
			{false, true},
			{true, true},
		} {
			enableBGP := testConfig.EnableBGP
			enableVXLAN := testConfig.EnableVXLAN

			if enableBGP {
				defaultInstance.CalicoNetwork.BGP = &bgpEnabled
			} else {
				defaultInstance.CalicoNetwork.BGP = &bgpDisabled
			}

			if enableVXLAN {
				defaultInstance.CalicoNetwork.IPPools[0].Encapsulation = operatorv1.EncapsulationVXLAN
			} else {
				defaultInstance.CalicoNetwork.IPPools[0].Encapsulation = operatorv1.EncapsulationNone
			}
			By(fmt.Sprintf("BGP enabled: %v, VXLAN enabled: %v", enableBGP, enableVXLAN), func() {
				expectedResources := []struct {
					name    string
					ns      string
					group   string
					version string
					kind    string
				}{
					{name: "cni-config-windows", ns: common.CalicoNamespace, group: "", version: "v1", kind: "ConfigMap"},
					{name: common.WindowsDaemonSetName, ns: common.CalicoNamespace, group: "apps", version: "v1", kind: "DaemonSet"},
				}

				component := render.Windows(&cfg)
				Expect(component.ResolveImages(nil)).To(BeNil())
				resources, _ := component.Objects()
				Expect(len(resources)).To(Equal(len(expectedResources)))

				// Should render the correct resources.
				i := 0
				for _, expectedRes := range expectedResources {
					rtest.ExpectResourceTypeAndObjectMetadata(resources[i], expectedRes.name, expectedRes.ns, expectedRes.group, expectedRes.version, expectedRes.kind)
					i++
				}

				// Check CNI configmap.
				cniCmResource := rtest.GetResource(resources, "cni-config-windows", "calico-system", "", "v1", "ConfigMap")
				Expect(cniCmResource).ToNot(BeNil())
				cniCm := cniCmResource.(*corev1.ConfigMap)
				mode := "none"
				if enableBGP {
					mode = "windows-bgp"
				} else if enableVXLAN {
					mode = "vxlan"
				}
				Expect(cniCm.Data["config"]).To(MatchJSON(fmt.Sprintf(`{
"name": "Calico",
"cniVersion": "1.0.0",
"plugins": [
  {
	"DNS": {
      "Nameservers": [
	    "10.96.0.10"
	  ],
	  "Search": [
		"svc.cluster.local"
	  ]
	},
	"capabilities": {
	  "dns": true
	},
	"datastore_type": "kubernetes",
	"ipam": {
	  "subnet": "usePodCidr",
	  "type": "calico-ipam"
	},
	"kubernetes": {
	  "k8s_api_root": "https://1.2.3.4:6443",
	  "kubeconfig": "c:/etc/cni/net.d/calico-kubeconfig"
	},
	"log_file_max_age": 5,
	"log_file_max_count": 5,
	"log_file_max_size": 1,
	"log_file_path": "c:/var/log/calico/cni/cni.log",
	"log_level": "Debug",
	"mode": "%s",
	"mtu": 0,
	"name": "Calico",
	"nodename": "__KUBERNETES_NODE_NAME__",
	"nodename_file": "__NODENAME_FILE__",
	"nodename_file_optional": true,
	"policies": [
	  {
		"Name": "EndpointPolicy",
		"Value": {
		  "ExceptionList": [
			"10.96.0.0/12"
		  ],
		  "Type": "OutBoundNAT"
		}
	  },
	  {
		"Name": "EndpointPolicy",
		"Value": {
		  "DestinationPrefix": "10.96.0.0/12",
		  "NeedEncap": true,
		  "Type": "SDNROUTE"
		}
	  }
	],
	"policy": {
	  "type": "k8s"
	},
	"type": "calico",
	"vxlan_mac_prefix": "0E-2A",
	"vxlan_vni": 4096,
	"windows_loopback_DSR": "__DSR_SUPPORT__",
	"windows_use_single_network": true
  }
]
}`, mode)))

				dsResource := rtest.GetResource(resources, "calico-node-windows", "calico-system", "apps", "v1", "DaemonSet")
				Expect(dsResource).ToNot(BeNil())

				// The DaemonSet should have the correct configuration.
				ds := dsResource.(*appsv1.DaemonSet)

				// The pod template should have node critical priority
				Expect(ds.Spec.Template.Spec.PriorityClassName).To(Equal(render.NodePriorityClassName))

				// The calico-node-windows daemonset has 3 containers (felix, node and confd).
				// confd is only instantiated if using BGP.
				numContainers := 3
				if !enableBGP {
					numContainers = 2
				}
				Expect(ds.Spec.Template.Spec.Containers).To(HaveLen(numContainers))
				for _, container := range ds.Spec.Template.Spec.Containers {
					// Windows node image override results in correct image.
					Expect(container.Image).To(Equal(fmt.Sprintf("quay.io/%s%s:%s", components.CalicoImagePath, components.ComponentCalicoNodeWindows.Image, components.ComponentCalicoNodeWindows.Version)))
					Expect(container.SecurityContext.Capabilities).To(BeNil())
					Expect(container.SecurityContext.Privileged).To(BeNil())
					Expect(container.SecurityContext.SELinuxOptions).To(BeNil())
					Expect(container.SecurityContext.WindowsOptions).To(Not(BeNil()))
					Expect(container.SecurityContext.WindowsOptions.GMSACredentialSpecName).To(BeNil())
					Expect(container.SecurityContext.WindowsOptions.GMSACredentialSpec).To(BeNil())
					Expect(*container.SecurityContext.WindowsOptions.RunAsUserName).To(Equal("NT AUTHORITY\\system"))
					Expect(*container.SecurityContext.WindowsOptions.HostProcess).To(BeTrue())
					Expect(container.SecurityContext.RunAsUser).To(BeNil())
					Expect(container.SecurityContext.RunAsGroup).To(BeNil())
					Expect(container.SecurityContext.RunAsNonRoot).To(BeNil())
					Expect(container.SecurityContext.ReadOnlyRootFilesystem).To(BeNil())
					Expect(container.SecurityContext.AllowPrivilegeEscalation).To(BeNil())
					Expect(container.SecurityContext.ProcMount).To(BeNil())
					Expect(container.SecurityContext.SeccompProfile).To(BeNil())
				}

				felixContainer := rtest.GetContainer(ds.Spec.Template.Spec.Containers, "felix")

				// Windows node image override results in correct image.
				Expect(felixContainer.Image).To(Equal(fmt.Sprintf("quay.io/%s%s:%s", components.CalicoImagePath, components.ComponentCalicoNodeWindows.Image, components.ComponentCalicoNodeWindows.Version)))
				Expect(felixContainer.SecurityContext.Capabilities).To(BeNil())
				Expect(felixContainer.SecurityContext.Privileged).To(BeNil())
				Expect(felixContainer.SecurityContext.SELinuxOptions).To(BeNil())
				Expect(felixContainer.SecurityContext.WindowsOptions).To(Not(BeNil()))
				Expect(felixContainer.SecurityContext.WindowsOptions.GMSACredentialSpecName).To(BeNil())
				Expect(felixContainer.SecurityContext.WindowsOptions.GMSACredentialSpec).To(BeNil())
				Expect(*felixContainer.SecurityContext.WindowsOptions.RunAsUserName).To(Equal("NT AUTHORITY\\system"))
				Expect(*felixContainer.SecurityContext.WindowsOptions.HostProcess).To(BeTrue())
				Expect(felixContainer.SecurityContext.RunAsUser).To(BeNil())
				Expect(felixContainer.SecurityContext.RunAsGroup).To(BeNil())
				Expect(felixContainer.SecurityContext.RunAsNonRoot).To(BeNil())
				Expect(felixContainer.SecurityContext.ReadOnlyRootFilesystem).To(BeNil())
				Expect(felixContainer.SecurityContext.AllowPrivilegeEscalation).To(BeNil())
				Expect(felixContainer.SecurityContext.ProcMount).To(BeNil())
				Expect(felixContainer.SecurityContext.SeccompProfile).To(BeNil())

				nodeContainer := rtest.GetContainer(ds.Spec.Template.Spec.Containers, "node")

				// Windows node image override results in correct image.
				Expect(nodeContainer.Image).To(Equal(fmt.Sprintf("quay.io/%s%s:%s", components.CalicoImagePath, components.ComponentCalicoNodeWindows.Image, components.ComponentCalicoNodeWindows.Version)))
				Expect(nodeContainer.SecurityContext.Capabilities).To(BeNil())
				Expect(nodeContainer.SecurityContext.Privileged).To(BeNil())
				Expect(nodeContainer.SecurityContext.SELinuxOptions).To(BeNil())
				Expect(nodeContainer.SecurityContext.WindowsOptions).To(Not(BeNil()))
				Expect(nodeContainer.SecurityContext.WindowsOptions.GMSACredentialSpecName).To(BeNil())
				Expect(nodeContainer.SecurityContext.WindowsOptions.GMSACredentialSpec).To(BeNil())
				Expect(*nodeContainer.SecurityContext.WindowsOptions.RunAsUserName).To(Equal("NT AUTHORITY\\system"))
				Expect(*nodeContainer.SecurityContext.WindowsOptions.HostProcess).To(BeTrue())
				Expect(nodeContainer.SecurityContext.RunAsUser).To(BeNil())
				Expect(nodeContainer.SecurityContext.RunAsGroup).To(BeNil())
				Expect(nodeContainer.SecurityContext.RunAsNonRoot).To(BeNil())
				Expect(nodeContainer.SecurityContext.ReadOnlyRootFilesystem).To(BeNil())
				Expect(nodeContainer.SecurityContext.AllowPrivilegeEscalation).To(BeNil())
				Expect(nodeContainer.SecurityContext.ProcMount).To(BeNil())
				Expect(nodeContainer.SecurityContext.SeccompProfile).To(BeNil())

				if enableBGP {
					confdContainer := rtest.GetContainer(ds.Spec.Template.Spec.Containers, "confd")

					// Windows node image override results in correct image.
					Expect(confdContainer.Image).To(Equal(fmt.Sprintf("quay.io/%s%s:%s", components.CalicoImagePath, components.ComponentCalicoNodeWindows.Image, components.ComponentCalicoNodeWindows.Version)))
					Expect(confdContainer.SecurityContext.Capabilities).To(BeNil())
					Expect(confdContainer.SecurityContext.Privileged).To(BeNil())
					Expect(confdContainer.SecurityContext.SELinuxOptions).To(BeNil())
					Expect(confdContainer.SecurityContext.WindowsOptions).To(Not(BeNil()))
					Expect(confdContainer.SecurityContext.WindowsOptions.GMSACredentialSpecName).To(BeNil())
					Expect(confdContainer.SecurityContext.WindowsOptions.GMSACredentialSpec).To(BeNil())
					Expect(*confdContainer.SecurityContext.WindowsOptions.RunAsUserName).To(Equal("NT AUTHORITY\\system"))
					Expect(*confdContainer.SecurityContext.WindowsOptions.HostProcess).To(BeTrue())
					Expect(confdContainer.SecurityContext.RunAsUser).To(BeNil())
					Expect(confdContainer.SecurityContext.RunAsGroup).To(BeNil())
					Expect(confdContainer.SecurityContext.RunAsNonRoot).To(BeNil())
					Expect(confdContainer.SecurityContext.ReadOnlyRootFilesystem).To(BeNil())
					Expect(confdContainer.SecurityContext.AllowPrivilegeEscalation).To(BeNil())
					Expect(confdContainer.SecurityContext.ProcMount).To(BeNil())
					Expect(confdContainer.SecurityContext.SeccompProfile).To(BeNil())
				}

				// Validate correct number of init containers.
				Expect(ds.Spec.Template.Spec.InitContainers).To(HaveLen(2))

				// CNI container uses image override.
				cniContainer := rtest.GetContainer(ds.Spec.Template.Spec.InitContainers, "install-cni")
				rtest.ExpectEnv(cniContainer.Env, "CNI_NET_DIR", "/etc/cni/net.d")
				Expect(cniContainer.Image).To(Equal(fmt.Sprintf("quay.io/%s%s:%s", components.CalicoImagePath, components.ComponentCalicoCNIWindows.Image, components.ComponentCalicoCNIWindows.Version)))

				Expect(cniContainer.SecurityContext.Capabilities).To(BeNil())
				Expect(cniContainer.SecurityContext.Privileged).To(BeNil())
				Expect(cniContainer.SecurityContext.SELinuxOptions).To(BeNil())
				Expect(cniContainer.SecurityContext.WindowsOptions).To(Not(BeNil()))
				Expect(cniContainer.SecurityContext.WindowsOptions.GMSACredentialSpecName).To(BeNil())
				Expect(cniContainer.SecurityContext.WindowsOptions.GMSACredentialSpec).To(BeNil())
				Expect(*cniContainer.SecurityContext.WindowsOptions.RunAsUserName).To(Equal("NT AUTHORITY\\system"))
				Expect(*cniContainer.SecurityContext.WindowsOptions.HostProcess).To(BeTrue())
				Expect(cniContainer.SecurityContext.RunAsUser).To(BeNil())
				Expect(cniContainer.SecurityContext.RunAsGroup).To(BeNil())
				Expect(cniContainer.SecurityContext.RunAsNonRoot).To(BeNil())
				Expect(cniContainer.SecurityContext.ReadOnlyRootFilesystem).To(BeNil())
				Expect(cniContainer.SecurityContext.AllowPrivilegeEscalation).To(BeNil())
				Expect(cniContainer.SecurityContext.ProcMount).To(BeNil())
				Expect(cniContainer.SecurityContext.SeccompProfile).To(BeNil())

				// uninstall container uses image override.
				uninstallContainer := rtest.GetContainer(ds.Spec.Template.Spec.InitContainers, "uninstall-calico")
				Expect(uninstallContainer.Image).To(Equal(fmt.Sprintf("quay.io/%s%s:%s", components.CalicoImagePath, components.ComponentCalicoNodeWindows.Image, components.ComponentCalicoNodeWindows.Version)))

				Expect(uninstallContainer.SecurityContext.Capabilities).To(BeNil())
				Expect(uninstallContainer.SecurityContext.Privileged).To(BeNil())
				Expect(uninstallContainer.SecurityContext.SELinuxOptions).To(BeNil())
				Expect(uninstallContainer.SecurityContext.WindowsOptions).To(Not(BeNil()))
				Expect(uninstallContainer.SecurityContext.WindowsOptions.GMSACredentialSpecName).To(BeNil())
				Expect(uninstallContainer.SecurityContext.WindowsOptions.GMSACredentialSpec).To(BeNil())
				Expect(*uninstallContainer.SecurityContext.WindowsOptions.RunAsUserName).To(Equal("NT AUTHORITY\\system"))
				Expect(*uninstallContainer.SecurityContext.WindowsOptions.HostProcess).To(BeTrue())
				Expect(uninstallContainer.SecurityContext.RunAsUser).To(BeNil())
				Expect(uninstallContainer.SecurityContext.RunAsGroup).To(BeNil())
				Expect(uninstallContainer.SecurityContext.RunAsNonRoot).To(BeNil())
				Expect(uninstallContainer.SecurityContext.ReadOnlyRootFilesystem).To(BeNil())
				Expect(uninstallContainer.SecurityContext.AllowPrivilegeEscalation).To(BeNil())
				Expect(uninstallContainer.SecurityContext.ProcMount).To(BeNil())
				Expect(uninstallContainer.SecurityContext.SeccompProfile).To(BeNil())

				// Verify env
				expectedNodeEnv := []corev1.EnvVar{
					{Name: "CNI_PLUGIN_TYPE", Value: "Calico"},
					{Name: "DATASTORE_TYPE", Value: "kubernetes"},
					{Name: "WAIT_FOR_DATASTORE", Value: "true"},
					{Name: "CALICO_MANAGE_CNI", Value: "true"},
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

					{Name: "IP", Value: "autodetect"},
					{Name: "IP_AUTODETECTION_METHOD", Value: "first-found"},
					{Name: "IP6", Value: "none"},
					{Name: "FELIX_IPV6SUPPORT", Value: "false"},
					{Name: "FELIX_TYPHAK8SNAMESPACE", Value: "calico-system"},
					{Name: "FELIX_TYPHAK8SSERVICENAME", Value: "calico-typha"},
					{Name: "FELIX_TYPHACAFILE", Value: certificatemanagement.TrustedCertBundleMountPath},
					{Name: "FELIX_TYPHACERTFILE", Value: "/node-certs/tls.crt"},
					{Name: "FELIX_TYPHACN", Value: "typha-server"},
					{Name: "FELIX_TYPHAKEYFILE", Value: "/node-certs/tls.key"},

					{Name: "VXLAN_VNI", Value: "4096"},
					{Name: "VXLAN_ADAPTER", Value: ""},
					{Name: "KUBE_NETWORK", Value: "Calico.*"},
					{Name: "KUBERNETES_SERVICE_HOST", Value: "1.2.3.4"},
					{Name: "KUBERNETES_SERVICE_PORT", Value: "6443"},
				}

				// Set CALICO_NETWORKING_BACKEND
				if enableBGP {
					expectedNodeEnv = append(expectedNodeEnv, corev1.EnvVar{Name: "CALICO_NETWORKING_BACKEND", Value: "windows-bgp"})
				} else if enableVXLAN {
					expectedNodeEnv = append(expectedNodeEnv, corev1.EnvVar{Name: "CALICO_NETWORKING_BACKEND", Value: "vxlan"})
				} else {
					expectedNodeEnv = append(expectedNodeEnv, corev1.EnvVar{Name: "CALICO_NETWORKING_BACKEND", Value: "none"})
				}

				// Set CLUSTER_TYPE
				if enableBGP {
					expectedNodeEnv = append(expectedNodeEnv, corev1.EnvVar{Name: "CLUSTER_TYPE", Value: "k8s,operator,bgp,windows"})
				} else {
					expectedNodeEnv = append(expectedNodeEnv, corev1.EnvVar{Name: "CLUSTER_TYPE", Value: "k8s,operator,windows"})
				}

				Expect(rtest.GetContainer(ds.Spec.Template.Spec.Containers, "node").Env).To(ConsistOf(expectedNodeEnv))
				Expect(rtest.GetContainer(ds.Spec.Template.Spec.Containers, "felix").Env).To(ConsistOf(expectedNodeEnv))
				if enableBGP {
					Expect(rtest.GetContainer(ds.Spec.Template.Spec.Containers, "confd").Env).To(ConsistOf(expectedNodeEnv))
				}

				// Expect the SECURITY_GROUP env variables to not be set
				Expect(rtest.GetContainer(ds.Spec.Template.Spec.Containers, "node").Env).NotTo(ContainElement(gstruct.MatchFields(gstruct.IgnoreExtras, gstruct.Fields{"Name": Equal("TIGERA_DEFAULT_SECURITY_GROUPS")})))
				Expect(rtest.GetContainer(ds.Spec.Template.Spec.Containers, "node").Env).NotTo(ContainElement(gstruct.MatchFields(gstruct.IgnoreExtras, gstruct.Fields{"Name": Equal("TIGERA_POD_SECURITY_GROUP")})))
				Expect(rtest.GetContainer(ds.Spec.Template.Spec.Containers, "felix").Env).NotTo(ContainElement(gstruct.MatchFields(gstruct.IgnoreExtras, gstruct.Fields{"Name": Equal("TIGERA_DEFAULT_SECURITY_GROUPS")})))
				Expect(rtest.GetContainer(ds.Spec.Template.Spec.Containers, "felix").Env).NotTo(ContainElement(gstruct.MatchFields(gstruct.IgnoreExtras, gstruct.Fields{"Name": Equal("TIGERA_POD_SECURITY_GROUP")})))
				if enableBGP {
					Expect(rtest.GetContainer(ds.Spec.Template.Spec.Containers, "confd").Env).NotTo(ContainElement(gstruct.MatchFields(gstruct.IgnoreExtras, gstruct.Fields{"Name": Equal("TIGERA_DEFAULT_SECURITY_GROUPS")})))
					Expect(rtest.GetContainer(ds.Spec.Template.Spec.Containers, "confd").Env).NotTo(ContainElement(gstruct.MatchFields(gstruct.IgnoreExtras, gstruct.Fields{"Name": Equal("TIGERA_POD_SECURITY_GROUP")})))
				}

				expectedCNIEnv := []corev1.EnvVar{
					{Name: "SLEEP", Value: "false"},
					{Name: "CNI_PLUGIN_TYPE", Value: "Calico"},
					{Name: "CNI_BIN_DIR", Value: "/host/opt/cni/bin"},
					{Name: "CNI_CONF_NAME", Value: "10-calico.conflist"},
					{Name: "CNI_NET_DIR", Value: "/etc/cni/net.d"},
					{Name: "VXLAN_VNI", Value: "4096"},
					{
						Name:  "KUBERNETES_NODE_NAME",
						Value: "",
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

					{Name: "KUBERNETES_SERVICE_HOST", Value: "1.2.3.4"},
					{Name: "KUBERNETES_SERVICE_PORT", Value: "6443"},
					{Name: "KUBERNETES_SERVICE_CIDRS", Value: "10.96.0.0/12"},
					{Name: "KUBERNETES_DNS_SERVERS", Value: "10.96.0.10"},
				}
				Expect(rtest.GetContainer(ds.Spec.Template.Spec.InitContainers, "install-cni").Env).To(ConsistOf(expectedCNIEnv))

				expectedUninstallEnv := []corev1.EnvVar{
					{Name: "SLEEP", Value: "false"},
					{Name: "CNI_PLUGIN_TYPE", Value: "Calico"},
					{Name: "CNI_BIN_DIR", Value: "/host/opt/cni/bin"},
					{Name: "CNI_CONF_NAME", Value: "10-calico.conflist"},
					{Name: "CNI_NET_DIR", Value: "/host/etc/cni/net.d"},
				}
				Expect(rtest.GetContainer(ds.Spec.Template.Spec.InitContainers, "uninstall-calico").Env).To(ConsistOf(expectedUninstallEnv))

				// Verify volumes.
				fileOrCreate := corev1.HostPathFileOrCreate
				dirOrCreate := corev1.HostPathDirectoryOrCreate
				expectedVols := []corev1.Volume{
					{Name: "lib-modules", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/lib/modules"}}},
					{Name: "var-run-calico", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/var/run/calico", Type: &dirOrCreate}}},
					{Name: "var-lib-calico", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/var/lib/calico", Type: &dirOrCreate}}},
					{Name: "xtables-lock", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/run/xtables.lock", Type: &fileOrCreate}}},
					{Name: "cni-bin-dir", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/opt/cni/bin", Type: &dirOrCreate}}},
					{Name: "cni-net-dir", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/etc/cni/net.d"}}},
					{Name: "cni-log-dir", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/var/log/calico/cni", Type: &dirOrCreate}}},
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
				}
				Expect(ds.Spec.Template.Spec.Volumes).To(ConsistOf(expectedVols))

				// Verify volume mounts.
				expectedNodeVolumeMounts := []corev1.VolumeMount{
					{MountPath: "/host/etc/cni/net.d", Name: "cni-net-dir"},
					{MountPath: "/var/run/calico", Name: "var-run-calico"},
					{MountPath: "/var/lib/calico", Name: "var-lib-calico"},
					{MountPath: "c:/etc/pki/tls/certs", Name: "tigera-ca-bundle", ReadOnly: true},
					{MountPath: "c:/node-certs", Name: render.NodeTLSSecretName, ReadOnly: true},
					{MountPath: "/var/log/calico/cni", Name: "cni-log-dir", ReadOnly: false},
				}
				Expect(rtest.GetContainer(ds.Spec.Template.Spec.Containers, "node").VolumeMounts).To(ConsistOf(expectedNodeVolumeMounts))
				Expect(rtest.GetContainer(ds.Spec.Template.Spec.Containers, "felix").VolumeMounts).To(ConsistOf(expectedNodeVolumeMounts))
				if enableBGP {
					Expect(rtest.GetContainer(ds.Spec.Template.Spec.Containers, "confd").VolumeMounts).To(ConsistOf(expectedNodeVolumeMounts))
				}

				expectedCNIVolumeMounts := []corev1.VolumeMount{
					{MountPath: "/host/opt/cni/bin", Name: "cni-bin-dir"},
					{MountPath: "/host/etc/cni/net.d", Name: "cni-net-dir"},
				}
				Expect(rtest.GetContainer(ds.Spec.Template.Spec.InitContainers, "install-cni").VolumeMounts).To(ConsistOf(expectedCNIVolumeMounts))

				expectedUninstallVolumeMounts := []corev1.VolumeMount{
					{MountPath: "/host/opt/cni/bin", Name: "cni-bin-dir"},
					{MountPath: "/host/etc/cni/net.d", Name: "cni-net-dir"},
				}
				Expect(rtest.GetContainer(ds.Spec.Template.Spec.InitContainers, "uninstall-calico").VolumeMounts).To(ConsistOf(expectedUninstallVolumeMounts))

				// Verify tolerations.
				Expect(ds.Spec.Template.Spec.Tolerations).To(ConsistOf(rmeta.TolerateAll))

				// Verify readiness and liveness probes.
				verifyWindowsProbesAndLifecycle(ds, true)
			})
		}
	})
	It("should properly render an explicitly configured MTU", func() {
		mtu := int32(1450)
		defaultInstance.CalicoNetwork.MTU = &mtu

		component := render.Windows(&cfg)
		Expect(component.ResolveImages(nil)).To(BeNil())
		resources, _ := component.Objects()

		// Make sure the configmap is populated correctly with the MTU.
		cniCmResource := rtest.GetResource(resources, "cni-config-windows", "calico-system", "", "v1", "ConfigMap")
		Expect(cniCmResource).ToNot(BeNil())
		cniCm := cniCmResource.(*corev1.ConfigMap)
		Expect(cniCm.Data["config"]).To(MatchJSON(`{
"name": "Calico",
"cniVersion": "1.0.0",
"plugins": [
  {
	"DNS": {
      "Nameservers": [
	    "10.96.0.10"
	  ],
	  "Search": [
		"svc.cluster.local"
	  ]
	},
	"capabilities": {
	  "dns": true
	},
	"datastore_type": "kubernetes",
	"ipam": {
	  "subnet": "usePodCidr",
	  "type": "calico-ipam"
	},
	"kubernetes": {
	  "k8s_api_root": "https://1.2.3.4:6443",
	  "kubeconfig": "c:/etc/cni/net.d/calico-kubeconfig"
	},
	"log_file_max_age": 5,
	"log_file_max_count": 5,
	"log_file_max_size": 1,
	"log_file_path": "c:/var/log/calico/cni/cni.log",
	"log_level": "Debug",
	"mode": "windows-bgp",
	"mtu": 1450,
	"name": "Calico",
	"nodename": "__KUBERNETES_NODE_NAME__",
	"nodename_file": "__NODENAME_FILE__",
	"nodename_file_optional": true,
	"policies": [
	  {
		"Name": "EndpointPolicy",
		"Value": {
		  "ExceptionList": [
			"10.96.0.0/12"
		  ],
		  "Type": "OutBoundNAT"
		}
	  },
	  {
		"Name": "EndpointPolicy",
		"Value": {
		  "DestinationPrefix": "10.96.0.0/12",
		  "NeedEncap": true,
		  "Type": "SDNROUTE"
		}
	  }
	],
	"policy": {
	  "type": "k8s"
	},
	"type": "calico",
	"vxlan_mac_prefix": "0E-2A",
	"vxlan_vni": 4096,
	"windows_loopback_DSR": "__DSR_SUPPORT__",
	"windows_use_single_network": true
  }
]
}`))

		// Make sure daemonset has the MTU set as well.
		dsResource := rtest.GetResource(resources, "calico-node-windows", "calico-system", "apps", "v1", "DaemonSet")
		Expect(dsResource).ToNot(BeNil())
		ds := dsResource.(*appsv1.DaemonSet)

		// Verify env
		expectedNodeEnv := []corev1.EnvVar{
			{Name: "FELIX_VXLANMTU", Value: "1450"},
			{Name: "FELIX_WIREGUARDMTU", Value: "1450"},
		}
		for _, e := range expectedNodeEnv {
			Expect(rtest.GetContainer(ds.Spec.Template.Spec.Containers, "felix").Env).To(ContainElement(e))
			Expect(rtest.GetContainer(ds.Spec.Template.Spec.Containers, "node").Env).To(ContainElement(e))
			Expect(rtest.GetContainer(ds.Spec.Template.Spec.Containers, "confd").Env).To(ContainElement(e))
		}
	})

	It("should render all resources for a default configuration using CalicoEnterprise", func() {
		type testConf struct {
			EnableBGP   bool
			EnableVXLAN bool
		}
		for _, testConfig := range []testConf{
			{true, false},
			{false, true},
			{true, true},
		} {
			enableBGP := testConfig.EnableBGP
			enableVXLAN := testConfig.EnableVXLAN

			if enableBGP {
				defaultInstance.CalicoNetwork.BGP = &bgpEnabled
			} else {
				defaultInstance.CalicoNetwork.BGP = &bgpDisabled
			}

			if enableVXLAN {
				defaultInstance.CalicoNetwork.IPPools[0].Encapsulation = operatorv1.EncapsulationVXLAN
			} else {
				defaultInstance.CalicoNetwork.IPPools[0].Encapsulation = operatorv1.EncapsulationNone
			}
			By(fmt.Sprintf("BGP enabled: %v, VXLAN enabled: %v", enableBGP, enableVXLAN), func() {
				expectedResources := []struct {
					name    string
					ns      string
					group   string
					version string
					kind    string
				}{
					{name: "calico-node-metrics-windows", ns: "calico-system", group: "", version: "v1", kind: "Service"},
					{name: "cni-config-windows", ns: common.CalicoNamespace, group: "", version: "v1", kind: "ConfigMap"},
					{name: common.WindowsDaemonSetName, ns: common.CalicoNamespace, group: "apps", version: "v1", kind: "DaemonSet"},
				}
				defaultInstance.Variant = operatorv1.CalicoEnterprise
				cfg.NodeReporterMetricsPort = 9081

				component := render.Windows(&cfg)
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
				ds := rtest.GetResource(resources, "calico-node-windows", "calico-system", "apps", "v1", "DaemonSet").(*appsv1.DaemonSet)

				// The pod template should have node critical priority
				Expect(ds.Spec.Template.Spec.PriorityClassName).To(Equal(render.NodePriorityClassName))

				// The calico-node-windows daemonset has 3 containers (felix, node and confd).
				// confd is only instantiated if using BGP.
				numContainers := 3
				if !enableBGP {
					numContainers = 2
				}
				Expect(ds.Spec.Template.Spec.Containers).To(HaveLen(numContainers))
				for _, container := range ds.Spec.Template.Spec.Containers {

					// Windows node image override results in correct image.
					Expect(container.Image).To(Equal(components.TigeraRegistry + "tigera/node-windows:" + components.ComponentTigeraNodeWindows.Version))
					Expect(container.SecurityContext.Capabilities).To(BeNil())
					Expect(container.SecurityContext.Privileged).To(BeNil())
					Expect(container.SecurityContext.SELinuxOptions).To(BeNil())
					Expect(container.SecurityContext.WindowsOptions).To(Not(BeNil()))
					Expect(container.SecurityContext.WindowsOptions.GMSACredentialSpecName).To(BeNil())
					Expect(container.SecurityContext.WindowsOptions.GMSACredentialSpec).To(BeNil())
					Expect(*container.SecurityContext.WindowsOptions.RunAsUserName).To(Equal("NT AUTHORITY\\system"))
					Expect(*container.SecurityContext.WindowsOptions.HostProcess).To(BeTrue())
					Expect(container.SecurityContext.RunAsUser).To(BeNil())
					Expect(container.SecurityContext.RunAsGroup).To(BeNil())
					Expect(container.SecurityContext.RunAsNonRoot).To(BeNil())
					Expect(container.SecurityContext.ReadOnlyRootFilesystem).To(BeNil())
					Expect(container.SecurityContext.AllowPrivilegeEscalation).To(BeNil())
					Expect(container.SecurityContext.ProcMount).To(BeNil())
					Expect(container.SecurityContext.SeccompProfile).To(BeNil())
				}

				felixContainer := rtest.GetContainer(ds.Spec.Template.Spec.Containers, "felix")

				// Windows node image override results in correct image.
				Expect(felixContainer.Image).To(Equal(components.TigeraRegistry + "tigera/node-windows:" + components.ComponentTigeraNodeWindows.Version))
				Expect(felixContainer.SecurityContext.Capabilities).To(BeNil())
				Expect(felixContainer.SecurityContext.Privileged).To(BeNil())
				Expect(felixContainer.SecurityContext.SELinuxOptions).To(BeNil())
				Expect(felixContainer.SecurityContext.WindowsOptions).To(Not(BeNil()))
				Expect(felixContainer.SecurityContext.WindowsOptions.GMSACredentialSpecName).To(BeNil())
				Expect(felixContainer.SecurityContext.WindowsOptions.GMSACredentialSpec).To(BeNil())
				Expect(*felixContainer.SecurityContext.WindowsOptions.RunAsUserName).To(Equal("NT AUTHORITY\\system"))
				Expect(*felixContainer.SecurityContext.WindowsOptions.HostProcess).To(BeTrue())
				Expect(felixContainer.SecurityContext.RunAsUser).To(BeNil())
				Expect(felixContainer.SecurityContext.RunAsGroup).To(BeNil())
				Expect(felixContainer.SecurityContext.RunAsNonRoot).To(BeNil())
				Expect(felixContainer.SecurityContext.ReadOnlyRootFilesystem).To(BeNil())
				Expect(felixContainer.SecurityContext.AllowPrivilegeEscalation).To(BeNil())
				Expect(felixContainer.SecurityContext.ProcMount).To(BeNil())
				Expect(felixContainer.SecurityContext.SeccompProfile).To(BeNil())

				nodeContainer := rtest.GetContainer(ds.Spec.Template.Spec.Containers, "node")

				// Windows node image override results in correct image.
				Expect(nodeContainer.Image).To(Equal(components.TigeraRegistry + "tigera/node-windows:" + components.ComponentTigeraNodeWindows.Version))
				Expect(nodeContainer.SecurityContext.Capabilities).To(BeNil())
				Expect(nodeContainer.SecurityContext.Privileged).To(BeNil())
				Expect(nodeContainer.SecurityContext.SELinuxOptions).To(BeNil())
				Expect(nodeContainer.SecurityContext.WindowsOptions).To(Not(BeNil()))
				Expect(nodeContainer.SecurityContext.WindowsOptions.GMSACredentialSpecName).To(BeNil())
				Expect(nodeContainer.SecurityContext.WindowsOptions.GMSACredentialSpec).To(BeNil())
				Expect(*nodeContainer.SecurityContext.WindowsOptions.RunAsUserName).To(Equal("NT AUTHORITY\\system"))
				Expect(*nodeContainer.SecurityContext.WindowsOptions.HostProcess).To(BeTrue())
				Expect(nodeContainer.SecurityContext.RunAsUser).To(BeNil())
				Expect(nodeContainer.SecurityContext.RunAsGroup).To(BeNil())
				Expect(nodeContainer.SecurityContext.RunAsNonRoot).To(BeNil())
				Expect(nodeContainer.SecurityContext.ReadOnlyRootFilesystem).To(BeNil())
				Expect(nodeContainer.SecurityContext.AllowPrivilegeEscalation).To(BeNil())
				Expect(nodeContainer.SecurityContext.ProcMount).To(BeNil())
				Expect(nodeContainer.SecurityContext.SeccompProfile).To(BeNil())

				if enableBGP {
					confdContainer := rtest.GetContainer(ds.Spec.Template.Spec.Containers, "confd")

					// Windows node image override results in correct image.
					Expect(confdContainer.Image).To(Equal(components.TigeraRegistry + "tigera/node-windows:" + components.ComponentTigeraNodeWindows.Version))
					Expect(confdContainer.SecurityContext.Capabilities).To(BeNil())
					Expect(confdContainer.SecurityContext.Privileged).To(BeNil())
					Expect(confdContainer.SecurityContext.SELinuxOptions).To(BeNil())
					Expect(confdContainer.SecurityContext.WindowsOptions).To(Not(BeNil()))
					Expect(confdContainer.SecurityContext.WindowsOptions.GMSACredentialSpecName).To(BeNil())
					Expect(confdContainer.SecurityContext.WindowsOptions.GMSACredentialSpec).To(BeNil())
					Expect(*confdContainer.SecurityContext.WindowsOptions.RunAsUserName).To(Equal("NT AUTHORITY\\system"))
					Expect(*confdContainer.SecurityContext.WindowsOptions.HostProcess).To(BeTrue())
					Expect(confdContainer.SecurityContext.RunAsUser).To(BeNil())
					Expect(confdContainer.SecurityContext.RunAsGroup).To(BeNil())
					Expect(confdContainer.SecurityContext.RunAsNonRoot).To(BeNil())
					Expect(confdContainer.SecurityContext.ReadOnlyRootFilesystem).To(BeNil())
					Expect(confdContainer.SecurityContext.AllowPrivilegeEscalation).To(BeNil())
					Expect(confdContainer.SecurityContext.ProcMount).To(BeNil())
					Expect(confdContainer.SecurityContext.SeccompProfile).To(BeNil())
				}

				// Validate correct number of init containers.
				Expect(ds.Spec.Template.Spec.InitContainers).To(HaveLen(2))

				// CNI container uses image override.
				cniContainer := rtest.GetContainer(ds.Spec.Template.Spec.InitContainers, "install-cni")
				rtest.ExpectEnv(cniContainer.Env, "CNI_NET_DIR", "/etc/cni/net.d")
				Expect(cniContainer.Image).To(Equal(components.TigeraRegistry + "tigera/cni-windows:" + components.ComponentTigeraCNIWindows.Version))

				Expect(cniContainer.SecurityContext.Capabilities).To(BeNil())
				Expect(cniContainer.SecurityContext.Privileged).To(BeNil())
				Expect(cniContainer.SecurityContext.SELinuxOptions).To(BeNil())
				Expect(cniContainer.SecurityContext.WindowsOptions).To(Not(BeNil()))
				Expect(cniContainer.SecurityContext.WindowsOptions.GMSACredentialSpecName).To(BeNil())
				Expect(cniContainer.SecurityContext.WindowsOptions.GMSACredentialSpec).To(BeNil())
				Expect(*cniContainer.SecurityContext.WindowsOptions.RunAsUserName).To(Equal("NT AUTHORITY\\system"))
				Expect(*cniContainer.SecurityContext.WindowsOptions.HostProcess).To(BeTrue())
				Expect(cniContainer.SecurityContext.RunAsUser).To(BeNil())
				Expect(cniContainer.SecurityContext.RunAsGroup).To(BeNil())
				Expect(cniContainer.SecurityContext.RunAsNonRoot).To(BeNil())
				Expect(cniContainer.SecurityContext.ReadOnlyRootFilesystem).To(BeNil())
				Expect(cniContainer.SecurityContext.AllowPrivilegeEscalation).To(BeNil())
				Expect(cniContainer.SecurityContext.ProcMount).To(BeNil())
				Expect(cniContainer.SecurityContext.SeccompProfile).To(BeNil())

				// uninstall container uses image override.
				uninstallContainer := rtest.GetContainer(ds.Spec.Template.Spec.InitContainers, "uninstall-calico")
				Expect(uninstallContainer.Image).To(Equal(components.TigeraRegistry + "tigera/node-windows:" + components.ComponentTigeraNodeWindows.Version))

				Expect(uninstallContainer.SecurityContext.Capabilities).To(BeNil())
				Expect(uninstallContainer.SecurityContext.Privileged).To(BeNil())
				Expect(uninstallContainer.SecurityContext.SELinuxOptions).To(BeNil())
				Expect(uninstallContainer.SecurityContext.WindowsOptions).To(Not(BeNil()))
				Expect(uninstallContainer.SecurityContext.WindowsOptions.GMSACredentialSpecName).To(BeNil())
				Expect(uninstallContainer.SecurityContext.WindowsOptions.GMSACredentialSpec).To(BeNil())
				Expect(*uninstallContainer.SecurityContext.WindowsOptions.RunAsUserName).To(Equal("NT AUTHORITY\\system"))
				Expect(*uninstallContainer.SecurityContext.WindowsOptions.HostProcess).To(BeTrue())
				Expect(uninstallContainer.SecurityContext.RunAsUser).To(BeNil())
				Expect(uninstallContainer.SecurityContext.RunAsGroup).To(BeNil())
				Expect(uninstallContainer.SecurityContext.RunAsNonRoot).To(BeNil())
				Expect(uninstallContainer.SecurityContext.ReadOnlyRootFilesystem).To(BeNil())
				Expect(uninstallContainer.SecurityContext.AllowPrivilegeEscalation).To(BeNil())
				Expect(uninstallContainer.SecurityContext.ProcMount).To(BeNil())
				Expect(uninstallContainer.SecurityContext.SeccompProfile).To(BeNil())

				// Verify env
				expectedNodeEnv := []corev1.EnvVar{
					{Name: "CNI_PLUGIN_TYPE", Value: "Calico"},
					{Name: "DATASTORE_TYPE", Value: "kubernetes"},
					{Name: "WAIT_FOR_DATASTORE", Value: "true"},
					{Name: "CALICO_MANAGE_CNI", Value: "true"},
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
					{Name: "IP", Value: "autodetect"},
					{Name: "IP_AUTODETECTION_METHOD", Value: "first-found"},
					{Name: "IP6", Value: "none"},
					{Name: "FELIX_IPV6SUPPORT", Value: "false"},
					{Name: "FELIX_TYPHAK8SNAMESPACE", Value: "calico-system"},
					{Name: "FELIX_TYPHAK8SSERVICENAME", Value: "calico-typha"},
					{Name: "FELIX_TYPHACAFILE", Value: certificatemanagement.TrustedCertBundleMountPath},
					{Name: "FELIX_TYPHACERTFILE", Value: "/node-certs/tls.crt"},
					{Name: "FELIX_TYPHACN", Value: "typha-server"},
					{Name: "FELIX_TYPHAKEYFILE", Value: "/node-certs/tls.key"},

					{Name: "VXLAN_VNI", Value: "4096"},
					{Name: "VXLAN_ADAPTER", Value: ""},
					{Name: "KUBE_NETWORK", Value: "Calico.*"},
					{Name: "KUBERNETES_SERVICE_HOST", Value: "1.2.3.4"},
					{Name: "KUBERNETES_SERVICE_PORT", Value: "6443"},

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
				}

				// Set CALICO_NETWORKING_BACKEND
				if enableBGP {
					expectedNodeEnv = append(expectedNodeEnv, corev1.EnvVar{Name: "CALICO_NETWORKING_BACKEND", Value: "windows-bgp"})
				} else if enableVXLAN {
					expectedNodeEnv = append(expectedNodeEnv, corev1.EnvVar{Name: "CALICO_NETWORKING_BACKEND", Value: "vxlan"})
				} else {
					expectedNodeEnv = append(expectedNodeEnv, corev1.EnvVar{Name: "CALICO_NETWORKING_BACKEND", Value: "none"})
				}

				// Set CLUSTER_TYPE
				if enableBGP {
					expectedNodeEnv = append(expectedNodeEnv, corev1.EnvVar{Name: "CLUSTER_TYPE", Value: "k8s,operator,bgp,windows"})
				} else {
					expectedNodeEnv = append(expectedNodeEnv, corev1.EnvVar{Name: "CLUSTER_TYPE", Value: "k8s,operator,windows"})
				}

				Expect(rtest.GetContainer(ds.Spec.Template.Spec.Containers, "node").Env).To(ConsistOf(expectedNodeEnv))
				Expect(rtest.GetContainer(ds.Spec.Template.Spec.Containers, "felix").Env).To(ConsistOf(expectedNodeEnv))
				if enableBGP {
					Expect(rtest.GetContainer(ds.Spec.Template.Spec.Containers, "confd").Env).To(ConsistOf(expectedNodeEnv))
				}

				// Expect the SECURITY_GROUP env variables to not be set
				Expect(rtest.GetContainer(ds.Spec.Template.Spec.Containers, "node").Env).NotTo(ContainElement(gstruct.MatchFields(gstruct.IgnoreExtras, gstruct.Fields{"Name": Equal("TIGERA_DEFAULT_SECURITY_GROUPS")})))
				Expect(rtest.GetContainer(ds.Spec.Template.Spec.Containers, "node").Env).NotTo(ContainElement(gstruct.MatchFields(gstruct.IgnoreExtras, gstruct.Fields{"Name": Equal("TIGERA_POD_SECURITY_GROUP")})))
				Expect(rtest.GetContainer(ds.Spec.Template.Spec.Containers, "felix").Env).NotTo(ContainElement(gstruct.MatchFields(gstruct.IgnoreExtras, gstruct.Fields{"Name": Equal("TIGERA_DEFAULT_SECURITY_GROUPS")})))
				Expect(rtest.GetContainer(ds.Spec.Template.Spec.Containers, "felix").Env).NotTo(ContainElement(gstruct.MatchFields(gstruct.IgnoreExtras, gstruct.Fields{"Name": Equal("TIGERA_POD_SECURITY_GROUP")})))
				if enableBGP {
					Expect(rtest.GetContainer(ds.Spec.Template.Spec.Containers, "confd").Env).NotTo(ContainElement(gstruct.MatchFields(gstruct.IgnoreExtras, gstruct.Fields{"Name": Equal("TIGERA_DEFAULT_SECURITY_GROUPS")})))
					Expect(rtest.GetContainer(ds.Spec.Template.Spec.Containers, "confd").Env).NotTo(ContainElement(gstruct.MatchFields(gstruct.IgnoreExtras, gstruct.Fields{"Name": Equal("TIGERA_POD_SECURITY_GROUP")})))
				}

				expectedCNIEnv := []corev1.EnvVar{
					{Name: "SLEEP", Value: "false"},
					{Name: "CNI_PLUGIN_TYPE", Value: "Calico"},
					{Name: "CNI_BIN_DIR", Value: "/host/opt/cni/bin"},
					{Name: "CNI_CONF_NAME", Value: "10-calico.conflist"},
					{Name: "CNI_NET_DIR", Value: "/etc/cni/net.d"},
					{Name: "VXLAN_VNI", Value: "4096"},
					{
						Name:  "KUBERNETES_NODE_NAME",
						Value: "",
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

					{Name: "KUBERNETES_SERVICE_HOST", Value: "1.2.3.4"},
					{Name: "KUBERNETES_SERVICE_PORT", Value: "6443"},
					{Name: "KUBERNETES_SERVICE_CIDRS", Value: "10.96.0.0/12"},
					{Name: "KUBERNETES_DNS_SERVERS", Value: "10.96.0.10"},
				}
				Expect(rtest.GetContainer(ds.Spec.Template.Spec.InitContainers, "install-cni").Env).To(ConsistOf(expectedCNIEnv))

				expectedUninstallEnv := []corev1.EnvVar{
					{Name: "SLEEP", Value: "false"},
					{Name: "CNI_PLUGIN_TYPE", Value: "Calico"},
					{Name: "CNI_BIN_DIR", Value: "/host/opt/cni/bin"},
					{Name: "CNI_CONF_NAME", Value: "10-calico.conflist"},
					{Name: "CNI_NET_DIR", Value: "/host/etc/cni/net.d"},
				}
				Expect(rtest.GetContainer(ds.Spec.Template.Spec.InitContainers, "uninstall-calico").Env).To(ConsistOf(expectedUninstallEnv))

				// Verify volumes.
				fileOrCreate := corev1.HostPathFileOrCreate
				dirOrCreate := corev1.HostPathDirectoryOrCreate
				expectedVols := []corev1.Volume{
					{Name: "lib-modules", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/lib/modules"}}},
					{Name: "var-run-calico", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/var/run/calico", Type: &dirOrCreate}}},
					{Name: "var-lib-calico", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/var/lib/calico", Type: &dirOrCreate}}},
					{Name: "xtables-lock", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/run/xtables.lock", Type: &fileOrCreate}}},
					{Name: "cni-bin-dir", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/opt/cni/bin", Type: &dirOrCreate}}},
					{Name: "cni-net-dir", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/etc/cni/net.d"}}},
					{Name: "cni-log-dir", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/var/log/calico/cni", Type: &dirOrCreate}}},
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
					{Name: "var-log-calico", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/var/log/calico", Type: &dirOrCreate}}},
				}
				Expect(ds.Spec.Template.Spec.Volumes).To(ConsistOf(expectedVols))

				// Verify volume mounts.
				expectedNodeVolumeMounts := []corev1.VolumeMount{
					{MountPath: "/host/etc/cni/net.d", Name: "cni-net-dir"},
					{MountPath: "/var/run/calico", Name: "var-run-calico"},
					{MountPath: "/var/lib/calico", Name: "var-lib-calico"},
					{MountPath: "c:/etc/pki/tls/certs", Name: "tigera-ca-bundle", ReadOnly: true},
					{MountPath: "c:/node-certs", Name: render.NodeTLSSecretName, ReadOnly: true},
					{MountPath: "/var/log/calico", Name: "var-log-calico", ReadOnly: false},
				}
				Expect(rtest.GetContainer(ds.Spec.Template.Spec.Containers, "node").VolumeMounts).To(ConsistOf(expectedNodeVolumeMounts))
				Expect(rtest.GetContainer(ds.Spec.Template.Spec.Containers, "felix").VolumeMounts).To(ConsistOf(expectedNodeVolumeMounts))
				if enableBGP {
					Expect(rtest.GetContainer(ds.Spec.Template.Spec.Containers, "confd").VolumeMounts).To(ConsistOf(expectedNodeVolumeMounts))
				}

				expectedCNIVolumeMounts := []corev1.VolumeMount{
					{MountPath: "/host/opt/cni/bin", Name: "cni-bin-dir"},
					{MountPath: "/host/etc/cni/net.d", Name: "cni-net-dir"},
				}
				Expect(rtest.GetContainer(ds.Spec.Template.Spec.InitContainers, "install-cni").VolumeMounts).To(ConsistOf(expectedCNIVolumeMounts))

				expectedUninstallVolumeMounts := []corev1.VolumeMount{
					{MountPath: "/host/opt/cni/bin", Name: "cni-bin-dir"},
					{MountPath: "/host/etc/cni/net.d", Name: "cni-net-dir"},
				}
				Expect(rtest.GetContainer(ds.Spec.Template.Spec.InitContainers, "uninstall-calico").VolumeMounts).To(ConsistOf(expectedUninstallVolumeMounts))

				// Verify tolerations.
				Expect(ds.Spec.Template.Spec.Tolerations).To(ConsistOf(rmeta.TolerateAll))

				// Verify readiness and liveness probes.
				verifyWindowsProbesAndLifecycle(ds, false)
			})
		}
	})

	It("should render all resources when using Calico CNI on EKS", func() {
		expectedResources := []struct {
			name    string
			ns      string
			group   string
			version string
			kind    string
		}{
			{name: "cni-config-windows", ns: common.CalicoNamespace, group: "", version: "v1", kind: "ConfigMap"},
			{name: common.WindowsDaemonSetName, ns: common.CalicoNamespace, group: "apps", version: "v1", kind: "DaemonSet"},
		}

		// defaultInstance.FlexVolumePath = "/usr/libexec/kubernetes/kubelet-plugins/volume/exec/"
		defaultInstance.KubernetesProvider = operatorv1.ProviderEKS
		defaultInstance.CNI = &operatorv1.CNISpec{Type: operatorv1.PluginCalico, IPAM: &operatorv1.IPAMSpec{
			Type: operatorv1.IPAMPluginAmazonVPC,
		}}
		defaultInstance.CalicoNetwork.BGP = &bgpDisabled
		defaultInstance.CalicoNetwork.IPPools[0].Encapsulation = operatorv1.EncapsulationVXLAN
		component := render.Windows(&cfg)
		Expect(component.ResolveImages(nil)).To(BeNil())
		resources, _ := component.Objects()
		Expect(len(resources)).To(Equal(len(expectedResources)))

		// Should render the correct resources.
		i := 0
		for _, expectedRes := range expectedResources {
			rtest.ExpectResourceTypeAndObjectMetadata(resources[i], expectedRes.name, expectedRes.ns, expectedRes.group, expectedRes.version, expectedRes.kind)
			i++
		}

		cniCmResource := rtest.GetResource(resources, "cni-config-windows", "calico-system", "", "v1", "ConfigMap")
		Expect(cniCmResource).ToNot(BeNil())
		cniCm := cniCmResource.(*corev1.ConfigMap)
		Expect(cniCm.Data["config"]).To(MatchJSON(`{
"name": "Calico",
"cniVersion": "1.0.0",
"plugins": [
  {
    "DNS": {
      "Nameservers": [
	    "10.96.0.10"
	  ],
      "Search": [
        "svc.cluster.local"
      ]
    },
    "capabilities": {
      "dns": true
    },
    "datastore_type": "kubernetes",
    "ipam": {
      "subnet": "usePodCidr",
      "type": "calico-ipam"
    },
    "kubernetes": {
      "k8s_api_root": "https://1.2.3.4:6443",
      "kubeconfig": "c:/etc/cni/net.d/calico-kubeconfig"
    },
    "log_file_max_age": 5,
    "log_file_max_count": 5,
    "log_file_max_size": 1,
    "log_file_path": "c:/var/log/calico/cni/cni.log",
    "log_level": "Debug",
    "mode": "vxlan",
    "mtu": 0,
    "name": "Calico",
    "nodename": "__KUBERNETES_NODE_NAME__",
    "nodename_file": "__NODENAME_FILE__",
    "nodename_file_optional": true,
    "policies": [
      {
      "Name": "EndpointPolicy",
      "Value": {
        "ExceptionList": [
          "10.96.0.0/12"
        ],
        "Type": "OutBoundNAT"
      }
      },
      {
      "Name": "EndpointPolicy",
      "Value": {
        "DestinationPrefix": "10.96.0.0/12",
        "NeedEncap": true,
        "Type": "SDNROUTE"
      }
      }
    ],
    "policy": {
      "type": "k8s"
    },
    "type": "calico",
    "vxlan_mac_prefix": "0E-2A",
    "vxlan_vni": 4096,
    "windows_loopback_DSR": "__DSR_SUPPORT__",
    "windows_use_single_network": true
  }
]
}`))

		dsResource := rtest.GetResource(resources, "calico-node-windows", "calico-system", "apps", "v1", "DaemonSet")
		Expect(dsResource).ToNot(BeNil())

		// The DaemonSet should have the correct configuration.
		ds := dsResource.(*appsv1.DaemonSet)

		// The pod template should have node critical priority
		Expect(ds.Spec.Template.Spec.PriorityClassName).To(Equal(render.NodePriorityClassName))

		// The calico-node-windows daemonset has 2 containers (felix, node) when using VXLAN
		Expect(ds.Spec.Template.Spec.Containers).To(HaveLen(2))

		for _, container := range ds.Spec.Template.Spec.Containers {
			// Windows image override results in correct image.
			Expect(container.Image).To(Equal(fmt.Sprintf("quay.io/%s%s:%s", components.CalicoImagePath, components.ComponentCalicoNodeWindows.Image, components.ComponentCalicoNodeWindows.Version)))
		}

		// Validate correct number of init containers.
		Expect(len(ds.Spec.Template.Spec.InitContainers)).To(Equal(2))

		cniContainer := rtest.GetContainer(ds.Spec.Template.Spec.InitContainers, "install-cni")
		rtest.ExpectEnv(cniContainer.Env, "CNI_NET_DIR", "/etc/cni/net.d")

		// CNI container uses image override.
		Expect(cniContainer.Image).To(Equal(fmt.Sprintf("quay.io/%s%s:%s", components.CalicoImagePath, components.ComponentCalicoCNIWindows.Image, components.ComponentCalicoCNIWindows.Version)))

		// uninstall container uses image override.
		uninstallContainer := rtest.GetContainer(ds.Spec.Template.Spec.InitContainers, "uninstall-calico")
		Expect(uninstallContainer.Image).To(Equal(fmt.Sprintf("quay.io/%s%s:%s", components.CalicoImagePath, components.ComponentCalicoNodeWindows.Image, components.ComponentCalicoNodeWindows.Version)))

		// Verify env
		expectedNodeEnv := []corev1.EnvVar{
			{Name: "CNI_PLUGIN_TYPE", Value: "Calico"},
			{Name: "DATASTORE_TYPE", Value: "kubernetes"},
			{Name: "WAIT_FOR_DATASTORE", Value: "true"},
			{Name: "CALICO_MANAGE_CNI", Value: "true"},
			{Name: "CALICO_NETWORKING_BACKEND", Value: "vxlan"},
			{Name: "CALICO_DISABLE_FILE_LOGGING", Value: "false"},
			{Name: "CLUSTER_TYPE", Value: "k8s,operator,ecs,windows"},
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
			{Name: "IP", Value: "autodetect"},
			{Name: "IP_AUTODETECTION_METHOD", Value: "first-found"},
			{Name: "IP6", Value: "none"},
			{Name: "FELIX_IPV6SUPPORT", Value: "false"},
			{Name: "FELIX_TYPHAK8SNAMESPACE", Value: "calico-system"},
			{Name: "FELIX_TYPHAK8SSERVICENAME", Value: "calico-typha"},
			{Name: "FELIX_TYPHACAFILE", Value: certificatemanagement.TrustedCertBundleMountPath},
			{Name: "FELIX_TYPHACERTFILE", Value: "/node-certs/tls.crt"},
			{Name: "FELIX_TYPHACN", Value: "typha-server"},
			{Name: "FELIX_TYPHAKEYFILE", Value: "/node-certs/tls.key"},

			{Name: "VXLAN_VNI", Value: "4096"},
			{Name: "VXLAN_ADAPTER", Value: ""},
			{Name: "KUBE_NETWORK", Value: "Calico.*"},
			{Name: "KUBERNETES_SERVICE_HOST", Value: "1.2.3.4"},
			{Name: "KUBERNETES_SERVICE_PORT", Value: "6443"},
		}

		Expect(rtest.GetContainer(ds.Spec.Template.Spec.Containers, "node").Env).To(ConsistOf(expectedNodeEnv))
		Expect(rtest.GetContainer(ds.Spec.Template.Spec.Containers, "felix").Env).To(ConsistOf(expectedNodeEnv))

		// Expect the SECURITY_GROUP env variables to not be set
		Expect(rtest.GetContainer(ds.Spec.Template.Spec.Containers, "node").Env).NotTo(ContainElement(gstruct.MatchFields(gstruct.IgnoreExtras, gstruct.Fields{"Name": Equal("TIGERA_DEFAULT_SECURITY_GROUPS")})))
		Expect(rtest.GetContainer(ds.Spec.Template.Spec.Containers, "node").Env).NotTo(ContainElement(gstruct.MatchFields(gstruct.IgnoreExtras, gstruct.Fields{"Name": Equal("TIGERA_POD_SECURITY_GROUP")})))
		Expect(rtest.GetContainer(ds.Spec.Template.Spec.Containers, "felix").Env).NotTo(ContainElement(gstruct.MatchFields(gstruct.IgnoreExtras, gstruct.Fields{"Name": Equal("TIGERA_DEFAULT_SECURITY_GROUPS")})))
		Expect(rtest.GetContainer(ds.Spec.Template.Spec.Containers, "felix").Env).NotTo(ContainElement(gstruct.MatchFields(gstruct.IgnoreExtras, gstruct.Fields{"Name": Equal("TIGERA_POD_SECURITY_GROUP")})))

		expectedCNIEnv := []corev1.EnvVar{
			{Name: "SLEEP", Value: "false"},
			{Name: "CNI_PLUGIN_TYPE", Value: "Calico"},
			{Name: "CNI_BIN_DIR", Value: "/host/opt/cni/bin"},
			{Name: "CNI_CONF_NAME", Value: "10-calico.conflist"},
			{Name: "CNI_NET_DIR", Value: "/etc/cni/net.d"},
			{Name: "VXLAN_VNI", Value: "4096"},

			{
				Name:  "KUBERNETES_NODE_NAME",
				Value: "",
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

			{Name: "KUBERNETES_SERVICE_HOST", Value: "1.2.3.4"},
			{Name: "KUBERNETES_SERVICE_PORT", Value: "6443"},
			{Name: "KUBERNETES_SERVICE_CIDRS", Value: "10.96.0.0/12"},
			{Name: "KUBERNETES_DNS_SERVERS", Value: "10.96.0.10"},
		}
		Expect(rtest.GetContainer(ds.Spec.Template.Spec.InitContainers, "install-cni").Env).To(ConsistOf(expectedCNIEnv))

		expectedUninstallEnv := []corev1.EnvVar{
			{Name: "SLEEP", Value: "false"},
			{Name: "CNI_PLUGIN_TYPE", Value: "Calico"},
			{Name: "CNI_BIN_DIR", Value: "/host/opt/cni/bin"},
			{Name: "CNI_CONF_NAME", Value: "10-calico.conflist"},
			{Name: "CNI_NET_DIR", Value: "/host/etc/cni/net.d"},
		}
		Expect(rtest.GetContainer(ds.Spec.Template.Spec.InitContainers, "uninstall-calico").Env).To(ConsistOf(expectedUninstallEnv))

		// Verify volumes.
		fileOrCreate := corev1.HostPathFileOrCreate
		dirOrCreate := corev1.HostPathDirectoryOrCreate
		expectedVols := []corev1.Volume{
			{Name: "lib-modules", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/lib/modules"}}},
			{Name: "var-run-calico", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/var/run/calico", Type: &dirOrCreate}}},
			{Name: "var-lib-calico", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/var/lib/calico", Type: &dirOrCreate}}},
			{Name: "xtables-lock", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/run/xtables.lock", Type: &fileOrCreate}}},
			{Name: "cni-bin-dir", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/opt/cni/bin", Type: &dirOrCreate}}},
			{Name: "cni-net-dir", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/etc/cni/net.d"}}},
			{Name: "cni-log-dir", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/var/log/calico/cni", Type: &dirOrCreate}}},
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
		}
		Expect(ds.Spec.Template.Spec.Volumes).To(ConsistOf(expectedVols))

		// Verify volume mounts.
		expectedNodeVolumeMounts := []corev1.VolumeMount{
			{MountPath: "/host/etc/cni/net.d", Name: "cni-net-dir"},
			{MountPath: "/var/run/calico", Name: "var-run-calico"},
			{MountPath: "/var/lib/calico", Name: "var-lib-calico"},
			{MountPath: "c:/etc/pki/tls/certs", Name: "tigera-ca-bundle", ReadOnly: true},
			{MountPath: "c:/node-certs", Name: render.NodeTLSSecretName, ReadOnly: true},
			{MountPath: "/var/log/calico/cni", Name: "cni-log-dir", ReadOnly: false},
		}
		Expect(rtest.GetContainer(ds.Spec.Template.Spec.Containers, "node").VolumeMounts).To(ConsistOf(expectedNodeVolumeMounts))
		Expect(rtest.GetContainer(ds.Spec.Template.Spec.Containers, "felix").VolumeMounts).To(ConsistOf(expectedNodeVolumeMounts))

		expectedCNIVolumeMounts := []corev1.VolumeMount{
			{MountPath: "/host/opt/cni/bin", Name: "cni-bin-dir"},
			{MountPath: "/host/etc/cni/net.d", Name: "cni-net-dir"},
		}
		Expect(rtest.GetContainer(ds.Spec.Template.Spec.InitContainers, "install-cni").VolumeMounts).To(ConsistOf(expectedCNIVolumeMounts))

		expectedUninstallVolumeMounts := []corev1.VolumeMount{
			{MountPath: "/host/opt/cni/bin", Name: "cni-bin-dir"},
			{MountPath: "/host/etc/cni/net.d", Name: "cni-net-dir"},
		}
		Expect(rtest.GetContainer(ds.Spec.Template.Spec.InitContainers, "uninstall-calico").VolumeMounts).To(ConsistOf(expectedUninstallVolumeMounts))

		// Verify tolerations.
		Expect(ds.Spec.Template.Spec.Tolerations).To(ConsistOf(rmeta.TolerateAll))

		// Verify readiness and liveness probes.
		verifyWindowsProbesAndLifecycle(ds, true)
	})

	It("should properly render a configuration using the AmazonVPC CNI plugin", func() {
		// Override the installation with one configured for AmazonVPC CNI.
		amazonVPCInstalllation := &operatorv1.InstallationSpec{
			KubernetesProvider: operatorv1.ProviderEKS,
			CNI:                &operatorv1.CNISpec{Type: operatorv1.PluginAmazonVPC},
			ServiceCIDRs:       []string{"10.96.0.0/12"},
			WindowsNodes: &operatorv1.WindowsNodeSpec{
				CNIBinDir:    "/opt/cni/bin",
				CNIConfigDir: "/etc/cni/net.d",
				CNILogDir:    "/var/log/calico/cni",
			},
		}
		cfg.Installation = amazonVPCInstalllation

		component := render.Windows(&cfg)
		Expect(component.ResolveImages(nil)).To(BeNil())
		resources, _ := component.Objects()
		Expect(len(resources)).To(Equal(defaultNumExpectedResources - 1))

		// Should render the correct resources.
		Expect(rtest.GetResource(resources, "calico-node-windows", "calico-system", "apps", "v1", "DaemonSet")).ToNot(BeNil())
		dsResource := rtest.GetResource(resources, "calico-node-windows", "calico-system", "apps", "v1", "DaemonSet")
		Expect(dsResource).ToNot(BeNil())

		// Should not render CNI configuration.
		cniCmResource := rtest.GetResource(resources, "cni-config-windows", "calico-system", "", "v1", "ConfigMap")
		Expect(cniCmResource).To(BeNil())

		// The DaemonSet should have the correct configuration.
		ds := dsResource.(*appsv1.DaemonSet)

		// The pod template should have node critical priority
		Expect(ds.Spec.Template.Spec.PriorityClassName).To(Equal(render.NodePriorityClassName))

		// CNI install container should not be present.
		cniContainer := rtest.GetContainer(ds.Spec.Template.Spec.InitContainers, "install-cni")
		Expect(cniContainer).To(BeNil())

		// uninstall container should still be present.
		uninstallContainer := rtest.GetContainer(ds.Spec.Template.Spec.InitContainers, "uninstall-calico")
		Expect(uninstallContainer).NotTo(BeNil())

		// Validate correct number of init containers.
		Expect(len(ds.Spec.Template.Spec.InitContainers)).To(Equal(1))

		// Verify env
		expectedNodeEnv := []corev1.EnvVar{
			{Name: "CNI_PLUGIN_TYPE", Value: "AmazonVPC"},
			{Name: "DATASTORE_TYPE", Value: "kubernetes"},
			{Name: "WAIT_FOR_DATASTORE", Value: "true"},
			{Name: "CALICO_NETWORKING_BACKEND", Value: "none"},
			{Name: "CALICO_DISABLE_FILE_LOGGING", Value: "false"},
			{Name: "CLUSTER_TYPE", Value: "k8s,operator,ecs,windows"},
			{Name: "IP", Value: "none"},
			{Name: "IP6", Value: "none"},
			{Name: "CALICO_MANAGE_CNI", Value: "false"},
			{Name: "FELIX_DEFAULTENDPOINTTOHOSTACTION", Value: "ACCEPT"},
			{Name: "FELIX_IPV6SUPPORT", Value: "false"},
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
			{Name: "FELIX_TYPHAK8SNAMESPACE", Value: "calico-system"},
			{Name: "FELIX_TYPHAK8SSERVICENAME", Value: "calico-typha"},
			{Name: "FELIX_TYPHACAFILE", Value: certificatemanagement.TrustedCertBundleMountPath},
			{Name: "FELIX_TYPHACERTFILE", Value: "/node-certs/tls.crt"},
			{Name: "FELIX_TYPHACN", Value: "typha-server"},
			{Name: "FELIX_TYPHAKEYFILE", Value: "/node-certs/tls.key"},
			{Name: "FELIX_ROUTESOURCE", Value: "WorkloadIPs"},
			{Name: "FELIX_BPFEXTTOSERVICECONNMARK", Value: "0x80"},

			{Name: "VXLAN_VNI", Value: "4096"},
			{Name: "VXLAN_ADAPTER", Value: ""},
			{Name: "KUBE_NETWORK", Value: "vpc.*"},
			{Name: "KUBERNETES_SERVICE_HOST", Value: "1.2.3.4"},
			{Name: "KUBERNETES_SERVICE_PORT", Value: "6443"},
		}

		Expect(rtest.GetContainer(ds.Spec.Template.Spec.Containers, "node").Env).To(ConsistOf(expectedNodeEnv))
		Expect(rtest.GetContainer(ds.Spec.Template.Spec.Containers, "felix").Env).To(ConsistOf(expectedNodeEnv))

		// Expect the SECURITY_GROUP env variables to not be set
		Expect(rtest.GetContainer(ds.Spec.Template.Spec.Containers, "node").Env).NotTo(ContainElement(gstruct.MatchFields(gstruct.IgnoreExtras, gstruct.Fields{"Name": Equal("TIGERA_DEFAULT_SECURITY_GROUPS")})))
		Expect(rtest.GetContainer(ds.Spec.Template.Spec.Containers, "node").Env).NotTo(ContainElement(gstruct.MatchFields(gstruct.IgnoreExtras, gstruct.Fields{"Name": Equal("TIGERA_POD_SECURITY_GROUP")})))
		Expect(rtest.GetContainer(ds.Spec.Template.Spec.Containers, "felix").Env).NotTo(ContainElement(gstruct.MatchFields(gstruct.IgnoreExtras, gstruct.Fields{"Name": Equal("TIGERA_DEFAULT_SECURITY_GROUPS")})))
		Expect(rtest.GetContainer(ds.Spec.Template.Spec.Containers, "felix").Env).NotTo(ContainElement(gstruct.MatchFields(gstruct.IgnoreExtras, gstruct.Fields{"Name": Equal("TIGERA_POD_SECURITY_GROUP")})))

		// Verify volumes.
		fileOrCreate := corev1.HostPathFileOrCreate
		dirOrCreate := corev1.HostPathDirectoryOrCreate
		expectedVols := []corev1.Volume{
			{Name: "lib-modules", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/lib/modules"}}},
			{Name: "var-run-calico", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/var/run/calico", Type: &dirOrCreate}}},
			{Name: "var-lib-calico", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/var/lib/calico", Type: &dirOrCreate}}},
			{Name: "xtables-lock", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/run/xtables.lock", Type: &fileOrCreate}}},
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
		}
		Expect(ds.Spec.Template.Spec.Volumes).To(ConsistOf(expectedVols))

		// Verify volume mounts.
		expectedNodeVolumeMounts := []corev1.VolumeMount{
			{MountPath: "/var/run/calico", Name: "var-run-calico"},
			{MountPath: "/var/lib/calico", Name: "var-lib-calico"},
			{MountPath: "c:/etc/pki/tls/certs", Name: "tigera-ca-bundle", ReadOnly: true},
			{MountPath: "c:/node-certs", Name: render.NodeTLSSecretName, ReadOnly: true},
		}
		Expect(rtest.GetContainer(ds.Spec.Template.Spec.Containers, "node").VolumeMounts).To(ConsistOf(expectedNodeVolumeMounts))
		Expect(rtest.GetContainer(ds.Spec.Template.Spec.Containers, "felix").VolumeMounts).To(ConsistOf(expectedNodeVolumeMounts))

		// Verify tolerations.
		Expect(ds.Spec.Template.Spec.Tolerations).To(ConsistOf(rmeta.TolerateAll))

		// Verify readiness and liveness probes.
		verifyWindowsProbesAndLifecycle(ds, true)
	})

	DescribeTable("should properly render configuration using non-Calico CNI plugin",
		func(cni operatorv1.CNIPluginType, ipam operatorv1.IPAMPluginType) {
			installlation := &operatorv1.InstallationSpec{
				CNI: &operatorv1.CNISpec{
					Type: cni,
					IPAM: &operatorv1.IPAMSpec{Type: ipam},
				},
				WindowsNodes: &operatorv1.WindowsNodeSpec{
					CNIBinDir:    "/opt/cni/bin",
					CNIConfigDir: "/etc/cni/net.d",
					CNILogDir:    "/var/log/calico/cni",
				},
			}
			cfg.Installation = installlation

			component := render.Windows(&cfg)
			Expect(component.ResolveImages(nil)).To(BeNil())
			resources, _ := component.Objects()

			// Should render the correct resources.
			Expect(rtest.GetResource(resources, "calico-node-windows", "calico-system", "apps", "v1", "DaemonSet")).ToNot(BeNil())
			dsResource := rtest.GetResource(resources, "calico-node-windows", "calico-system", "apps", "v1", "DaemonSet")
			Expect(dsResource).ToNot(BeNil())

			// Should not render CNI configuration.
			cniCmResource := rtest.GetResource(resources, "cni-config-windows", "calico-system", "", "v1", "ConfigMap")
			Expect(cniCmResource).To(BeNil())

			// The DaemonSet should have the correct configuration.
			ds := dsResource.(*appsv1.DaemonSet)

			// The pod template should have node critical priority
			Expect(ds.Spec.Template.Spec.PriorityClassName).To(Equal(render.NodePriorityClassName))

			// CNI install container should not be present.
			cniContainer := rtest.GetContainer(ds.Spec.Template.Spec.InitContainers, "install-cni")
			Expect(cniContainer).To(BeNil())
			// Validate correct number of init containers.
			Expect(len(ds.Spec.Template.Spec.InitContainers)).To(Equal(1))

			// Verify env
			expectedEnvs := []corev1.EnvVar{
				{Name: "CNI_PLUGIN_TYPE", Value: string(cni)},
				{Name: "CALICO_NETWORKING_BACKEND", Value: "none"},
				{Name: "FELIX_DEFAULTENDPOINTTOHOSTACTION", Value: "ACCEPT"},
			}
			for _, expected := range expectedEnvs {
				Expect(ds.Spec.Template.Spec.Containers[0].Env).To(ContainElement(expected))
			}

			// Verify readiness and liveness probes.
			verifyWindowsProbesAndLifecycle(ds, true)
		},
		Entry("GKE", operatorv1.PluginGKE, operatorv1.IPAMPluginHostLocal),
		Entry("AmazonVPC", operatorv1.PluginAmazonVPC, operatorv1.IPAMPluginAmazonVPC),
		Entry("AzureVNET", operatorv1.PluginAzureVNET, operatorv1.IPAMPluginAzureVNET),
	)

	It("should render all resources when running on openshift", func() {
		expectedResources := []struct {
			name    string
			ns      string
			group   string
			version string
			kind    string
		}{
			{name: "cni-config-windows", ns: common.CalicoNamespace, group: "", version: "v1", kind: "ConfigMap"},
			{name: common.WindowsDaemonSetName, ns: common.CalicoNamespace, group: "apps", version: "v1", kind: "DaemonSet"},
		}

		defaultInstance.FlexVolumePath = "/etc/kubernetes/kubelet-plugins/volume/exec/"
		defaultInstance.KubernetesProvider = operatorv1.ProviderOpenShift
		component := render.Windows(&cfg)
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
		ds := rtest.GetResource(resources, "calico-node-windows", "calico-system", "apps", "v1", "DaemonSet").(*appsv1.DaemonSet)

		// The pod template should have node critical priority
		Expect(ds.Spec.Template.Spec.PriorityClassName).To(Equal(render.NodePriorityClassName))

		felixContainer := rtest.GetContainer(ds.Spec.Template.Spec.Containers, "felix")
		Expect(felixContainer.Image).To(Equal(fmt.Sprintf("quay.io/%s%s:%s", components.CalicoImagePath, components.ComponentCalicoNodeWindows.Image, components.ComponentCalicoNodeWindows.Version)))
		nodeContainer := rtest.GetContainer(ds.Spec.Template.Spec.Containers, "node")
		Expect(nodeContainer.Image).To(Equal(fmt.Sprintf("quay.io/%s%s:%s", components.CalicoImagePath, components.ComponentCalicoNodeWindows.Image, components.ComponentCalicoNodeWindows.Version)))
		cniContainer := rtest.GetContainer(ds.Spec.Template.Spec.InitContainers, "install-cni")
		Expect(cniContainer.Image).To(Equal(fmt.Sprintf("quay.io/%s%s:%s", components.CalicoImagePath, components.ComponentCalicoCNIWindows.Image, components.ComponentCalicoCNIWindows.Version)))
		uninstallContainer := rtest.GetContainer(ds.Spec.Template.Spec.InitContainers, "uninstall-calico")
		Expect(uninstallContainer.Image).To(Equal(fmt.Sprintf("quay.io/%s%s:%s", components.CalicoImagePath, components.ComponentCalicoNodeWindows.Image, components.ComponentCalicoNodeWindows.Version)))

		// FIXME: confirm openshift CNI path defaults
		expectedCNIVolumeMounts := []corev1.VolumeMount{
			{MountPath: "/host/opt/cni/bin", Name: "cni-bin-dir"},
			{MountPath: "/host/etc/cni/net.d", Name: "cni-net-dir"},
		}
		Expect(rtest.GetContainer(ds.Spec.Template.Spec.InitContainers, "install-cni").VolumeMounts).To(ConsistOf(expectedCNIVolumeMounts))

		// FIXME: confirm openshift CNI path defaults
		expectedUninstallVolumeMounts := []corev1.VolumeMount{
			{MountPath: "/host/opt/cni/bin", Name: "cni-bin-dir"},
			{MountPath: "/host/etc/cni/net.d", Name: "cni-net-dir"},
		}
		Expect(rtest.GetContainer(ds.Spec.Template.Spec.InitContainers, "uninstall-calico").VolumeMounts).To(ConsistOf(expectedUninstallVolumeMounts))

		// Verify volumes
		// FIXME: confirm openshift CNI path defaults
		fileOrCreate := corev1.HostPathFileOrCreate
		dirOrCreate := corev1.HostPathDirectoryOrCreate
		expectedVols := []corev1.Volume{
			{Name: "lib-modules", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/lib/modules"}}},
			{Name: "var-run-calico", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/var/run/calico", Type: &dirOrCreate}}},
			{Name: "var-lib-calico", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/var/lib/calico", Type: &dirOrCreate}}},
			{Name: "xtables-lock", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/run/xtables.lock", Type: &fileOrCreate}}},
			{Name: "cni-bin-dir", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/opt/cni/bin", Type: &dirOrCreate}}},
			{Name: "cni-net-dir", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/etc/cni/net.d"}}},
			{Name: "cni-log-dir", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/var/log/calico/cni", Type: &dirOrCreate}}},
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
		}
		Expect(ds.Spec.Template.Spec.Volumes).To(ConsistOf(expectedVols))

		expectedNodeEnv := []corev1.EnvVar{
			{Name: "CNI_PLUGIN_TYPE", Value: "Calico"},
			{Name: "DATASTORE_TYPE", Value: "kubernetes"},
			{Name: "WAIT_FOR_DATASTORE", Value: "true"},
			{Name: "CALICO_MANAGE_CNI", Value: "true"},
			{Name: "CALICO_NETWORKING_BACKEND", Value: "windows-bgp"},
			{Name: "CLUSTER_TYPE", Value: "k8s,operator,openshift,bgp,windows"},
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
			{Name: "IP", Value: "autodetect"},
			{Name: "IP_AUTODETECTION_METHOD", Value: "first-found"},
			{Name: "IP6", Value: "none"},
			{Name: "FELIX_IPV6SUPPORT", Value: "false"},
			{Name: "FELIX_TYPHAK8SNAMESPACE", Value: "calico-system"},
			{Name: "FELIX_TYPHAK8SSERVICENAME", Value: "calico-typha"},
			{Name: "FELIX_TYPHACAFILE", Value: certificatemanagement.TrustedCertBundleMountPath},
			{Name: "FELIX_TYPHACERTFILE", Value: "/node-certs/tls.crt"},
			{Name: "FELIX_TYPHACN", Value: "typha-server"},
			{Name: "FELIX_TYPHAKEYFILE", Value: "/node-certs/tls.key"},

			// Calico Windows specific envvars
			{Name: "VXLAN_VNI", Value: "4096"},
			{Name: "VXLAN_ADAPTER", Value: ""},
			{Name: "KUBE_NETWORK", Value: "Calico.*"},
			{Name: "KUBERNETES_SERVICE_HOST", Value: "1.2.3.4"},
			{Name: "KUBERNETES_SERVICE_PORT", Value: "6443"},
		}

		Expect(rtest.GetContainer(ds.Spec.Template.Spec.Containers, "node").Env).To(ConsistOf(expectedNodeEnv))
		Expect(rtest.GetContainer(ds.Spec.Template.Spec.Containers, "felix").Env).To(ConsistOf(expectedNodeEnv))
		Expect(rtest.GetContainer(ds.Spec.Template.Spec.Containers, "confd").Env).To(ConsistOf(expectedNodeEnv))

		verifyWindowsProbesAndLifecycle(ds, true)
	})

	It("should render all resources when variant is CalicoEnterprise and running on openshift", func() {
		expectedResources := []struct {
			name    string
			ns      string
			group   string
			version string
			kind    string
		}{
			{name: "calico-node-metrics-windows", ns: "calico-system", group: "", version: "v1", kind: "Service"},
			{name: "cni-config-windows", ns: common.CalicoNamespace, group: "", version: "v1", kind: "ConfigMap"},
			{name: common.WindowsDaemonSetName, ns: common.CalicoNamespace, group: "apps", version: "v1", kind: "DaemonSet"},
		}

		defaultInstance.Variant = operatorv1.CalicoEnterprise
		defaultInstance.KubernetesProvider = operatorv1.ProviderOpenShift
		cfg.NodeReporterMetricsPort = 9081

		component := render.Windows(&cfg)
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
		ds := rtest.GetResource(resources, "calico-node-windows", "calico-system", "apps", "v1", "DaemonSet").(*appsv1.DaemonSet)

		// The pod template should have node critical priority
		Expect(ds.Spec.Template.Spec.PriorityClassName).To(Equal(render.NodePriorityClassName))

		felixContainer := rtest.GetContainer(ds.Spec.Template.Spec.Containers, "felix")
		Expect(felixContainer.Image).To(Equal(fmt.Sprintf("%s%s%s:%s", components.TigeraRegistry, components.TigeraImagePath, components.ComponentTigeraNodeWindows.Image, components.ComponentTigeraNodeWindows.Version)))
		nodeContainer := rtest.GetContainer(ds.Spec.Template.Spec.Containers, "node")
		Expect(nodeContainer.Image).To(Equal(fmt.Sprintf("%s%s%s:%s", components.TigeraRegistry, components.TigeraImagePath, components.ComponentTigeraNodeWindows.Image, components.ComponentTigeraNodeWindows.Version)))
		cniContainer := rtest.GetContainer(ds.Spec.Template.Spec.InitContainers, "install-cni")
		Expect(cniContainer.Image).To(Equal(fmt.Sprintf("%s%s%s:%s", components.TigeraRegistry, components.TigeraImagePath, components.ComponentTigeraCNIWindows.Image, components.ComponentTigeraCNIWindows.Version)))
		uninstallContainer := rtest.GetContainer(ds.Spec.Template.Spec.InitContainers, "uninstall-calico")
		Expect(uninstallContainer.Image).To(Equal(fmt.Sprintf("%s%s%s:%s", components.TigeraRegistry, components.TigeraImagePath, components.ComponentTigeraNodeWindows.Image, components.ComponentTigeraNodeWindows.Version)))

		// FIXME: confirm openshift CNI path defaults
		expectedCNIVolumeMounts := []corev1.VolumeMount{
			{MountPath: "/host/opt/cni/bin", Name: "cni-bin-dir"},
			{MountPath: "/host/etc/cni/net.d", Name: "cni-net-dir"},
		}
		Expect(rtest.GetContainer(ds.Spec.Template.Spec.InitContainers, "install-cni").VolumeMounts).To(ConsistOf(expectedCNIVolumeMounts))

		// FIXME: confirm openshift CNI path defaults
		expectedUninstallVolumeMounts := []corev1.VolumeMount{
			{MountPath: "/host/opt/cni/bin", Name: "cni-bin-dir"},
			{MountPath: "/host/etc/cni/net.d", Name: "cni-net-dir"},
		}
		Expect(rtest.GetContainer(ds.Spec.Template.Spec.InitContainers, "uninstall-calico").VolumeMounts).To(ConsistOf(expectedUninstallVolumeMounts))

		// Verify volumes
		// FIXME: confirm openshift CNI path defaults
		fileOrCreate := corev1.HostPathFileOrCreate
		dirOrCreate := corev1.HostPathDirectoryOrCreate
		expectedVols := []corev1.Volume{
			{Name: "lib-modules", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/lib/modules"}}},
			{Name: "var-run-calico", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/var/run/calico", Type: &dirOrCreate}}},
			{Name: "var-lib-calico", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/var/lib/calico", Type: &dirOrCreate}}},
			{Name: "xtables-lock", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/run/xtables.lock", Type: &fileOrCreate}}},
			{Name: "cni-bin-dir", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/opt/cni/bin", Type: &dirOrCreate}}},
			{Name: "cni-net-dir", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/etc/cni/net.d"}}},
			{Name: "cni-log-dir", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/var/log/calico/cni", Type: &dirOrCreate}}},
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
			{Name: "var-log-calico", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/var/log/calico", Type: &dirOrCreate}}},
		}
		Expect(ds.Spec.Template.Spec.Volumes).To(ConsistOf(expectedVols))

		expectedNodeEnv := []corev1.EnvVar{
			// Default envvars.
			{Name: "CNI_PLUGIN_TYPE", Value: "Calico"},
			{Name: "DATASTORE_TYPE", Value: "kubernetes"},
			{Name: "WAIT_FOR_DATASTORE", Value: "true"},
			{Name: "CALICO_MANAGE_CNI", Value: "true"},
			{Name: "CALICO_NETWORKING_BACKEND", Value: "windows-bgp"},
			{Name: "CLUSTER_TYPE", Value: "k8s,operator,openshift,bgp,windows"},
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
			{Name: "IP", Value: "autodetect"},
			{Name: "IP_AUTODETECTION_METHOD", Value: "first-found"},
			{Name: "IP6", Value: "none"},
			{Name: "FELIX_IPV6SUPPORT", Value: "false"},
			{Name: "FELIX_TYPHAK8SNAMESPACE", Value: "calico-system"},
			{Name: "FELIX_TYPHAK8SSERVICENAME", Value: "calico-typha"},
			{Name: "FELIX_TYPHACAFILE", Value: certificatemanagement.TrustedCertBundleMountPath},
			{Name: "FELIX_TYPHACERTFILE", Value: "/node-certs/tls.crt"},
			{Name: "FELIX_TYPHACN", Value: "typha-server"},
			{Name: "FELIX_TYPHAKEYFILE", Value: "/node-certs/tls.key"},

			{Name: "FELIX_DNSTRUSTEDSERVERS", Value: "k8s-service:openshift-dns/dns-default"},

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

			// Calico Windows specific envvars
			{Name: "VXLAN_VNI", Value: "4096"},
			{Name: "VXLAN_ADAPTER", Value: ""},
			{Name: "KUBE_NETWORK", Value: "Calico.*"},
			{Name: "KUBERNETES_SERVICE_HOST", Value: "1.2.3.4"},
			{Name: "KUBERNETES_SERVICE_PORT", Value: "6443"},
		}
		Expect(rtest.GetContainer(ds.Spec.Template.Spec.Containers, "node").Env).To(ConsistOf(expectedNodeEnv))
		Expect(rtest.GetContainer(ds.Spec.Template.Spec.Containers, "felix").Env).To(ConsistOf(expectedNodeEnv))
		Expect(rtest.GetContainer(ds.Spec.Template.Spec.Containers, "confd").Env).To(ConsistOf(expectedNodeEnv))

		verifyWindowsProbesAndLifecycle(ds, false)
	})

	It("should render all resources when variant is CalicoEnterprise and running on RKE2", func() {
		expectedResources := []struct {
			name    string
			ns      string
			group   string
			version string
			kind    string
		}{
			{name: "calico-node-metrics-windows", ns: "calico-system", group: "", version: "v1", kind: "Service"},
			{name: "cni-config-windows", ns: common.CalicoNamespace, group: "", version: "v1", kind: "ConfigMap"},
			{name: common.WindowsDaemonSetName, ns: common.CalicoNamespace, group: "apps", version: "v1", kind: "DaemonSet"},
		}

		defaultInstance.Variant = operatorv1.CalicoEnterprise
		defaultInstance.KubernetesProvider = operatorv1.ProviderRKE2
		cfg.NodeReporterMetricsPort = 9081

		component := render.Windows(&cfg)
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
		ds := rtest.GetResource(resources, "calico-node-windows", "calico-system", "apps", "v1", "DaemonSet").(*appsv1.DaemonSet)

		// The pod template should have node critical priority
		Expect(ds.Spec.Template.Spec.PriorityClassName).To(Equal(render.NodePriorityClassName))

		felixContainer := rtest.GetContainer(ds.Spec.Template.Spec.Containers, "felix")
		Expect(felixContainer.Image).To(Equal(fmt.Sprintf("%s%s%s:%s", components.TigeraRegistry, components.TigeraImagePath, components.ComponentTigeraNodeWindows.Image, components.ComponentTigeraNodeWindows.Version)))
		nodeContainer := rtest.GetContainer(ds.Spec.Template.Spec.Containers, "node")
		Expect(nodeContainer.Image).To(Equal(fmt.Sprintf("%s%s%s:%s", components.TigeraRegistry, components.TigeraImagePath, components.ComponentTigeraNodeWindows.Image, components.ComponentTigeraNodeWindows.Version)))
		cniContainer := rtest.GetContainer(ds.Spec.Template.Spec.InitContainers, "install-cni")
		Expect(cniContainer.Image).To(Equal(fmt.Sprintf("%s%s%s:%s", components.TigeraRegistry, components.TigeraImagePath, components.ComponentTigeraCNIWindows.Image, components.ComponentTigeraCNIWindows.Version)))
		uninstallContainer := rtest.GetContainer(ds.Spec.Template.Spec.InitContainers, "uninstall-calico")
		Expect(uninstallContainer.Image).To(Equal(fmt.Sprintf("%s%s%s:%s", components.TigeraRegistry, components.TigeraImagePath, components.ComponentTigeraNodeWindows.Image, components.ComponentTigeraNodeWindows.Version)))

		// FIXME: confirm RKE2 CNI path defaults
		expectedCNIVolumeMounts := []corev1.VolumeMount{
			{MountPath: "/host/opt/cni/bin", Name: "cni-bin-dir"},
			{MountPath: "/host/etc/cni/net.d", Name: "cni-net-dir"},
		}
		Expect(rtest.GetContainer(ds.Spec.Template.Spec.InitContainers, "install-cni").VolumeMounts).To(ConsistOf(expectedCNIVolumeMounts))

		// FIXME: confirm RKE2 CNI path defaults
		expectedUninstallVolumeMounts := []corev1.VolumeMount{
			{MountPath: "/host/opt/cni/bin", Name: "cni-bin-dir"},
			{MountPath: "/host/etc/cni/net.d", Name: "cni-net-dir"},
		}
		Expect(rtest.GetContainer(ds.Spec.Template.Spec.InitContainers, "uninstall-calico").VolumeMounts).To(ConsistOf(expectedUninstallVolumeMounts))

		// Verify volumes
		// FIXME: confirm RKE2 CNI path defaults
		fileOrCreate := corev1.HostPathFileOrCreate
		dirOrCreate := corev1.HostPathDirectoryOrCreate
		expectedVols := []corev1.Volume{
			{Name: "lib-modules", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/lib/modules"}}},
			{Name: "var-run-calico", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/var/run/calico", Type: &dirOrCreate}}},
			{Name: "var-lib-calico", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/var/lib/calico", Type: &dirOrCreate}}},
			{Name: "xtables-lock", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/run/xtables.lock", Type: &fileOrCreate}}},
			{Name: "cni-bin-dir", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/opt/cni/bin", Type: &dirOrCreate}}},
			{Name: "cni-net-dir", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/etc/cni/net.d"}}},
			{Name: "cni-log-dir", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/var/log/calico/cni", Type: &dirOrCreate}}},
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
			{Name: "var-log-calico", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/var/log/calico", Type: &dirOrCreate}}},
		}
		Expect(ds.Spec.Template.Spec.Volumes).To(ConsistOf(expectedVols))

		expectedNodeEnv := []corev1.EnvVar{
			// Default envvars.
			{Name: "CNI_PLUGIN_TYPE", Value: "Calico"},
			{Name: "DATASTORE_TYPE", Value: "kubernetes"},
			{Name: "WAIT_FOR_DATASTORE", Value: "true"},
			{Name: "CALICO_MANAGE_CNI", Value: "true"},
			{Name: "CALICO_NETWORKING_BACKEND", Value: "windows-bgp"},
			{Name: "CLUSTER_TYPE", Value: "k8s,operator,bgp,windows"},
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
			{Name: "IP", Value: "autodetect"},
			{Name: "IP_AUTODETECTION_METHOD", Value: "first-found"},
			{Name: "IP6", Value: "none"},
			{Name: "FELIX_IPV6SUPPORT", Value: "false"},
			{Name: "FELIX_TYPHAK8SNAMESPACE", Value: "calico-system"},
			{Name: "FELIX_TYPHAK8SSERVICENAME", Value: "calico-typha"},
			{Name: "FELIX_TYPHACAFILE", Value: certificatemanagement.TrustedCertBundleMountPath},
			{Name: "FELIX_TYPHACERTFILE", Value: "/node-certs/tls.crt"},
			{Name: "FELIX_TYPHACN", Value: "typha-server"},
			{Name: "FELIX_TYPHAKEYFILE", Value: "/node-certs/tls.key"},

			{Name: "FELIX_DNSTRUSTEDSERVERS", Value: "k8s-service:kube-system/rke2-coredns-rke2-coredns"},

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

			// Calico Windows specific envvars
			{Name: "VXLAN_VNI", Value: "4096"},
			{Name: "VXLAN_ADAPTER", Value: ""},
			{Name: "KUBE_NETWORK", Value: "Calico.*"},
			{Name: "KUBERNETES_SERVICE_HOST", Value: "1.2.3.4"},
			{Name: "KUBERNETES_SERVICE_PORT", Value: "6443"},
		}
		Expect(ds.Spec.Template.Spec.Containers[0].Env).To(ConsistOf(expectedNodeEnv))
		Expect(len(ds.Spec.Template.Spec.Containers[0].Env)).To(Equal(len(expectedNodeEnv)))

		verifyWindowsProbesAndLifecycle(ds, false)

		// The metrics service should have the correct configuration.
		ms := rtest.GetResource(resources, "calico-node-metrics-windows", "calico-system", "", "v1", "Service").(*corev1.Service)
		Expect(ms.Spec.ClusterIP).To(Equal("None"), "metrics service should be headless to prevent kube-proxy from rendering too many iptables rules")
	})

	Describe("AKS", func() {
		It("should avoid virtual nodes", func() {
			defaultInstance.KubernetesProvider = operatorv1.ProviderAKS
			component := render.Windows(&cfg)
			Expect(component.ResolveImages(nil)).To(BeNil())
			resources, _ := component.Objects()
			dsResource := rtest.GetResource(resources, "calico-node-windows", "calico-system", "apps", "v1", "DaemonSet")
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
			component := render.Windows(&cfg)
			Expect(component.ResolveImages(nil)).To(BeNil())
			resources, _ := component.Objects()
			dsResource := rtest.GetResource(resources, "calico-node-windows", "calico-system", "apps", "v1", "DaemonSet")
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
			component := render.Windows(&cfg)
			Expect(component.ResolveImages(nil)).To(BeNil())
			resources, _ := component.Objects()
			Expect(len(resources)).To(Equal(defaultNumExpectedResources))

			dsResource := rtest.GetResource(resources, "calico-node-windows", "calico-system", "apps", "v1", "DaemonSet")
			Expect(dsResource).ToNot(BeNil())

			// The DaemonSet should have the correct configuration.
			ds := dsResource.(*appsv1.DaemonSet)

			// The pod template should have node critical priority
			Expect(ds.Spec.Template.Spec.PriorityClassName).To(Equal(render.NodePriorityClassName))

			felixContainer := rtest.GetContainer(ds.Spec.Template.Spec.Containers, "felix")
			rtest.ExpectEnv(felixContainer.Env, "IP_AUTODETECTION_METHOD", "can-reach=1.1.1.1")
		})

		It("should support interface regex", func() {
			defaultInstance.CalicoNetwork.NodeAddressAutodetectionV4.FirstFound = nil
			defaultInstance.CalicoNetwork.NodeAddressAutodetectionV4.Interface = "eth*"
			component := render.Windows(&cfg)
			Expect(component.ResolveImages(nil)).To(BeNil())
			resources, _ := component.Objects()
			Expect(len(resources)).To(Equal(defaultNumExpectedResources))

			dsResource := rtest.GetResource(resources, "calico-node-windows", "calico-system", "apps", "v1", "DaemonSet")
			Expect(dsResource).ToNot(BeNil())

			// The DaemonSet should have the correct configuration.
			ds := dsResource.(*appsv1.DaemonSet)

			// The pod template should have node critical priority
			Expect(ds.Spec.Template.Spec.PriorityClassName).To(Equal(render.NodePriorityClassName))

			felixContainer := rtest.GetContainer(ds.Spec.Template.Spec.Containers, "felix")
			rtest.ExpectEnv(felixContainer.Env, "IP_AUTODETECTION_METHOD", "interface=eth*")
		})

		It("should support skip-interface regex", func() {
			defaultInstance.CalicoNetwork.NodeAddressAutodetectionV4.FirstFound = nil
			defaultInstance.CalicoNetwork.NodeAddressAutodetectionV4.SkipInterface = "eth*"
			component := render.Windows(&cfg)
			Expect(component.ResolveImages(nil)).To(BeNil())
			resources, _ := component.Objects()
			Expect(len(resources)).To(Equal(defaultNumExpectedResources))

			dsResource := rtest.GetResource(resources, "calico-node-windows", "calico-system", "apps", "v1", "DaemonSet")
			Expect(dsResource).ToNot(BeNil())

			// The DaemonSet should have the correct configuration.
			ds := dsResource.(*appsv1.DaemonSet)

			// The pod template should have node critical priority
			Expect(ds.Spec.Template.Spec.PriorityClassName).To(Equal(render.NodePriorityClassName))

			felixContainer := rtest.GetContainer(ds.Spec.Template.Spec.Containers, "felix")
			rtest.ExpectEnv(felixContainer.Env, "IP_AUTODETECTION_METHOD", "skip-interface=eth*")
		})

		It("should support cidr", func() {
			defaultInstance.CalicoNetwork.NodeAddressAutodetectionV4.FirstFound = nil
			defaultInstance.CalicoNetwork.NodeAddressAutodetectionV4.CIDRS = []string{"10.0.1.0/24", "10.0.2.0/24"}
			component := render.Windows(&cfg)
			Expect(component.ResolveImages(nil)).To(BeNil())
			resources, _ := component.Objects()
			Expect(len(resources)).To(Equal(defaultNumExpectedResources))

			dsResource := rtest.GetResource(resources, "calico-node-windows", "calico-system", "apps", "v1", "DaemonSet")
			Expect(dsResource).ToNot(BeNil())

			// The DaemonSet should have the correct configuration.
			ds := dsResource.(*appsv1.DaemonSet)

			// The pod template should have node critical priority
			Expect(ds.Spec.Template.Spec.PriorityClassName).To(Equal(render.NodePriorityClassName))

			felixContainer := rtest.GetContainer(ds.Spec.Template.Spec.Containers, "felix")
			rtest.ExpectEnv(felixContainer.Env, "IP_AUTODETECTION_METHOD", "cidr=10.0.1.0/24,10.0.2.0/24")
		})
	})

	It("should not enable prometheus metrics if NodeMetricsPort is nil", func() {
		defaultInstance.Variant = operatorv1.CalicoEnterprise
		defaultInstance.NodeMetricsPort = nil
		cfg.NodeReporterMetricsPort = 9081

		component := render.Windows(&cfg)
		Expect(component.ResolveImages(nil)).To(BeNil())
		resources, _ := component.Objects()
		Expect(len(resources)).To(Equal(defaultNumExpectedResources + 1))

		dsResource := rtest.GetResource(resources, "calico-node-windows", "calico-system", "apps", "v1", "DaemonSet")
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
		component := render.Windows(&cfg)
		Expect(component.ResolveImages(nil)).To(BeNil())
		resources, _ := component.Objects()
		Expect(len(resources)).To(Equal(defaultNumExpectedResources + 1))

		dsResource := rtest.GetResource(resources, "calico-node-windows", "calico-system", "apps", "v1", "DaemonSet")
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

	It("should render MaxUnavailable if a custom value was set", func() {
		two := intstr.FromInt(2)
		defaultInstance.NodeUpdateStrategy.RollingUpdate.MaxUnavailable = &two
		component := render.Windows(&cfg)
		Expect(component.ResolveImages(nil)).To(BeNil())
		resources, _ := component.Objects()
		Expect(len(resources)).To(Equal(defaultNumExpectedResources))

		dsResource := rtest.GetResource(resources, "calico-node-windows", "calico-system", "apps", "v1", "DaemonSet")
		Expect(dsResource).ToNot(BeNil())
		ds := dsResource.(*appsv1.DaemonSet)
		Expect(ds).ToNot(BeNil())

		Expect(ds.Spec.UpdateStrategy.RollingUpdate.MaxUnavailable).To(Equal(&two))
	})

	It("should render cni config with host-local", func() {
		defaultInstance.CNI.IPAM.Type = operatorv1.IPAMPluginHostLocal
		component := render.Windows(&cfg)
		Expect(component.ResolveImages(nil)).To(BeNil())
		resources, _ := component.Objects()
		Expect(len(resources)).To(Equal(defaultNumExpectedResources))

		// Should render the correct resources.
		cniCmResource := rtest.GetResource(resources, "cni-config-windows", "calico-system", "", "v1", "ConfigMap")
		Expect(cniCmResource).ToNot(BeNil())
		cniCm := cniCmResource.(*corev1.ConfigMap)

		Expect(cniCm.Data["config"]).To(MatchJSON(`{
"name": "Calico",
"cniVersion": "1.0.0",
"plugins": [
  {
	"DNS": {
	  "Nameservers": [
		"10.96.0.10"
	  ],
	  "Search": [
		"svc.cluster.local"
	  ]
	},
	"capabilities": {
	  "dns": true
	},
	"datastore_type": "kubernetes",
	"ipam": {
	  "subnet": "usePodCidr",
	  "type": "host-local"
	},
	"kubernetes": {
	  "k8s_api_root": "https://1.2.3.4:6443",
	  "kubeconfig": "c:/etc/cni/net.d/calico-kubeconfig"
	},
	"log_file_max_age": 5,
	"log_file_max_count": 5,
	"log_file_max_size": 1,
	"log_file_path": "c:/var/log/calico/cni/cni.log",
	"log_level": "Debug",
	"mode": "windows-bgp",
	"mtu": 0,
	"name": "Calico",
	"nodename": "__KUBERNETES_NODE_NAME__",
	"nodename_file": "__NODENAME_FILE__",
	"nodename_file_optional": true,
	"policies": [
	  {
		"Name": "EndpointPolicy",
		"Value": {
		  "ExceptionList": [
			"10.96.0.0/12"
		  ],
		  "Type": "OutBoundNAT"
		}
	  },
	  {
		"Name": "EndpointPolicy",
		"Value": {
		  "DestinationPrefix": "10.96.0.0/12",
		  "NeedEncap": true,
		  "Type": "SDNROUTE"
		}
	  }
	],
	"policy": {
	  "type": "k8s"
	},
	"type": "calico",
	"vxlan_mac_prefix": "0E-2A",
	"vxlan_vni": 4096,
	"windows_loopback_DSR": "__DSR_SUPPORT__",
	"windows_use_single_network": true
  }
]
}`))
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
				ComponentName:        operatorv1.ComponentNameNodeWindows,
				ResourceRequirements: rr,
			},
			{
				ComponentName:        operatorv1.ComponentNameFelixWindows,
				ResourceRequirements: rr,
			},
			{
				ComponentName:        operatorv1.ComponentNameConfdWindows,
				ResourceRequirements: rr,
			},
		}

		component := render.Windows(&cfg)
		Expect(component.ResolveImages(nil)).To(BeNil())
		resources, _ := component.Objects()

		dsResource := rtest.GetResource(resources, "calico-node-windows", "calico-system", "apps", "v1", "DaemonSet")
		Expect(dsResource).ToNot(BeNil())
		ds := dsResource.(*appsv1.DaemonSet)

		felixContainer := rtest.GetContainer(ds.Spec.Template.Spec.Containers, "felix")
		Expect(felixContainer.Resources).To(Equal(*rr))
		nodeContainer := rtest.GetContainer(ds.Spec.Template.Spec.Containers, "node")
		Expect(nodeContainer.Resources).To(Equal(*rr))
		confdContainer := rtest.GetContainer(ds.Spec.Template.Spec.Containers, "confd")
		Expect(confdContainer.Resources).To(Equal(*rr))
	})

	It("should render when configured to use cloud routes with host-local", func() {
		expectedResources := []struct {
			name    string
			ns      string
			group   string
			version string
			kind    string
		}{
			{name: "cni-config-windows", ns: common.CalicoNamespace, group: "", version: "v1", kind: "ConfigMap"},
			{name: common.WindowsDaemonSetName, ns: common.CalicoNamespace, group: "apps", version: "v1", kind: "DaemonSet"},
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
		component := render.Windows(&cfg)
		Expect(component.ResolveImages(nil)).To(BeNil())
		resources, _ := component.Objects()
		Expect(len(resources)).To(Equal(len(expectedResources)))

		// Should render the correct resources.
		i := 0
		for _, expectedRes := range expectedResources {
			rtest.ExpectResourceTypeAndObjectMetadata(resources[i], expectedRes.name, expectedRes.ns, expectedRes.group, expectedRes.version, expectedRes.kind)
			i++
		}

		cniCmResource := rtest.GetResource(resources, "cni-config-windows", "calico-system", "", "v1", "ConfigMap")
		Expect(cniCmResource).ToNot(BeNil())
		cniCm := cniCmResource.(*corev1.ConfigMap)
		Expect(cniCm.Data["config"]).To(MatchJSON(`{
"name": "Calico",
"cniVersion": "1.0.0",
"plugins": [
  {
	"DNS": {
	  "Nameservers": [
		"10.96.0.10"
	  ],
	  "Search": [
		"svc.cluster.local"
	  ]
	},
	"capabilities": {
	  "dns": true
	},
	"datastore_type": "kubernetes",
	"ipam": {
	  "subnet": "usePodCidr",
	  "type": "host-local"
	},
	"kubernetes": {
	  "k8s_api_root": "https://1.2.3.4:6443",
	  "kubeconfig": "c:/etc/cni/net.d/calico-kubeconfig"
	},
	"log_file_max_age": 5,
	"log_file_max_count": 5,
	"log_file_max_size": 1,
	"log_file_path": "c:/var/log/calico/cni/cni.log",
	"log_level": "Debug",
	"mode": "none",
	"mtu": 0,
	"name": "Calico",
	"nodename": "__KUBERNETES_NODE_NAME__",
	"nodename_file": "__NODENAME_FILE__",
	"nodename_file_optional": true,
	"policies": [
	  {
		"Name": "EndpointPolicy",
		"Value": {
		  "ExceptionList": [
			"10.96.0.0/12"
		  ],
		  "Type": "OutBoundNAT"
		}
	  },
	  {
		"Name": "EndpointPolicy",
		"Value": {
		  "DestinationPrefix": "10.96.0.0/12",
		  "NeedEncap": true,
		  "Type": "SDNROUTE"
		}
	  }
	],
	"policy": {
	  "type": "k8s"
	},
	"type": "calico",
	"vxlan_mac_prefix": "0E-2A",
	"vxlan_vni": 4096,
	"windows_loopback_DSR": "__DSR_SUPPORT__",
	"windows_use_single_network": true
  }
]
}`))

		dsResource := rtest.GetResource(resources, "calico-node-windows", "calico-system", "apps", "v1", "DaemonSet")
		Expect(dsResource).ToNot(BeNil())

		// The DaemonSet should have the correct configuration.
		ds := dsResource.(*appsv1.DaemonSet)

		// The pod template should have node critical priority
		Expect(ds.Spec.Template.Spec.PriorityClassName).To(Equal(render.NodePriorityClassName))

		nodeContainer := rtest.GetContainer(ds.Spec.Template.Spec.Containers, "node")
		felixContainer := rtest.GetContainer(ds.Spec.Template.Spec.Containers, "node")

		cniContainer := rtest.GetContainer(ds.Spec.Template.Spec.InitContainers, "install-cni")
		rtest.ExpectEnv(cniContainer.Env, "CNI_NET_DIR", "/etc/cni/net.d")

		// Node image override results in correct image.
		Expect(nodeContainer.Image).To(Equal(fmt.Sprintf("quay.io/%s%s:%s", components.CalicoImagePath, components.ComponentCalicoNodeWindows.Image, components.ComponentCalicoNodeWindows.Version)))
		Expect(felixContainer.Image).To(Equal(fmt.Sprintf("quay.io/%s%s:%s", components.CalicoImagePath, components.ComponentCalicoNodeWindows.Image, components.ComponentCalicoNodeWindows.Version)))

		// Validate correct number of init containers.
		Expect(len(ds.Spec.Template.Spec.InitContainers)).To(Equal(2))

		// CNI container uses image override.
		Expect(rtest.GetContainer(ds.Spec.Template.Spec.InitContainers, "install-cni").Image).To(Equal(fmt.Sprintf("quay.io/%s%s:%s", components.CalicoImagePath, components.ComponentCalicoCNIWindows.Image, components.ComponentCalicoCNIWindows.Version)))

		// uninstall container uses image override.
		Expect(rtest.GetContainer(ds.Spec.Template.Spec.InitContainers, "uninstall-calico").Image).To(Equal(fmt.Sprintf("quay.io/%s%s:%s", components.CalicoImagePath, components.ComponentCalicoNodeWindows.Image, components.ComponentCalicoNodeWindows.Version)))

		// Verify env
		expectedNodeEnv := []corev1.EnvVar{
			{Name: "CNI_PLUGIN_TYPE", Value: "Calico"},
			{Name: "DATASTORE_TYPE", Value: "kubernetes"},
			{Name: "WAIT_FOR_DATASTORE", Value: "true"},
			{Name: "CALICO_NETWORKING_BACKEND", Value: "none"},
			{Name: "CALICO_MANAGE_CNI", Value: "true"},
			{Name: "CALICO_DISABLE_FILE_LOGGING", Value: "false"},
			{Name: "CLUSTER_TYPE", Value: "k8s,operator,windows"},
			{Name: "USE_POD_CIDR", Value: "true"},
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
			{Name: "IP", Value: "autodetect"},
			{Name: "IP_AUTODETECTION_METHOD", Value: "first-found"},
			{Name: "IP6", Value: "none"},
			{Name: "FELIX_IPV6SUPPORT", Value: "false"},
			{Name: "FELIX_TYPHAK8SNAMESPACE", Value: "calico-system"},
			{Name: "FELIX_TYPHAK8SSERVICENAME", Value: "calico-typha"},
			{Name: "FELIX_TYPHACAFILE", Value: certificatemanagement.TrustedCertBundleMountPath},
			{Name: "FELIX_TYPHACERTFILE", Value: "/node-certs/tls.crt"},
			{Name: "FELIX_TYPHACN", Value: "typha-server"},
			{Name: "FELIX_TYPHAKEYFILE", Value: "/node-certs/tls.key"},

			{Name: "VXLAN_VNI", Value: "4096"},
			{Name: "VXLAN_ADAPTER", Value: ""},
			{Name: "KUBE_NETWORK", Value: "Calico.*"},
			{Name: "KUBERNETES_SERVICE_HOST", Value: "1.2.3.4"},
			{Name: "KUBERNETES_SERVICE_PORT", Value: "6443"},
		}
		Expect(nodeContainer.Env).To(ConsistOf(expectedNodeEnv))
		Expect(felixContainer.Env).To(ConsistOf(expectedNodeEnv))

		expectedCNIEnv := []corev1.EnvVar{
			{Name: "SLEEP", Value: "false"},
			{Name: "CNI_PLUGIN_TYPE", Value: "Calico"},
			{Name: "CNI_BIN_DIR", Value: "/host/opt/cni/bin"},
			{Name: "CNI_CONF_NAME", Value: "10-calico.conflist"},
			{Name: "CNI_NET_DIR", Value: "/etc/cni/net.d"},
			{Name: "VXLAN_VNI", Value: "4096"},
			{
				Name:  "KUBERNETES_NODE_NAME",
				Value: "",
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

			{Name: "KUBERNETES_SERVICE_HOST", Value: "1.2.3.4"},
			{Name: "KUBERNETES_SERVICE_PORT", Value: "6443"},
			{Name: "KUBERNETES_SERVICE_CIDRS", Value: "10.96.0.0/12"},
			{Name: "KUBERNETES_DNS_SERVERS", Value: "10.96.0.10"},
		}
		Expect(rtest.GetContainer(ds.Spec.Template.Spec.InitContainers, "install-cni").Env).To(ConsistOf(expectedCNIEnv))

		expectedUninstallEnv := []corev1.EnvVar{
			{Name: "SLEEP", Value: "false"},
			{Name: "CNI_PLUGIN_TYPE", Value: "Calico"},
			{Name: "CNI_BIN_DIR", Value: "/host/opt/cni/bin"},
			{Name: "CNI_CONF_NAME", Value: "10-calico.conflist"},
			{Name: "CNI_NET_DIR", Value: "/host/etc/cni/net.d"},
		}
		Expect(rtest.GetContainer(ds.Spec.Template.Spec.InitContainers, "uninstall-calico").Env).To(ConsistOf(expectedUninstallEnv))

		// Verify readiness and liveness probes.
		verifyWindowsProbesAndLifecycle(ds, true)
	})

	Context("With calico-node-windows DaemonSet overrides", func() {
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

		It("should handle calicoNodeWindowsDaemonSet overrides", func() {
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

			defaultInstance.CalicoNodeWindowsDaemonSet = &operatorv1.CalicoNodeWindowsDaemonSet{
				Metadata: &operatorv1.Metadata{
					Labels:      map[string]string{"top-level": "label1"},
					Annotations: map[string]string{"top-level": "annot1"},
				},
				Spec: &operatorv1.CalicoNodeWindowsDaemonSetSpec{
					MinReadySeconds: &minReadySeconds,
					Template: &operatorv1.CalicoNodeWindowsDaemonSetPodTemplateSpec{
						Metadata: &operatorv1.Metadata{
							Labels:      map[string]string{"template-level": "label2"},
							Annotations: map[string]string{"template-level": "annot2"},
						},
						Spec: &operatorv1.CalicoNodeWindowsDaemonSetPodSpec{
							Containers: []operatorv1.CalicoNodeWindowsDaemonSetContainer{
								{
									Name:      "node",
									Resources: &rr1,
								},
								{
									Name:      "felix",
									Resources: &rr1,
								},
								{
									Name:      "confd",
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

			component := render.Windows(&cfg)
			resources, _ := component.Objects()
			dsResource := rtest.GetResource(resources, "calico-node-windows", "calico-system", "apps", "v1", "DaemonSet")
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
			// adds standard labels such as "k8s-app=calico-node-windows" and
			// the host-networked marker. The daemonset object produced by the
			// render itself only carries the override-supplied template-level
			// label; the rest are layered on during apply.
			Expect(ds.Spec.Template.Labels).To(HaveLen(1))
			Expect(ds.Spec.Template.Labels["template-level"]).To(Equal("label2"))

			// With the default instance we expect 3 template-level annotations
			// - 2 added by the operator by default
			// - 1 added by the calicoNodeWindowsDaemonSet override
			Expect(ds.Spec.Template.Annotations).To(HaveLen(3))
			Expect(ds.Spec.Template.Annotations).To(HaveKey("tigera-operator.hash.operator.tigera.io/tigera-ca-private"))
			Expect(ds.Spec.Template.Annotations).To(HaveKey("hash.operator.tigera.io/cni-config"))
			Expect(ds.Spec.Template.Annotations["template-level"]).To(Equal("annot2"))

			Expect(ds.Spec.Template.Spec.Containers).To(HaveLen(3))
			nodeContainer := rtest.GetContainer(ds.Spec.Template.Spec.Containers, "node")
			Expect(nodeContainer.Resources).To(Equal(rr1))
			felixContainer := rtest.GetContainer(ds.Spec.Template.Spec.Containers, "felix")
			Expect(felixContainer.Resources).To(Equal(rr1))
			confdContainer := rtest.GetContainer(ds.Spec.Template.Spec.Containers, "confd")
			Expect(confdContainer.Resources).To(Equal(rr1))

			Expect(ds.Spec.Template.Spec.NodeSelector).To(HaveLen(2))
			Expect(ds.Spec.Template.Spec.NodeSelector).To(HaveKeyWithValue("custom-node-selector", "value"))
			Expect(ds.Spec.Template.Spec.NodeSelector).To(HaveKeyWithValue("kubernetes.io/os", "windows"))

			Expect(ds.Spec.Template.Spec.Tolerations).To(HaveLen(1))
			Expect(ds.Spec.Template.Spec.Tolerations[0]).To(Equal(toleration))
		})

		It("should override ComponentResources", func() {
			defaultInstance.ComponentResources = []operatorv1.ComponentResource{
				{
					ComponentName:        operatorv1.ComponentNameNode,
					ResourceRequirements: &rr1,
				},
			}

			defaultInstance.CalicoNodeWindowsDaemonSet = &operatorv1.CalicoNodeWindowsDaemonSet{
				Spec: &operatorv1.CalicoNodeWindowsDaemonSetSpec{
					Template: &operatorv1.CalicoNodeWindowsDaemonSetPodTemplateSpec{
						Spec: &operatorv1.CalicoNodeWindowsDaemonSetPodSpec{
							Containers: []operatorv1.CalicoNodeWindowsDaemonSetContainer{
								{
									Name:      "node",
									Resources: &rr2,
								},
								{
									Name:      "felix",
									Resources: &rr2,
								},
								{
									Name:      "confd",
									Resources: &rr2,
								},
							},
						},
					},
				},
			}

			component := render.Windows(&cfg)
			resources, _ := component.Objects()
			dsResource := rtest.GetResource(resources, "calico-node-windows", "calico-system", "apps", "v1", "DaemonSet")
			Expect(dsResource).ToNot(BeNil())

			ds := dsResource.(*appsv1.DaemonSet)
			Expect(ds.Spec.Template.Spec.Containers).To(HaveLen(3))
			nodeContainer := rtest.GetContainer(ds.Spec.Template.Spec.Containers, "node")
			Expect(nodeContainer.Resources).To(Equal(rr2))
			felixContainer := rtest.GetContainer(ds.Spec.Template.Spec.Containers, "felix")
			Expect(felixContainer.Resources).To(Equal(rr2))
			confdContainer := rtest.GetContainer(ds.Spec.Template.Spec.Containers, "confd")
			Expect(confdContainer.Resources).To(Equal(rr2))
		})
	})
})

// verifyWindowsProbesAndLifecycle asserts the expected node liveness and readiness probe plus pod lifecycle settings.
// The unused argument is kept temporarily so existing call sites compile while the OSS/Enterprise distinction
// is being phased out.
func verifyWindowsProbesAndLifecycle(ds *appsv1.DaemonSet, _ bool) {
	livenessCmd := []string{"$env:CONTAINER_SANDBOX_MOUNT_POINT/CalicoWindows/calico.exe", "component", "node", "health", "--felix-live"}
	readinessCmd := []string{"$env:CONTAINER_SANDBOX_MOUNT_POINT/CalicoWindows/calico.exe", "component", "node", "health", "--felix-ready"}
	preStopCmd := []string{"$env:CONTAINER_SANDBOX_MOUNT_POINT/CalicoWindows/calico.exe", "component", "node", "shutdown"}

	expectedLiveness := &corev1.Probe{
		ProbeHandler: corev1.ProbeHandler{
			Exec: &corev1.ExecAction{Command: livenessCmd},
		},
		InitialDelaySeconds: 10,
		FailureThreshold:    6,
		TimeoutSeconds:      10,
		PeriodSeconds:       10,
	}
	ExpectWithOffset(1, rtest.GetContainer(ds.Spec.Template.Spec.Containers, "felix").LivenessProbe).To(Equal(expectedLiveness))

	expectedReadiness := &corev1.Probe{
		ProbeHandler: corev1.ProbeHandler{
			Exec: &corev1.ExecAction{Command: readinessCmd},
		},
		TimeoutSeconds: 10,
		PeriodSeconds:  10,
	}
	ExpectWithOffset(1, rtest.GetContainer(ds.Spec.Template.Spec.Containers, "felix").ReadinessProbe).To(Equal(expectedReadiness))

	expectedLifecycle := &corev1.Lifecycle{
		PreStop: &corev1.LifecycleHandler{
			Exec: &corev1.ExecAction{Command: preStopCmd},
		},
	}
	ExpectWithOffset(1, rtest.GetContainer(ds.Spec.Template.Spec.Containers, "felix").Lifecycle).To(Equal(expectedLifecycle))
}
