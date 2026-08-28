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

package windows_test

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
	"github.com/tigera/operator/pkg/extensions/extensionstest"
	"github.com/tigera/operator/pkg/render"
	rmeta "github.com/tigera/operator/pkg/render/common/meta"
	rtest "github.com/tigera/operator/pkg/render/common/test"
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

// renderWindows renders the windows component and applies the registered
// enterprise modifier the way the componentHandler does, so enterprise tests
// exercise the integrated output (image overrides come from ResolveImages; the
// metrics service, env, volumes and mounts come from the modifier).
func renderWindows(cfg *render.WindowsConfiguration) []client.Object {
	comp := render.Windows(cfg)
	ExpectWithOffset(1, comp.ResolveImages(nil)).To(BeNil())
	objs, _ := comp.Objects()
	ri := render.Inputs{Installation: cfg.Installation}
	out, _ := ext.Windows().Modify(extensionstest.WindowsStub{StubComponent: extensionstest.StubComponent{Create: objs, Delete: nil}, Cfg: nil}, ri).Objects()
	return out
}

func getTyphaNodeTLS(cli client.Client, certificateManager certificatemanager.CertificateManager) *render.TyphaNodeTLS {
	nodeKeyPair, err := certificateManager.GetOrCreateKeyPair(cli, render.NodeTLSSecretName, common.OperatorNamespace(), []string{render.FelixCommonName})
	Expect(err).NotTo(HaveOccurred())

	typhaKeyPair, err := certificateManager.GetOrCreateKeyPair(cli, render.TyphaTLSSecretName, common.OperatorNamespace(), []string{render.FelixCommonName})
	Expect(err).NotTo(HaveOccurred())

	trustedBundle := certificateManager.CreateTrustedBundle(nodeKeyPair, typhaKeyPair)

	return &render.TyphaNodeTLS{
		TrustedBundle:   trustedBundle,
		TyphaSecret:     typhaKeyPair,
		TyphaCommonName: render.TyphaCommonName,
		NodeSecret:      nodeKeyPair,
		NodeCommonName:  render.FelixCommonName,
	}
}

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

var _ = Describe("Windows enterprise rendering tests", func() {
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
		certificateManager, err := certificatemanager.Create(cli, nil, defaultClusterDomain, common.OperatorNamespace(), certificatemanager.AllowCACreation())
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
					{name: "cni-config-windows", ns: common.CalicoNamespace, group: "", version: "v1", kind: "ConfigMap"},
					{name: common.WindowsDaemonSetName, ns: common.CalicoNamespace, group: "apps", version: "v1", kind: "DaemonSet"},
					{name: "calico-node-metrics-windows", ns: "calico-system", group: "", version: "v1", kind: "Service"},
				}
				defaultInstance.Variant = operatorv1.CalicoEnterprise

				resources := renderWindows(&cfg)
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

	It("should render all resources when variant is CalicoEnterprise and running on openshift", func() {
		expectedResources := []struct {
			name    string
			ns      string
			group   string
			version string
			kind    string
		}{
			{name: "cni-config-windows", ns: common.CalicoNamespace, group: "", version: "v1", kind: "ConfigMap"},
			{name: common.WindowsDaemonSetName, ns: common.CalicoNamespace, group: "apps", version: "v1", kind: "DaemonSet"},
			{name: "calico-node-metrics-windows", ns: "calico-system", group: "", version: "v1", kind: "Service"},
		}

		defaultInstance.Variant = operatorv1.CalicoEnterprise
		defaultInstance.KubernetesProvider = operatorv1.ProviderOpenShift

		resources := renderWindows(&cfg)
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
			{name: "cni-config-windows", ns: common.CalicoNamespace, group: "", version: "v1", kind: "ConfigMap"},
			{name: common.WindowsDaemonSetName, ns: common.CalicoNamespace, group: "apps", version: "v1", kind: "DaemonSet"},
			{name: "calico-node-metrics-windows", ns: "calico-system", group: "", version: "v1", kind: "Service"},
		}

		defaultInstance.Variant = operatorv1.CalicoEnterprise
		defaultInstance.KubernetesProvider = operatorv1.ProviderRKE2

		resources := renderWindows(&cfg)
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

	It("should not enable prometheus metrics if NodeMetricsPort is nil", func() {
		defaultInstance.Variant = operatorv1.CalicoEnterprise
		defaultInstance.NodeMetricsPort = nil

		resources := renderWindows(&cfg)
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
		resources := renderWindows(&cfg)
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
})
