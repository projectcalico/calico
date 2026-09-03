// Copyright (c) 2022-2026 Tigera, Inc. All rights reserved.

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
	"bufio"
	"bytes"
	"fmt"
	glog "log"
	"reflect"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"

	operatorv1 "github.com/projectcalico/calico/operator/api/v1"
	"github.com/projectcalico/calico/operator/pkg/apis"
	"github.com/projectcalico/calico/operator/pkg/common"
	"github.com/projectcalico/calico/operator/pkg/controller/certificatemanager"
	"github.com/projectcalico/calico/operator/pkg/controller/k8sapi"
	ctrlrfake "github.com/projectcalico/calico/operator/pkg/ctrlruntime/client/fake"
	"github.com/projectcalico/calico/operator/pkg/dns"
	"github.com/projectcalico/calico/operator/pkg/render"
	rcertificatemanagement "github.com/projectcalico/calico/operator/pkg/render/certificatemanagement"
	rtest "github.com/projectcalico/calico/operator/pkg/render/common/test"
	"github.com/projectcalico/calico/operator/pkg/render/kubecontrollers"
)

const clusterDomain = "cluster.local"

// allCalicoComponents takes the given configuration and returns all the components
// associated with installing Calico's core, similar to how the core_controller behaves.
func allCalicoComponents(
	k8sServiceEp k8sapi.ServiceEndpoint,
	cr *operatorv1.InstallationSpec,
	managementClusterConnection *operatorv1.ManagementClusterConnection,
	pullSecrets []*corev1.Secret,
	typhaNodeTLS *render.TyphaNodeTLS,
	bt map[string]string,
	up bool,
	nodeAppArmorProfile string,
	clusterDomain string,
	kubeControllersMetricsPort int,
	bgpLayout *corev1.ConfigMap,
) ([]render.Component, error) {
	namespaces := render.Namespaces(&render.NamespaceConfiguration{Installation: cr, PullSecrets: pullSecrets})

	objs := []client.Object{}
	if bgpLayout != nil {
		objs = append(objs, bgpLayout)
	}
	secretsAndConfigMaps := render.NewCreationPassthrough(objs...)

	nodeCfg := &render.NodeConfiguration{
		K8sServiceEp:        k8sServiceEp,
		Installation:        cr,
		TLS:                 typhaNodeTLS,
		NodeAppArmorProfile: nodeAppArmorProfile,
		ClusterDomain:       clusterDomain,
		BGPLayouts:          bgpLayout,
		BirdTemplates:       bt,
		MigrateNamespaces:   up,
		FelixConfiguration:  &v3.FelixConfiguration{Spec: v3.FelixConfigurationSpec{HealthPort: ptr.To(9099)}},
	}
	typhaCfg := &render.TyphaConfiguration{
		K8sServiceEp:       k8sServiceEp,
		Installation:       cr,
		TLS:                typhaNodeTLS,
		ClusterDomain:      clusterDomain,
		MigrateNamespaces:  up,
		FelixConfiguration: &v3.FelixConfiguration{Spec: v3.FelixConfigurationSpec{HealthPort: ptr.To(9099)}},
	}
	kcCfg := &kubecontrollers.KubeControllersConfiguration{
		K8sServiceEp:      k8sServiceEp,
		Installation:      cr,
		ClusterDomain:     clusterDomain,
		MetricsPort:       kubeControllersMetricsPort,
		Namespace:         common.CalicoNamespace,
		BindingNamespaces: []string{common.CalicoNamespace},
	}

	winCfg := &render.WindowsConfiguration{
		K8sServiceEp:  k8sServiceEp,
		K8sDNSServers: []string{},
		Installation:  cr,
		ClusterDomain: clusterDomain,
		TLS:           typhaNodeTLS,
		VXLANVNI:      4096,
	}

	nodeCertComponent := rcertificatemanagement.CertificateManagement(&rcertificatemanagement.Config{
		Namespace:       common.CalicoNamespace,
		ServiceAccounts: []string{render.CalicoNodeObjectName, render.TyphaServiceAccountName},
		KeyPairOptions: []rcertificatemanagement.KeyPairOption{
			rcertificatemanagement.NewKeyPairOption(typhaNodeTLS.NodeSecret, true, true),
			rcertificatemanagement.NewKeyPairOption(typhaNodeTLS.TyphaSecret, true, true),
		},
		TrustedBundle: typhaNodeTLS.TrustedBundle,
	})

	return []render.Component{namespaces, secretsAndConfigMaps, render.Typha(typhaCfg), render.Node(nodeCfg), kubecontrollers.NewCalicoKubeControllers(kcCfg), render.Windows(winCfg), nodeCertComponent}, nil
}

var _ = Describe("Rendering tests", func() {
	var instance *operatorv1.InstallationSpec
	var logBuffer bytes.Buffer
	var logWriter *bufio.Writer
	var typhaNodeTLS *render.TyphaNodeTLS
	logSeverity := operatorv1.LogLevelInfo
	logFileMaxSize := resource.MustParse("100Mi")
	var logFileMaxAgeDays uint32 = 30
	var logFileMaxCount uint32 = 10
	one := intstr.FromInt(1)
	miMode := operatorv1.MultiInterfaceModeNone
	k8sServiceEp := k8sapi.ServiceEndpoint{}
	defaultCNIConfDir, defaultCNIBinDir := "/etc/cni/net.d", "/opt/cni/bin"

	BeforeEach(func() {
		// Initialize a default instance to use. Each test can override this to its
		// desired configuration.
		instance = &operatorv1.InstallationSpec{
			CNI: &operatorv1.CNISpec{
				Type: operatorv1.PluginCalico,
				IPAM: &operatorv1.IPAMSpec{
					Type: operatorv1.IPAMPluginCalico,
				},
				BinDir:  &defaultCNIBinDir,
				ConfDir: &defaultCNIConfDir,
			},
			CalicoNetwork: &operatorv1.CalicoNetworkSpec{
				IPPools:            []operatorv1.IPPool{{CIDR: "192.168.1.0/16"}},
				MultiInterfaceMode: &miMode,
			},
			Registry: "test-reg/",
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
		scheme := runtime.NewScheme()
		Expect(apis.AddToScheme(scheme, false)).NotTo(HaveOccurred())

		cli := ctrlrfake.DefaultFakeClientBuilder(scheme).Build()
		certificateManager, err := certificatemanager.Create(cli, nil, clusterDomain, common.OperatorNamespace(), certificatemanager.AllowCACreation())
		Expect(err).NotTo(HaveOccurred())

		typhaNodeTLS = getTyphaNodeTLS(cli, certificateManager)
		logWriter = bufio.NewWriter(&logBuffer)
		render.SetTestLogger(zap.New(zap.UseDevMode(true), zap.WriteTo(logWriter)))
	})

	AfterEach(func() {
		if CurrentSpecReport().Failed() {
			err := logWriter.Flush()
			Expect(err).NotTo(HaveOccurred())
			fmt.Printf("Logs:\n%s\n", logBuffer.String())
		}
	})

	It("should render all resources for a default configuration", func() {
		// For this scenario, we expect the basic resources
		// created by the controller without any optional ones. These include:
		// - 5 node resources (ServiceAccount, ClusterRole, Binding, ConfigMap, DaemonSet)
		// - 3 calico-cni-plugin resources (ServiceAccount, ClusterRole, ClusterRoleBinding)
		// - 4 secrets for Typha comms (2 in operator namespace and 2 in calico namespace)
		// - 1 ConfigMap for Typha comms (1 in calico namespace)
		// - 6 typha resources (Service, SA, Role, Binding, Deployment, PodDisruptionBudget)
		// - 6 kube-controllers resources (ServiceAccount, ClusterRole, Binding, Deployment, Service, Secret,RoleBinding)
		// - 1 namespace
		// - 2 Windows node resources (ConfigMap, DaemonSet)
		c, err := allCalicoComponents(k8sServiceEp, instance, nil, nil, typhaNodeTLS, nil, false, "", dns.DefaultClusterDomain, 9094, nil)
		Expect(err).To(BeNil(), "Expected Calico to create successfully %s", err)
		Expect(componentCount(c)).To(Equal(5 + 3 + 4 + 1 + 6 + 6 + 1 + 2))
	})

	It("should render all resources when variant is Tigera Secure", func() {
		// For this scenario, we expect the basic resources plus the following for Tigera Secure.
		// The calico/node and Windows calico/node metrics Services are added by the
		// enterprise modifiers at the componentHandler, not by Objects(), so they do
		// not appear in this render-only aggregation.
		var nodeMetricsPort int32 = 9081
		instance.Variant = operatorv1.CalicoEnterprise
		instance.NodeMetricsPort = &nodeMetricsPort
		c, err := allCalicoComponents(k8sServiceEp, instance, nil, nil, typhaNodeTLS, nil, false, "", dns.DefaultClusterDomain, 9094, nil)
		Expect(err).To(BeNil(), "Expected Calico to create successfully %s", err)
		Expect(componentCount(c)).To(Equal(5 + 3 + 4 + 1 + 6 + 6 + 1 + 2))
	})

	It("should render calico with a apparmor profile if annotation is present in installation", func() {
		apparmorProf := "foobar"
		comps, err := allCalicoComponents(k8sServiceEp, instance, nil, nil, typhaNodeTLS, nil, false, apparmorProf, dns.DefaultClusterDomain, 0, nil)
		Expect(err).To(BeNil(), "Expected Calico to create successfully %s", err)
		var cn *appsv1.DaemonSet
		for _, comp := range comps {
			resources, _ := comp.Objects()
			r := rtest.GetResource(resources, "calico-node", "calico-system", "apps", "v1", "DaemonSet")
			if r != nil {
				cn = r.(*appsv1.DaemonSet)
				break
			}
		}
		Expect(cn).ToNot(BeNil())
		Expect(cn.Spec.Template.ObjectMeta.Annotations["container.apparmor.security.beta.kubernetes.io/calico-node"]).To(Equal(apparmorProf))
	})

	It("should handle BGP layout ConfigMap", func() {
		bgpLayout := &corev1.ConfigMap{
			TypeMeta: metav1.TypeMeta{Kind: "ConfigMap", APIVersion: "v1"},
			Data: map[string]string{
				render.BGPLayoutConfigMapKey: "",
			},
		}
		bgpLayout.Name = "bgp-layout"
		bgpLayout.Namespace = common.OperatorNamespace()
		comps, err := allCalicoComponents(k8sServiceEp, instance, nil, nil, typhaNodeTLS, nil, false, "", dns.DefaultClusterDomain, 0, bgpLayout)
		Expect(err).To(BeNil(), "Expected Calico to create successfully %s", err)
		var cm *corev1.ConfigMap
		var ds *appsv1.DaemonSet
		for _, comp := range comps {
			resources, _ := comp.Objects()
			r := rtest.GetResource(resources, "bgp-layout", "calico-system", "", "v1", "ConfigMap")
			if r != nil {
				cm = r.(*corev1.ConfigMap)
			}
			r = rtest.GetResource(resources, "calico-node", "calico-system", "apps", "v1", "DaemonSet")
			if r != nil {
				ds = r.(*appsv1.DaemonSet)
			}
		}
		Expect(cm).ToNot(BeNil())
		Expect(ds).ToNot(BeNil())
		Expect(ds.Spec.Template.Annotations).To(HaveKey("hash.operator.tigera.io/bgp-layout"))
		Expect(ds.Spec.Template.Annotations["hash.operator.tigera.io/bgp-layout"]).NotTo(BeEmpty())
	})

	It("should set node priority class to system-node-critical", func() {
		comps, err := allCalicoComponents(k8sServiceEp, instance, nil, nil, typhaNodeTLS, nil, false, "", dns.DefaultClusterDomain, 0, nil)
		Expect(err).To(BeNil(), "Expected Calico to create successfully %s", err)
		var cn *appsv1.DaemonSet
		for _, comp := range comps {
			resources, _ := comp.Objects()
			r := rtest.GetResource(resources, common.NodeDaemonSetName, common.CalicoNamespace, "apps", "v1", "DaemonSet")
			if r != nil {
				cn = r.(*appsv1.DaemonSet)
				break
			}
		}
		Expect(cn).ToNot(BeNil())
		Expect(cn.Spec.Template.Spec.PriorityClassName).To(Equal("system-node-critical"))
	})

	It("should set typha priority class to system-cluster-critical", func() {
		comps, err := allCalicoComponents(k8sServiceEp, instance, nil, nil, typhaNodeTLS, nil, false, "", dns.DefaultClusterDomain, 0, nil)
		Expect(err).To(BeNil(), "Expected Calico to create successfully %s", err)
		var cn *appsv1.Deployment
		for _, comp := range comps {
			resources, _ := comp.Objects()
			r := rtest.GetResource(resources, common.TyphaDeploymentName, common.CalicoNamespace, "apps", "v1", "Deployment")
			if r != nil {
				cn = r.(*appsv1.Deployment)
				break
			}
		}
		Expect(cn).ToNot(BeNil())
		Expect(cn.Spec.Template.Spec.PriorityClassName).To(Equal("system-cluster-critical"))
	})

	It("should set kube controllers priority class to system-cluster-critical", func() {
		comps, err := allCalicoComponents(k8sServiceEp, instance, nil, nil, typhaNodeTLS, nil, false, "", dns.DefaultClusterDomain, 0, nil)
		Expect(err).To(BeNil(), "Expected Calico to create successfully %s", err)
		var cn *appsv1.Deployment
		for _, comp := range comps {
			resources, _ := comp.Objects()
			r := rtest.GetResource(resources, common.KubeControllersDeploymentName, common.CalicoNamespace, "apps", "v1", "Deployment")
			if r != nil {
				cn = r.(*appsv1.Deployment)
				break
			}
		}
		Expect(cn).ToNot(BeNil())
		Expect(cn.Spec.Template.Spec.PriorityClassName).To(Equal("system-cluster-critical"))
	})
})

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

func componentCount(components []render.Component) int {
	count := 0
	for _, c := range components {
		objsToCreate, _ := c.Objects()
		count += len(objsToCreate)
		glog.Printf("Component: %s\n", reflect.TypeOf(c))
		for i, o := range objsToCreate {
			glog.Printf(" - %d/%d: %s/%s\n", i, len(objsToCreate), o.GetNamespace(), o.GetName())
		}
	}
	return count
}
