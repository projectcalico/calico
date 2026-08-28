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

package gatewayapi

import (
	"context"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	admissionregv1 "k8s.io/api/admissionregistration/v1"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apiextenv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/utils/ptr"

	envoyapi "github.com/envoyproxy/gateway/api/v1alpha1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	gapi "sigs.k8s.io/gateway-api/apis/v1"
	"sigs.k8s.io/yaml"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/components"
	"github.com/tigera/operator/pkg/controller"
	"github.com/tigera/operator/pkg/imageoverride"
	"github.com/tigera/operator/pkg/render"
	rtest "github.com/tigera/operator/pkg/render/common/test"
	"github.com/tigera/operator/pkg/render/gatewayapi"
)

// l7CollectorImage stands in for the image ExtendInputs resolves.
const l7CollectorImage = "test-registry/l7-collector:latest"

func testScheme() *runtime.Scheme {
	s := runtime.NewScheme()
	Expect(scheme.AddToScheme(s)).ShouldNot(HaveOccurred())
	Expect(apiextenv1.AddToScheme(s)).ShouldNot(HaveOccurred())
	Expect(admissionregv1.AddToScheme(s)).ShouldNot(HaveOccurred())
	Expect(operatorv1.AddToScheme(s)).ShouldNot(HaveOccurred())
	return s
}

// enterpriseComponent renders the gateway API implementation the way the controller
// does, with the extension's image overrides and modifier applied.
func enterpriseComponent(cfg *gatewayapi.GatewayAPIImplementationConfig) render.Component {
	ext := New(operatorv1.CalicoEnterprise)
	cfg.Scheme = testScheme()
	cfg.ImageOverrides = imageoverride.New()
	RegisterImages(cfg.ImageOverrides, operatorv1.CalicoEnterprise)

	comp, err := gatewayapi.GatewayAPIImplementationComponent(cfg)
	Expect(err).NotTo(HaveOccurred())
	Expect(comp.ResolveImages(nil)).NotTo(HaveOccurred())

	return ext.Modify(comp, render.Inputs{
		Installation: cfg.Installation,
		Extension:    gatewayAPIRenderData{l7LogCollectorImage: l7CollectorImage},
	})
}

var _ = Describe("Gateway API enterprise extension", func() {
	AccessLogSettings := []envoyapi.ProxyAccessLogSetting{
		{
			Sinks: []envoyapi.ProxyAccessLogSink{
				{
					Type: envoyapi.ProxyAccessLogSinkTypeFile,
					File: &envoyapi.FileEnvoyProxyAccessLog{
						Path: "/access_logs/access.log",
					},
				},
			},
			Format: &envoyapi.ProxyAccessLogFormat{
				Type: ptr.To(envoyapi.ProxyAccessLogFormatTypeJSON),
				JSON: map[string]string{
					"reporter":                         "gateway",
					"start_time":                       "%START_TIME%",
					"duration":                         "%DURATION%",
					"response_code":                    "%RESPONSE_CODE%",
					"bytes_sent":                       "%BYTES_SENT%",
					"bytes_received":                   "%BYTES_RECEIVED%",
					"user_agent":                       "%REQ(USER-AGENT)%",
					"request_path":                     "%REQ(X-ENVOY-ORIGINAL-PATH?:PATH)%",
					"request_method":                   "%REQ(:METHOD)%",
					"request_id":                       "%REQ(X-REQUEST-ID)%",
					"type":                             "{{.}}",
					"downstream_remote_address":        "%DOWNSTREAM_REMOTE_ADDRESS%",
					"downstream_local_address":         "%DOWNSTREAM_LOCAL_ADDRESS%",
					"downstream_direct_remote_address": "%DOWNSTREAM_DIRECT_REMOTE_ADDRESS%",
					"domain":                           "%REQ(HOST?:AUTHORITY)%",
					"upstream_host":                    "%UPSTREAM_HOST%",
					"upstream_local_address":           "%UPSTREAM_LOCAL_ADDRESS%",
					"upstream_service_time":            "%RESP(X-ENVOY-UPSTREAM-SERVICE-TIME)%",
					"route_name":                       "%ROUTE_NAME%",
				},
			},
			Type: &accessLogType,
		},
	}

	It("patches every EnvoyProxy the render emits", func() {
		installation := &operatorv1.InstallationSpec{Variant: operatorv1.CalicoEnterprise}
		gatewayAPI := &operatorv1.GatewayAPI{
			Spec: operatorv1.GatewayAPISpec{
				GatewayClasses: []operatorv1.GatewayClassSpec{{Name: "one"}, {Name: "two"}, {Name: "three"}},
			},
		}
		gatewayComp := enterpriseComponent(&gatewayapi.GatewayAPIImplementationConfig{
			Installation: installation,
			GatewayAPI:   gatewayAPI,
		})

		objsToCreate, _ := gatewayComp.Objects()

		proxies := 0
		for _, o := range objsToCreate {
			if proxy, ok := o.(*envoyapi.EnvoyProxy); ok {
				proxies++
				Expect(proxy.Spec.Provider.Kubernetes.EnvoyDeployment.Pod.Volumes).NotTo(BeEmpty())
			}
		}
		Expect(proxies).To(Equal(3))
	})

	It("panics when a GatewayClass has no EnvoyProxy to patch", func() {
		cfg := &gatewayapi.GatewayAPIImplementationConfig{
			Installation: &operatorv1.InstallationSpec{Variant: operatorv1.CalicoEnterprise},
			GatewayAPI: &operatorv1.GatewayAPI{
				Spec: operatorv1.GatewayAPISpec{
					GatewayClasses: []operatorv1.GatewayClassSpec{{Name: "one"}, {Name: "two"}},
				},
			},
		}
		ri := render.Inputs{
			Installation: cfg.Installation,
			Extension:    gatewayAPIRenderData{l7LogCollectorImage: l7CollectorImage},
		}
		create := []client.Object{&envoyapi.EnvoyProxy{}}

		Expect(func() { modifyImplementation(ri, cfg, create, nil) }).To(Panic())
	})

	It("tolerates a GatewayAPI with no GatewayClasses", func() {
		gatewayComp := enterpriseComponent(&gatewayapi.GatewayAPIImplementationConfig{
			Installation: &operatorv1.InstallationSpec{Variant: operatorv1.CalicoEnterprise},
			GatewayAPI:   &operatorv1.GatewayAPI{},
		})

		Expect(func() { gatewayComp.Objects() }).NotTo(Panic())
	})

	It("should deploy l7-log-collector (no waf-http-filter sidecar) for Enterprise", func() {
		installation := &operatorv1.InstallationSpec{
			Variant: operatorv1.CalicoEnterprise,
		}
		gatewayAPI := &operatorv1.GatewayAPI{
			Spec: operatorv1.GatewayAPISpec{
				GatewayClasses: []operatorv1.GatewayClassSpec{{Name: "tigera-gateway-class"}},
			},
		}
		gatewayComp := enterpriseComponent(&gatewayapi.GatewayAPIImplementationConfig{
			Installation:           installation,
			GatewayAPI:             gatewayAPI,
			IncludeV3NetworkPolicy: true,
		})
		objsToCreate, _ := gatewayComp.Objects()
		proxy, err := rtest.GetResourceOfType[*envoyapi.EnvoyProxy](objsToCreate, gatewayapi.GatewayClassName, common.CalicoNamespace)
		Expect(err).NotTo(HaveOccurred())

		envoyDeployment := proxy.Spec.Provider.Kubernetes.EnvoyDeployment
		Expect(envoyDeployment).ToNot(BeNil())

		Expect(envoyDeployment.Pod).ToNot(BeNil())
		Expect(envoyDeployment.Pod.Volumes).To(HaveLen(2))
		Expect(envoyDeployment.Pod.Volumes[0].Name).To(Equal("access-logs"))
		Expect(envoyDeployment.Pod.Volumes[0].EmptyDir).ToNot(BeNil())
		Expect(envoyDeployment.Pod.Volumes[1].Name).To(Equal("felix-sync"))
		Expect(envoyDeployment.Pod.Volumes[1].CSI.Driver).To(Equal("csi.tigera.io"))

		Expect(envoyDeployment.InitContainers).To(HaveLen(1))
		Expect(envoyDeployment.InitContainers[0].Name).To(Equal("l7-log-collector"))
		Expect(*envoyDeployment.InitContainers[0].RestartPolicy).To(Equal(corev1.ContainerRestartPolicyAlways))
		Expect(envoyDeployment.InitContainers[0].VolumeMounts).To(HaveLen(2))
		Expect(envoyDeployment.InitContainers[0].VolumeMounts).To(ContainElements([]corev1.VolumeMount{
			{
				Name:      "access-logs",
				MountPath: "/access_logs",
			},
			{
				Name:      "felix-sync",
				MountPath: "/var/run/felix",
			},
		}))
		// WAF audit capture: the l7-log-collector tails the redirected Envoy app log on
		// the access-logs volume it already mounts.
		Expect(envoyDeployment.InitContainers[0].Env).To(ContainElement(corev1.EnvVar{
			Name:  "WAF_AUDIT_LOG_PATH",
			Value: "/access_logs/envoy.log",
		}))

		Expect(envoyDeployment.Container).ToNot(BeNil())
		Expect(envoyDeployment.Container.VolumeMounts).To(HaveLen(1))
		Expect(envoyDeployment.Container.VolumeMounts).To(ContainElement(corev1.VolumeMount{
			Name:      "access-logs",
			MountPath: "/access_logs",
		}))

		Expect(proxy.Spec.Telemetry.AccessLog.Settings).To(Equal(AccessLogSettings))

		// WAF audit capture: the wasm component logs at info so Coraza "AuditLog:" lines
		// reach Envoy's application log, while everything else stays at warn so the
		// redirected log file is approximately just the audit lines.
		Expect(proxy.Spec.Logging.Level).To(HaveKeyWithValue(envoyapi.LogComponentDefault, envoyapi.LogLevelWarn))
		Expect(proxy.Spec.Logging.Level).To(HaveKeyWithValue(envoyapi.ProxyLogComponent("wasm"), envoyapi.LogLevelInfo))

		// WAF audit capture: Envoy's application log is redirected to a file on the
		// var-log-calico HostPath volume via --log-path (appended through ExtraArgs,
		// which Envoy Gateway adds to the proxy args verbatim - each token a separate
		// element). The l7-log-collector tails this file.
		Expect(proxy.Spec.ExtraArgs).To(Equal([]string{"--log-path", "/access_logs/envoy.log"}))
	})

	It("should deploy l7-log-collector (no waf-http-filter sidecar) for Enterprise when using a custom proxy", func() {
		installation := &operatorv1.InstallationSpec{
			Variant: operatorv1.CalicoEnterprise,
		}
		gatewayAPI := &operatorv1.GatewayAPI{
			Spec: operatorv1.GatewayAPISpec{
				GatewayClasses: []operatorv1.GatewayClassSpec{{
					Name: "custom-class",
					EnvoyProxyRef: &operatorv1.NamespacedName{
						Namespace: "default",
						Name:      "my-proxy",
					},
				}},
			},
		}
		envoyProxy := &envoyapi.EnvoyProxy{
			TypeMeta: metav1.TypeMeta{
				Kind:       "EnvoyProxy",
				APIVersion: "gateway.envoyproxy.io/v1alpha1",
			},
			ObjectMeta: metav1.ObjectMeta{
				Name:      "my-proxy",
				Namespace: "default",
			},
			Spec: envoyapi.EnvoyProxySpec{
				Provider: &envoyapi.EnvoyProxyProvider{
					Type: envoyapi.EnvoyProxyProviderTypeKubernetes,
					Kubernetes: &envoyapi.EnvoyProxyKubernetesProvider{
						EnvoyDeployment: &envoyapi.KubernetesDeploymentSpec{
							InitContainers: []corev1.Container{
								{
									Name:          "some-other-sidecar",
									RestartPolicy: ptr.To(corev1.ContainerRestartPolicyAlways),
									VolumeMounts: []corev1.VolumeMount{
										{
											Name:      "some-other-volume",
											MountPath: "/test",
										},
									},
								},
							},
							Container: &envoyapi.KubernetesContainerSpec{
								VolumeMounts: []corev1.VolumeMount{
									{
										Name:      "some-other-volume",
										MountPath: "/test",
									},
								},
							},
							Pod: &envoyapi.KubernetesPodSpec{
								Volumes: []corev1.Volume{
									{
										Name: "some-other-volume",
										VolumeSource: corev1.VolumeSource{
											EmptyDir: &corev1.EmptyDirVolumeSource{},
										},
									},
								},
							},
						},
					},
				},
			},
		}
		gatewayComp := enterpriseComponent(&gatewayapi.GatewayAPIImplementationConfig{
			Installation: installation,
			GatewayAPI:   gatewayAPI,
			CustomEnvoyProxies: map[string]*envoyapi.EnvoyProxy{
				"custom-class": envoyProxy,
			},
		})
		objsToCreate, _ := gatewayComp.Objects()

		// Get the four expected GatewayClasses.
		gc, err := rtest.GetResourceOfType[*gapi.GatewayClass](objsToCreate, "custom-class", "")
		Expect(err).NotTo(HaveOccurred())

		// Get their four EnvoyProxies.
		Expect(gc.Spec.ParametersRef).NotTo(BeNil())
		proxy, err := rtest.GetResourceOfType[*envoyapi.EnvoyProxy](objsToCreate, gc.Spec.ParametersRef.Name, string(*gc.Spec.ParametersRef.Namespace))
		Expect(err).NotTo(HaveOccurred())

		envoyDeployment := proxy.Spec.Provider.Kubernetes.EnvoyDeployment
		Expect(envoyDeployment).ToNot(BeNil())

		Expect(envoyDeployment.InitContainers).To(HaveLen(2))
		Expect(envoyDeployment.InitContainers[0].Name).To(Equal("some-other-sidecar"))

		Expect(envoyDeployment.InitContainers[1].Name).To(Equal("l7-log-collector"))
		Expect(*envoyDeployment.InitContainers[1].RestartPolicy).To(Equal(corev1.ContainerRestartPolicyAlways))
		Expect(envoyDeployment.InitContainers[1].VolumeMounts).To(HaveLen(2))
		Expect(envoyDeployment.InitContainers[1].VolumeMounts).To(ContainElements([]corev1.VolumeMount{
			{
				Name:      "access-logs",
				MountPath: "/access_logs",
			},
			{
				Name:      "felix-sync",
				MountPath: "/var/run/felix",
			},
		}))
		Expect(envoyDeployment.InitContainers[1].Env).To(ContainElement(corev1.EnvVar{
			Name:  "WAF_AUDIT_LOG_PATH",
			Value: "/access_logs/envoy.log",
		}))

		Expect(envoyDeployment.Container).ToNot(BeNil())
		Expect(envoyDeployment.Container.VolumeMounts).To(ContainElements(
			corev1.VolumeMount{
				Name:      "some-other-volume",
				MountPath: "/test",
			}, corev1.VolumeMount{
				Name:      "access-logs",
				MountPath: "/access_logs",
			},
		))

		Expect(envoyDeployment.Pod).ToNot(BeNil())
		Expect(envoyDeployment.Pod.Volumes).To(HaveLen(3))
		Expect(envoyDeployment.Pod.Volumes[0].Name).To(Equal("some-other-volume"))
		Expect(envoyDeployment.Pod.Volumes[0].EmptyDir).ToNot(BeNil())
		Expect(envoyDeployment.Pod.Volumes[1].Name).To(Equal("access-logs"))
		Expect(envoyDeployment.Pod.Volumes[1].EmptyDir).ToNot(BeNil())
		Expect(envoyDeployment.Pod.Volumes[2].Name).To(Equal("felix-sync"))
		Expect(envoyDeployment.Pod.Volumes[2].CSI.Driver).To(Equal("csi.tigera.io"))
		Expect(proxy.Spec.Telemetry.AccessLog.Settings).To(Equal(AccessLogSettings))
	})

	It("should set owning gateway environment variables in l7-log-collector for Enterprise", func() {
		installation := &operatorv1.InstallationSpec{
			Variant: operatorv1.CalicoEnterprise,
		}
		gatewayAPI := &operatorv1.GatewayAPI{
			Spec: operatorv1.GatewayAPISpec{
				GatewayClasses: []operatorv1.GatewayClassSpec{{Name: "tigera-gateway-class"}},
			},
		}
		gatewayComp := enterpriseComponent(&gatewayapi.GatewayAPIImplementationConfig{
			Installation:           installation,
			GatewayAPI:             gatewayAPI,
			IncludeV3NetworkPolicy: true,
		})
		objsToCreate, _ := gatewayComp.Objects()
		proxy, err := rtest.GetResourceOfType[*envoyapi.EnvoyProxy](objsToCreate, gatewayapi.GatewayClassName, common.CalicoNamespace)
		Expect(err).NotTo(HaveOccurred())

		envoyDeployment := proxy.Spec.Provider.Kubernetes.EnvoyDeployment
		Expect(envoyDeployment).ToNot(BeNil())
		Expect(envoyDeployment.InitContainers).To(HaveLen(1))

		// Find the l7-log-collector init container
		var l7LogCollector *corev1.Container
		for i := range envoyDeployment.InitContainers {
			if envoyDeployment.InitContainers[i].Name == "l7-log-collector" {
				l7LogCollector = &envoyDeployment.InitContainers[i]
				break
			}
		}

		Expect(l7LogCollector).ToNot(BeNil(), "l7-log-collector container should exist")

		// Verify the owning gateway environment variables are present
		Expect(l7LogCollector.Env).To(ContainElement(OwningGatewayNameEnvVar))
		Expect(l7LogCollector.Env).To(ContainElement(OwningGatewayNamespaceEnvVar))

		// Verify the structure of the environment variables
		var foundNameEnvVar, foundNamespaceEnvVar bool
		for _, env := range l7LogCollector.Env {
			if env.Name == "OWNING_GATEWAY_NAME" {
				foundNameEnvVar = true
				Expect(env.ValueFrom).ToNot(BeNil())
				Expect(env.ValueFrom.FieldRef).ToNot(BeNil())
				Expect(env.ValueFrom.FieldRef.FieldPath).To(Equal("metadata.labels['gateway.envoyproxy.io/owning-gateway-name']"))
			}
			if env.Name == "OWNING_GATEWAY_NAMESPACE" {
				foundNamespaceEnvVar = true
				Expect(env.ValueFrom).ToNot(BeNil())
				Expect(env.ValueFrom.FieldRef).ToNot(BeNil())
				Expect(env.ValueFrom.FieldRef.FieldPath).To(Equal("metadata.labels['gateway.envoyproxy.io/owning-gateway-namespace']"))
			}
		}
		Expect(foundNameEnvVar).To(BeTrue(), "OWNING_GATEWAY_NAME environment variable should be set")
		Expect(foundNamespaceEnvVar).To(BeTrue(), "OWNING_GATEWAY_NAMESPACE environment variable should be set")
	})

	It("should set owning gateway environment variables in l7-log-collector when using custom proxy", func() {
		installation := &operatorv1.InstallationSpec{
			Variant: operatorv1.CalicoEnterprise,
		}
		gatewayAPI := &operatorv1.GatewayAPI{
			Spec: operatorv1.GatewayAPISpec{
				GatewayClasses: []operatorv1.GatewayClassSpec{{
					Name: "custom-class",
					EnvoyProxyRef: &operatorv1.NamespacedName{
						Namespace: "default",
						Name:      "my-proxy",
					},
				}},
			},
		}
		envoyProxy := &envoyapi.EnvoyProxy{
			TypeMeta: metav1.TypeMeta{
				Kind:       "EnvoyProxy",
				APIVersion: "gateway.envoyproxy.io/v1alpha1",
			},
			ObjectMeta: metav1.ObjectMeta{
				Name:      "my-proxy",
				Namespace: "default",
			},
			Spec: envoyapi.EnvoyProxySpec{
				Provider: &envoyapi.EnvoyProxyProvider{
					Type: envoyapi.EnvoyProxyProviderTypeKubernetes,
					Kubernetes: &envoyapi.EnvoyProxyKubernetesProvider{
						EnvoyDeployment: &envoyapi.KubernetesDeploymentSpec{
							InitContainers: []corev1.Container{
								{
									Name:          "some-other-sidecar",
									RestartPolicy: ptr.To(corev1.ContainerRestartPolicyAlways),
									Env: []corev1.EnvVar{
										{
											Name:  "OTHER_VAR",
											Value: "other-value",
										},
									},
								},
							},
						},
					},
				},
			},
		}
		gatewayComp := enterpriseComponent(&gatewayapi.GatewayAPIImplementationConfig{
			Installation: installation,
			GatewayAPI:   gatewayAPI,
			CustomEnvoyProxies: map[string]*envoyapi.EnvoyProxy{
				"custom-class": envoyProxy,
			},
		})
		objsToCreate, _ := gatewayComp.Objects()

		gc, err := rtest.GetResourceOfType[*gapi.GatewayClass](objsToCreate, "custom-class", "")
		Expect(err).NotTo(HaveOccurred())

		Expect(gc.Spec.ParametersRef).NotTo(BeNil())
		proxy, err := rtest.GetResourceOfType[*envoyapi.EnvoyProxy](objsToCreate, gc.Spec.ParametersRef.Name, string(*gc.Spec.ParametersRef.Namespace))
		Expect(err).NotTo(HaveOccurred())

		envoyDeployment := proxy.Spec.Provider.Kubernetes.EnvoyDeployment
		Expect(envoyDeployment).ToNot(BeNil())

		// Find the l7-log-collector init container
		var l7LogCollector *corev1.Container
		for i := range envoyDeployment.InitContainers {
			if envoyDeployment.InitContainers[i].Name == "l7-log-collector" {
				l7LogCollector = &envoyDeployment.InitContainers[i]
				break
			}
		}

		Expect(l7LogCollector).ToNot(BeNil(), "l7-log-collector container should exist")

		// Verify the owning gateway environment variables are present
		Expect(l7LogCollector.Env).To(ContainElement(OwningGatewayNameEnvVar))
		Expect(l7LogCollector.Env).To(ContainElement(OwningGatewayNamespaceEnvVar))

		// Verify environment variables include all expected values
		envVarNames := make([]string, len(l7LogCollector.Env))
		for i, env := range l7LogCollector.Env {
			envVarNames[i] = env.Name
		}
		Expect(envVarNames).To(ContainElement("LOG_LEVEL"))
		Expect(envVarNames).To(ContainElement("FELIX_DIAL_TARGET"))
		Expect(envVarNames).To(ContainElement("ENVOY_ACCESS_LOG_PATH"))
		Expect(envVarNames).To(ContainElement("OWNING_GATEWAY_NAME"))
		Expect(envVarNames).To(ContainElement("OWNING_GATEWAY_NAMESPACE"))
	})

	It("should verify owning gateway env vars use correct field paths", func() {
		// Test the global env var definitions
		Expect(OwningGatewayNameEnvVar.Name).To(Equal("OWNING_GATEWAY_NAME"))
		Expect(OwningGatewayNameEnvVar.ValueFrom).ToNot(BeNil())
		Expect(OwningGatewayNameEnvVar.ValueFrom.FieldRef).ToNot(BeNil())
		Expect(OwningGatewayNameEnvVar.ValueFrom.FieldRef.FieldPath).To(Equal("metadata.labels['gateway.envoyproxy.io/owning-gateway-name']"))

		Expect(OwningGatewayNamespaceEnvVar.Name).To(Equal("OWNING_GATEWAY_NAMESPACE"))
		Expect(OwningGatewayNamespaceEnvVar.ValueFrom).ToNot(BeNil())
		Expect(OwningGatewayNamespaceEnvVar.ValueFrom.FieldRef).ToNot(BeNil())
		Expect(OwningGatewayNamespaceEnvVar.ValueFrom.FieldRef.FieldPath).To(Equal("metadata.labels['gateway.envoyproxy.io/owning-gateway-namespace']"))
	})

	It("should not set owning gateway env vars in l7-log-collector for DaemonSet deployments", func() {
		installation := &operatorv1.InstallationSpec{
			Variant: operatorv1.CalicoEnterprise,
		}
		daemonSet := operatorv1.GatewayKindDaemonSet
		gatewayAPI := &operatorv1.GatewayAPI{
			Spec: operatorv1.GatewayAPISpec{
				GatewayClasses: []operatorv1.GatewayClassSpec{{
					Name:        "tigera-gateway-class-daemonset",
					GatewayKind: &daemonSet,
				}},
			},
		}
		gatewayComp := enterpriseComponent(&gatewayapi.GatewayAPIImplementationConfig{
			Installation:           installation,
			GatewayAPI:             gatewayAPI,
			IncludeV3NetworkPolicy: true,
		})
		objsToCreate, _ := gatewayComp.Objects()
		proxy, err := rtest.GetResourceOfType[*envoyapi.EnvoyProxy](objsToCreate, "tigera-gateway-class-daemonset", common.CalicoNamespace)
		Expect(err).NotTo(HaveOccurred())

		// DaemonSet should not have l7-log-collector or waf-http-filter
		Expect(proxy.Spec.Provider.Kubernetes.EnvoyDaemonSet).ToNot(BeNil())
		Expect(proxy.Spec.Provider.Kubernetes.EnvoyDeployment).To(BeNil())
		// DaemonSet init containers are not supported, so these should not be present
		// This is expected behavior as mentioned in the code comments
	})

	It("should create correct shared WAF ClusterRoles for L7 log collector enrichment", func() {
		installation := &operatorv1.InstallationSpec{
			Variant: operatorv1.CalicoEnterprise,
		}
		gatewayAPI := &operatorv1.GatewayAPI{
			Spec: operatorv1.GatewayAPISpec{
				GatewayClasses: []operatorv1.GatewayClassSpec{{Name: "tigera-gateway-class"}},
			},
		}
		gatewayComp := enterpriseComponent(&gatewayapi.GatewayAPIImplementationConfig{
			Installation:           installation,
			GatewayAPI:             gatewayAPI,
			IncludeV3NetworkPolicy: true,
		})
		objsToCreate, _ := gatewayComp.Objects()

		// Verify cluster-scoped ClusterRole exists with license key + token review rules.
		csRole, err := rtest.GetResourceOfType[*rbacv1.ClusterRole](objsToCreate, "waf-http-filter-cluster-scoped", "")
		Expect(err).NotTo(HaveOccurred())
		Expect(csRole.Rules).To(HaveLen(2))
		Expect(csRole.Rules).To(ContainElement(rbacv1.PolicyRule{
			APIGroups: []string{"crd.projectcalico.org", "projectcalico.org"},
			Resources: []string{"licensekeys"},
			Verbs:     []string{"get", "watch"},
		}))
		Expect(csRole.Rules).To(ContainElement(rbacv1.PolicyRule{
			APIGroups: []string{"authentication.k8s.io"},
			Resources: []string{"tokenreviews"},
			Verbs:     []string{"create"},
		}))

		// Verify gateway-resources ClusterRole exists with route rules only.
		grRole, err := rtest.GetResourceOfType[*rbacv1.ClusterRole](objsToCreate, "waf-http-filter-gateway-resources", "")
		Expect(err).NotTo(HaveOccurred())
		Expect(grRole.Rules).To(HaveLen(1))
		Expect(grRole.Rules).To(ContainElement(rbacv1.PolicyRule{
			APIGroups: []string{"gateway.networking.k8s.io"},
			Resources: []string{"gateways", "httproutes", "grpcroutes"},
			Verbs:     []string{"get", "list", "watch"},
		}))

		// With no GatewayNamespaces declared, no per-namespace SAs or CRBs/RoleBindings
		// are emitted — they only appear when a Gateway is created in a user namespace.
		_, err = rtest.GetResourceOfType[*rbacv1.ClusterRoleBinding](objsToCreate, gatewayapi.GatewayNamespacesCRBName, "")
		Expect(err).To(HaveOccurred())
	})

	It("renders the shared WAF CRB with a subject per Gateway namespace; per-namespace resources are controller-managed (Enterprise)", func() {
		gatewayComp := enterpriseComponent(&gatewayapi.GatewayAPIImplementationConfig{
			Installation:      &operatorv1.InstallationSpec{Variant: operatorv1.CalicoEnterprise},
			GatewayAPI:        &operatorv1.GatewayAPI{Spec: operatorv1.GatewayAPISpec{GatewayClasses: []operatorv1.GatewayClassSpec{{Name: "tigera-gateway-class"}}}},
			PullSecrets:       []*corev1.Secret{{ObjectMeta: metav1.ObjectMeta{Name: "tigera-pull-secret", Namespace: "tigera-operator"}}},
			GatewayNamespaces: []string{"default", "app-ns"},
		})
		objsToCreate, _ := gatewayComp.Objects()

		// The shared CRB carries one subject per Gateway namespace.
		crb, err := rtest.GetResourceOfType[*rbacv1.ClusterRoleBinding](objsToCreate, gatewayapi.GatewayNamespacesCRBName, "")
		Expect(err).NotTo(HaveOccurred())
		Expect(crb.RoleRef.Name).To(Equal("waf-http-filter-cluster-scoped"))
		nsSubjects := []string{}
		for _, s := range crb.Subjects {
			nsSubjects = append(nsSubjects, s.Namespace)
		}
		Expect(nsSubjects).To(ConsistOf("default", "app-ns"))

		// The per-namespace SA / RoleBinding / pull-secret are written by the controller (Gateway-owned),
		// not rendered here.
		_, err = rtest.GetResourceOfType[*corev1.ServiceAccount](objsToCreate, "waf-http-filter", "default")
		Expect(err).To(HaveOccurred())
		_, err = rtest.GetResourceOfType[*rbacv1.RoleBinding](objsToCreate, "waf-http-filter-gateway-resources", "default")
		Expect(err).To(HaveOccurred())
		_, err = rtest.GetResourceOfType[*corev1.Secret](objsToCreate, "tigera-pull-secret", "default")
		Expect(err).To(HaveOccurred())
	})

	It("should not create per-namespace resources when no Gateway namespaces are provided (Enterprise)", func() {
		installation := &operatorv1.InstallationSpec{
			Variant: operatorv1.CalicoEnterprise,
		}
		gatewayAPI := &operatorv1.GatewayAPI{
			Spec: operatorv1.GatewayAPISpec{
				GatewayClasses: []operatorv1.GatewayClassSpec{{Name: "tigera-gateway-class"}},
			},
		}
		gatewayComp := enterpriseComponent(&gatewayapi.GatewayAPIImplementationConfig{
			Installation:           installation,
			GatewayAPI:             gatewayAPI,
			IncludeV3NetworkPolicy: true,
		})
		objsToCreate, _ := gatewayComp.Objects()

		// With no GatewayNamespaces declared, no shared per-namespace CRB is created.
		_, err := rtest.GetResourceOfType[*rbacv1.ClusterRoleBinding](objsToCreate, gatewayapi.GatewayNamespacesCRBName, "")
		Expect(err).To(HaveOccurred())

		// Shared WAF ClusterRoles must always be present on Enterprise so per-namespace
		// CRBs can bind to them once a Gateway shows up.
		_, err = rtest.GetResourceOfType[*rbacv1.ClusterRole](objsToCreate, "waf-http-filter-cluster-scoped", "")
		Expect(err).NotTo(HaveOccurred())
		_, err = rtest.GetResourceOfType[*rbacv1.ClusterRole](objsToCreate, "waf-http-filter-gateway-resources", "")
		Expect(err).NotTo(HaveOccurred())
	})

	It("resolves the Enterprise envoy images", func() {
		installation := &operatorv1.InstallationSpec{
			Registry: "myregistry.io/",
			Variant:  operatorv1.CalicoEnterprise,
		}
		gatewayComp := enterpriseComponent(&gatewayapi.GatewayAPIImplementationConfig{
			Installation: installation,
			GatewayAPI: &operatorv1.GatewayAPI{
				Spec: operatorv1.GatewayAPISpec{
					GatewayClasses: []operatorv1.GatewayClassSpec{{Name: "tigera-gateway-class"}},
				},
			},
		})

		objsToCreate, _ := gatewayComp.Objects()

		deploy, err := rtest.GetResourceOfType[*appsv1.Deployment](objsToCreate, "envoy-gateway", common.CalicoNamespace)
		Expect(err).NotTo(HaveOccurred())
		Expect(deploy.Spec.Template.Spec.Containers[0].Image).To(
			Equal("myregistry.io/tigera/envoy-gateway:" + components.ComponentGatewayAPIEnvoyGateway.Version))

		proxy, err := rtest.GetResourceOfType[*envoyapi.EnvoyProxy](objsToCreate, gatewayapi.GatewayClassName, common.CalicoNamespace)
		Expect(err).NotTo(HaveOccurred())
		Expect(*proxy.Spec.Provider.Kubernetes.EnvoyDeployment.Container.Image).To(
			Equal("myregistry.io/tigera/envoy-proxy:" + components.ComponentGatewayAPIEnvoyProxy.Version))

		gatewayCM, err := rtest.GetResourceOfType[*corev1.ConfigMap](objsToCreate, "envoy-gateway-config", common.CalicoNamespace)
		Expect(err).NotTo(HaveOccurred())
		gatewayConfig := &envoyapi.EnvoyGateway{}
		Expect(yaml.Unmarshal([]byte(gatewayCM.Data[gatewayapi.EnvoyGatewayConfigKey]), gatewayConfig)).NotTo(HaveOccurred())
		Expect(*gatewayConfig.Provider.Kubernetes.RateLimitDeployment.Container.Image).To(
			Equal("myregistry.io/tigera/envoy-ratelimit:" + components.ComponentGatewayAPIEnvoyRatelimit.Version))
	})

	It("runs the l7-log-collector on the image the controller resolved", func() {
		gatewayComp := enterpriseComponent(&gatewayapi.GatewayAPIImplementationConfig{
			Installation: &operatorv1.InstallationSpec{Variant: operatorv1.CalicoEnterprise},
			GatewayAPI: &operatorv1.GatewayAPI{
				Spec: operatorv1.GatewayAPISpec{
					GatewayClasses: []operatorv1.GatewayClassSpec{{Name: "tigera-gateway-class"}},
				},
			},
		})

		objsToCreate, _ := gatewayComp.Objects()
		proxy, err := rtest.GetResourceOfType[*envoyapi.EnvoyProxy](objsToCreate, gatewayapi.GatewayClassName, common.CalicoNamespace)
		Expect(err).NotTo(HaveOccurred())
		Expect(proxy.Spec.Provider.Kubernetes.EnvoyDeployment.InitContainers[0].Image).To(Equal(l7CollectorImage))
	})

	It("resolves the l7-log-collector image from the installation", func() {
		ci := controller.Inputs{
			RenderInputs: render.Inputs{
				Installation: &operatorv1.InstallationSpec{
					Registry: "myregistry.io/",
					Variant:  operatorv1.CalicoEnterprise,
				},
			},
			Client: fake.NewClientBuilder().WithScheme(testScheme()).Build(),
		}
		ci, err := New(operatorv1.CalicoEnterprise).ExtendInputs(context.Background(), ci)
		Expect(err).NotTo(HaveOccurred())
		Expect(gatewayAPIData(ci.RenderInputs).l7LogCollectorImage).To(
			Equal("myregistry.io/tigera/gateway-l7-collector:" + components.ComponentGatewayL7Collector.Version))
	})

	It("queues the legacy install's WAF service account and the bindings that bound it", func() {
		gatewayComp := enterpriseComponent(&gatewayapi.GatewayAPIImplementationConfig{
			Installation: &operatorv1.InstallationSpec{Variant: operatorv1.CalicoEnterprise},
			GatewayAPI: &operatorv1.GatewayAPI{
				Spec: operatorv1.GatewayAPISpec{
					GatewayClasses: []operatorv1.GatewayClassSpec{{Name: "tigera-gateway-class"}},
				},
			},
		})

		_, objsToDelete := gatewayComp.Objects()
		rtest.ExpectResourceInList(objsToDelete, "waf-http-filter", "tigera-gateway", "", "v1", "ServiceAccount")
		rtest.ExpectResourceInList(objsToDelete, "waf-http-filter-cluster-scoped", "", "rbac.authorization.k8s.io", "v1", "ClusterRoleBinding")
		rtest.ExpectResourceInList(objsToDelete, "waf-http-filter-gateway-resources", "", "rbac.authorization.k8s.io", "v1", "ClusterRoleBinding")
	})

	It("leaves the legacy WAF service account alone when a Gateway lives in that namespace", func() {
		gatewayComp := enterpriseComponent(&gatewayapi.GatewayAPIImplementationConfig{
			Installation: &operatorv1.InstallationSpec{Variant: operatorv1.CalicoEnterprise},
			GatewayAPI: &operatorv1.GatewayAPI{
				Spec: operatorv1.GatewayAPISpec{
					GatewayClasses: []operatorv1.GatewayClassSpec{{Name: "tigera-gateway-class"}},
				},
			},
			GatewayNamespaces: []string{"tigera-gateway"},
		})

		_, objsToDelete := gatewayComp.Objects()
		for _, o := range objsToDelete {
			if sa, ok := o.(*corev1.ServiceAccount); ok && sa.Namespace == "tigera-gateway" {
				Expect(sa.Name).NotTo(Equal("waf-http-filter"))
			}
		}
	})

	It("gives each Gateway namespace the WAF filter's identity and pull secrets", func() {
		pullSecret := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Name: "tigera-pull-secret", Namespace: common.OperatorNamespace()},
		}
		objs := New(operatorv1.CalicoEnterprise).GatewayNamespaceObjects("app-ns", []*corev1.Secret{pullSecret})

		rtest.ExpectResourceInList(objs, "waf-http-filter", "app-ns", "", "v1", "ServiceAccount")
		rtest.ExpectResourceInList(objs, "waf-http-filter-gateway-resources", "app-ns", "rbac.authorization.k8s.io", "v1", "RoleBinding")
		rtest.ExpectResourceInList(objs, "tigera-operator-secrets", "app-ns", "rbac.authorization.k8s.io", "v1", "RoleBinding")
		rtest.ExpectResourceInList(objs, "tigera-pull-secret", "app-ns", "", "", "")
	})

	It("makes no changes when the installation is Calico", func() {
		cfg := &gatewayapi.GatewayAPIImplementationConfig{
			Scheme:       testScheme(),
			Installation: &operatorv1.InstallationSpec{Variant: operatorv1.Calico},
			GatewayAPI: &operatorv1.GatewayAPI{
				Spec: operatorv1.GatewayAPISpec{
					GatewayClasses: []operatorv1.GatewayClassSpec{{Name: "tigera-gateway-class"}},
				},
			},
		}
		comp, err := gatewayapi.GatewayAPIImplementationComponent(cfg)
		Expect(err).NotTo(HaveOccurred())
		Expect(comp.ResolveImages(nil)).NotTo(HaveOccurred())
		baseCreate, baseDelete := comp.Objects()

		decorated := New(operatorv1.CalicoEnterprise).Modify(comp, render.Inputs{Installation: cfg.Installation})
		create, del := decorated.Objects()
		Expect(create).To(HaveLen(len(baseCreate)))
		Expect(del).To(HaveLen(len(baseDelete)))
	})
})
