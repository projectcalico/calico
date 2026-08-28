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

package esmetrics

import (
	"fmt"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"

	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/components"
	"github.com/tigera/operator/pkg/render"
	rcomponents "github.com/tigera/operator/pkg/render/common/components"
	relasticsearch "github.com/tigera/operator/pkg/render/common/elasticsearch"
	rmeta "github.com/tigera/operator/pkg/render/common/meta"
	"github.com/tigera/operator/pkg/render/common/networkpolicy"
	"github.com/tigera/operator/pkg/render/common/secret"
	"github.com/tigera/operator/pkg/render/common/securitycontext"
	"github.com/tigera/operator/pkg/render/common/securitycontextconstraints"
	"github.com/tigera/operator/pkg/tls/certificatemanagement"
	"github.com/tigera/operator/pkg/url"
)

const (
	ElasticsearchMetricsSecret          = "tigera-ee-elasticsearch-metrics-elasticsearch-access"
	ElasticsearchMetricsServerTLSSecret = "tigera-ee-elasticsearch-metrics-tls"
	ElasticsearchMetricsName            = "tigera-elasticsearch-metrics"
	ElasticsearchMetricsRoleName        = "tigera-elasticsearch-metrics"
	ElasticsearchMetricsPolicyName      = networkpolicy.CalicoComponentPolicyPrefix + "elasticsearch-metrics"
	ElasticsearchMetricsPort            = 9081
)

var ESMetricsSourceEntityRule = networkpolicy.CreateSourceEntityRule(render.ElasticsearchNamespace, ElasticsearchMetricsName)

func ElasticsearchMetrics(cfg *Config) render.Component {
	return &elasticsearchMetrics{
		cfg: cfg,
	}
}

type Config struct {
	Installation         *operatorv1.InstallationSpec
	PullSecrets          []*corev1.Secret
	ESConfig             *relasticsearch.ClusterConfig
	ESMetricsCredsSecret *corev1.Secret
	ClusterDomain        string
	ServerTLS            certificatemanagement.KeyPairInterface
	TrustedBundle        certificatemanagement.TrustedBundleRO

	LogStorage *operatorv1.LogStorage
}

type elasticsearchMetrics struct {
	cfg         *Config
	calicoImage string
}

func (e *elasticsearchMetrics) ResolveImages(is *operatorv1.ImageSet) error {
	var err error

	reg := e.cfg.Installation.Registry
	path := e.cfg.Installation.ImagePath
	prefix := e.cfg.Installation.ImagePrefix

	e.calicoImage, err = components.GetReference(components.ComponentTigeraCalico, reg, path, prefix, is)
	if err != nil {
		return err
	}

	return err
}

func (e *elasticsearchMetrics) Objects() (objsToCreate, objsToDelete []client.Object) {
	toCreate := []client.Object{
		e.calicoSystemPolicy(),
	}
	toCreate = append(toCreate, secret.ToRuntimeObjects(secret.CopyToNamespace(render.ElasticsearchNamespace, e.cfg.ESMetricsCredsSecret)...)...)
	toCreate = append(toCreate, e.metricsService(), e.metricsDeployment(), e.serviceAccount())

	// allow-tigera Tier was renamed to calico-system
	objsToDelete = append(objsToDelete, networkpolicy.DeprecatedAllowTigeraNetworkPolicyObject("elasticsearch-metrics", render.ElasticsearchNamespace))

	if e.cfg.Installation.KubernetesProvider.IsOpenShift() {
		toCreate = append(toCreate, e.metricsRole(), e.metricsRoleBinding())
	}

	return toCreate, objsToDelete
}

func (e elasticsearchMetrics) serviceAccount() *corev1.ServiceAccount {
	return &corev1.ServiceAccount{
		TypeMeta: metav1.TypeMeta{Kind: "ServiceAccount", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      ElasticsearchMetricsName,
			Namespace: render.ElasticsearchNamespace,
		},
	}
}

func (e *elasticsearchMetrics) Ready() bool {
	return true
}

func (e *elasticsearchMetrics) SupportedOSType() rmeta.OSType {
	return rmeta.OSTypeLinux
}

func (e *elasticsearchMetrics) metricsRole() *rbacv1.Role {
	return &rbacv1.Role{
		TypeMeta: metav1.TypeMeta{Kind: "Role", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      ElasticsearchMetricsRoleName,
			Namespace: render.ElasticsearchNamespace,
		},
		Rules: []rbacv1.PolicyRule{
			{
				APIGroups:     []string{"security.openshift.io"},
				Resources:     []string{"securitycontextconstraints"},
				Verbs:         []string{"use"},
				ResourceNames: []string{securitycontextconstraints.NonRootV2},
			},
		},
	}
}

func (e *elasticsearchMetrics) metricsRoleBinding() *rbacv1.RoleBinding {
	return &rbacv1.RoleBinding{
		TypeMeta: metav1.TypeMeta{Kind: "RoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      ElasticsearchMetricsRoleName,
			Namespace: render.ElasticsearchNamespace,
		},
		RoleRef: rbacv1.RoleRef{
			Kind:     "Role",
			Name:     ElasticsearchMetricsRoleName,
			APIGroup: "rbac.authorization.k8s.io",
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      "ServiceAccount",
				Name:      ElasticsearchMetricsName,
				Namespace: render.ElasticsearchNamespace,
			},
		},
	}
}

func (e *elasticsearchMetrics) metricsService() *corev1.Service {
	return &corev1.Service{
		TypeMeta: metav1.TypeMeta{Kind: "Service", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      ElasticsearchMetricsName,
			Namespace: render.ElasticsearchNamespace,
			Labels: map[string]string{
				"k8s-app": ElasticsearchMetricsName,
			},
		},
		Spec: corev1.ServiceSpec{
			// Important: "None" tells Kubernetes that we want a headless service with
			// no kube-proxy load balancer.  If we omit this then kube-proxy will render
			// a huge set of iptables rules for this service since there's an instance
			// on every node.
			ClusterIP: "None",
			Selector: map[string]string{
				"k8s-app": ElasticsearchMetricsName,
			},
			Ports: []corev1.ServicePort{
				{
					Name:       "metrics-port",
					Port:       ElasticsearchMetricsPort,
					Protocol:   corev1.ProtocolTCP,
					TargetPort: intstr.FromInt(ElasticsearchMetricsPort),
				},
			},
		},
	}
}

func (e *elasticsearchMetrics) metricsDeployment() *appsv1.Deployment {
	sc := securitycontext.NewNonRootContext()
	annotations := e.cfg.TrustedBundle.HashAnnotations()
	var initContainers []corev1.Container
	if e.cfg.ServerTLS.UseCertificateManagement() {
		initContainers = append(initContainers, e.cfg.ServerTLS.InitContainer(render.ElasticsearchNamespace, sc))
	} else {
		annotations[e.cfg.ServerTLS.HashAnnotationKey()] = e.cfg.ServerTLS.HashAnnotationValue()
	}

	_, esHost, esPort, _ := url.ParseEndpoint(relasticsearch.GatewayEndpoint(e.SupportedOSType(), e.cfg.ClusterDomain, render.ElasticsearchNamespace))

	tolerations := e.cfg.Installation.ControlPlaneTolerations
	if e.cfg.Installation.KubernetesProvider.IsGKE() {
		tolerations = append(tolerations, rmeta.TolerateGKEARM64NoSchedule)
	}

	d := &appsv1.Deployment{
		TypeMeta: metav1.TypeMeta{Kind: "Deployment", APIVersion: "apps/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      ElasticsearchMetricsName,
			Namespace: render.ElasticsearchNamespace,
		},
		Spec: appsv1.DeploymentSpec{
			Replicas: ptr.To(int32(1)),
			Template: *relasticsearch.DecorateAnnotations(&corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Annotations: annotations,
				},
				Spec: corev1.PodSpec{
					Tolerations:        tolerations,
					NodeSelector:       e.cfg.Installation.ControlPlaneNodeSelector,
					ImagePullSecrets:   secret.GetReferenceList(e.cfg.PullSecrets),
					ServiceAccountName: ElasticsearchMetricsName,
					InitContainers:     initContainers,
					Containers: []corev1.Container{
						{
							Name:            ElasticsearchMetricsName,
							Image:           e.calicoImage,
							SecurityContext: sc,
							Command:         []string{components.CalicoBinaryPath, "component", "elasticsearch-metrics"},
							Args: []string{
								"--es.uri=https://$(ELASTIC_USERNAME):$(ELASTIC_PASSWORD)@$(ELASTIC_HOST):$(ELASTIC_PORT)",
								"--es.all", "--es.indices", "--es.indices_settings", "--es.shards", "--es.cluster_settings",
								"--es.timeout=30s", "--es.ca=$(ELASTIC_CA)", "--web.listen-address=:9081",
								"--web.telemetry-path=/metrics", "--tls.key=/tigera-ee-elasticsearch-metrics-tls/tls.key", "--tls.crt=/tigera-ee-elasticsearch-metrics-tls/tls.crt", fmt.Sprintf("--ca.crt=%s", certificatemanagement.TrustedCertBundleMountPath),
							},
							VolumeMounts: append(
								e.cfg.TrustedBundle.VolumeMounts(e.SupportedOSType()),
								e.cfg.ServerTLS.VolumeMount(e.SupportedOSType()),
							),
							Env: []corev1.EnvVar{
								relasticsearch.ElasticUsernameEnvVar(ElasticsearchMetricsSecret),
								relasticsearch.ElasticPasswordEnvVar(ElasticsearchMetricsSecret),
								relasticsearch.ElasticHostEnvVar(esHost),
								relasticsearch.ElasticPortEnvVar(esPort),
								relasticsearch.ElasticCAEnvVar(e.SupportedOSType()),
							},
						},
					},
					Volumes: []corev1.Volume{
						e.cfg.ServerTLS.Volume(),
						e.cfg.TrustedBundle.Volume(),
					},
				},
			}, []*corev1.Secret{e.cfg.ESMetricsCredsSecret}).(*corev1.PodTemplateSpec),
		},
	}

	if e.cfg.LogStorage != nil {
		if overrides := e.cfg.LogStorage.Spec.ElasticsearchMetricsDeployment; overrides != nil {
			rcomponents.ApplyDeploymentOverrides(d, overrides)
		}
	}

	return d
}

func (e *elasticsearchMetrics) calicoSystemPolicy() *v3.NetworkPolicy {
	egressRules := []v3.Rule{
		{
			Action:      v3.Allow,
			Protocol:    &networkpolicy.TCPProtocol,
			Source:      v3.EntityRule{},
			Destination: networkpolicy.DefaultHelper().ESGatewayEntityRule(),
		},
	}
	egressRules = networkpolicy.AppendDNSEgressRules(egressRules, e.cfg.Installation.KubernetesProvider.IsOpenShift())
	egressRules = append(egressRules,
		v3.Rule{
			Action:      v3.Allow,
			Protocol:    &networkpolicy.TCPProtocol,
			Destination: networkpolicy.KubeAPIServerEntityRule,
		},
	)

	return &v3.NetworkPolicy{
		TypeMeta: metav1.TypeMeta{Kind: "NetworkPolicy", APIVersion: "projectcalico.org/v3"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      ElasticsearchMetricsPolicyName,
			Namespace: render.ElasticsearchNamespace,
		},
		Spec: v3.NetworkPolicySpec{
			Order:                  &networkpolicy.HighPrecedenceOrder,
			Tier:                   networkpolicy.CalicoTierName,
			Selector:               networkpolicy.KubernetesAppSelector(ElasticsearchMetricsName),
			ServiceAccountSelector: "",
			Types:                  []v3.PolicyType{v3.PolicyTypeIngress, v3.PolicyTypeEgress},
			Ingress: []v3.Rule{
				{
					Action:   v3.Allow,
					Protocol: &networkpolicy.TCPProtocol,
					Source:   networkpolicy.PrometheusSourceEntityRule,
					Destination: v3.EntityRule{
						Ports: networkpolicy.Ports(ElasticsearchMetricsPort),
					},
				},
			},
			Egress: egressRules,
		},
	}
}
