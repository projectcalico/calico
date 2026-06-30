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

package esgateway

import (
	"fmt"
	"strings"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"

	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	"github.com/tigera/api/pkg/lib/numorstring"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/components"
	"github.com/tigera/operator/pkg/render"
	rcomponents "github.com/tigera/operator/pkg/render/common/components"
	"github.com/tigera/operator/pkg/render/common/elasticsearch"
	rmeta "github.com/tigera/operator/pkg/render/common/meta"
	"github.com/tigera/operator/pkg/render/common/networkpolicy"
	"github.com/tigera/operator/pkg/render/common/podaffinity"
	"github.com/tigera/operator/pkg/render/common/secret"
	"github.com/tigera/operator/pkg/render/common/securitycontext"
	"github.com/tigera/operator/pkg/render/common/securitycontextconstraints"
	"github.com/tigera/operator/pkg/render/logstorage"
	"github.com/tigera/operator/pkg/render/logstorage/esmetrics"
	"github.com/tigera/operator/pkg/render/logstorage/kibana"
	"github.com/tigera/operator/pkg/tls/certificatemanagement"
)

const (
	DeploymentName        = "tigera-secure-es-gateway"
	ServiceAccountName    = "tigera-secure-es-gateway"
	RoleName              = "tigera-secure-es-gateway"
	ServiceName           = "tigera-secure-es-gateway-http"
	PolicyName            = networkpolicy.CalicoComponentPolicyPrefix + "es-gateway-access"
	ElasticsearchPortName = "es-gateway-elasticsearch-port"
	KibanaPortName        = "es-gateway-kibana-port"
	Port                  = 5554

	ElasticsearchHTTPSEndpoint = "https://tigera-secure-es-http.tigera-elasticsearch.svc:9200"

	KibanaHTTPSEndpoint = "https://tigera-secure-kb-http.tigera-kibana.svc:5601"

	CloudPolicyName = networkpolicy.CalicoComponentPolicyPrefix + "cloud-es-gateway-access"
)

func EsGateway(c *Config) render.Component {
	return &esGateway{
		cfg: c,
	}
}

type esGateway struct {
	csrImage    string
	calicoImage string
	cfg         *Config
}

// Config contains all the config information needed to render the EsGateway component.
type Config struct {
	Installation               *operatorv1.InstallationSpec
	PullSecrets                []*corev1.Secret
	KubeControllersUserSecrets []*corev1.Secret
	ESGatewayKeyPair           certificatemanagement.KeyPairInterface
	TrustedBundle              certificatemanagement.TrustedBundleRO
	ClusterDomain              string
	EsAdminUserName            string
	Namespace                  string
	TruthNamespace             string
	LogStorage                 *operatorv1.LogStorage
	// Cloud holds Calico Cloud specific configuration. Inert unless Cloud.Enabled is set.
	Cloud CloudConfig
}

// CloudConfig holds Calico Cloud specific es-gateway configuration. Enabled gates all cloud
// behavior: when false (regular Calico/Calico Enterprise) the cloud decorators are no-ops.
type CloudConfig struct {
	Enabled              bool
	EsAdminUserSecret    *corev1.Secret
	ExternalCertsSecret  *corev1.Secret
	TenantID             string
	EnableMTLS           bool
	ExternalElastic      bool
	ExternalESDomain     string
	ExternalKibanaDomain string
}

func (e *esGateway) ResolveImages(is *operatorv1.ImageSet) error {
	reg := e.cfg.Installation.Registry
	path := e.cfg.Installation.ImagePath
	prefix := e.cfg.Installation.ImagePrefix
	var err error
	errMsgs := []string{}

	e.calicoImage, err = components.GetReference(components.CombinedCalicoImage(e.cfg.Installation), reg, path, prefix, is)
	if err != nil {
		errMsgs = append(errMsgs, err.Error())
	}
	if e.cfg.Installation.CertificateManagement != nil {
		e.csrImage, err = certificatemanagement.ResolveCSRInitImage(e.cfg.Installation, is)
		if err != nil {
			errMsgs = append(errMsgs, err.Error())
		}
	}
	if len(errMsgs) != 0 {
		return fmt.Errorf("%s", strings.Join(errMsgs, ","))
	}
	return nil
}

func (e *esGateway) Objects() (toCreate, toDelete []client.Object) {
	toCreate = append(toCreate, e.esGatewayCalicoSystemPolicy())
	toCreate = append(toCreate, secret.ToRuntimeObjects(e.cfg.KubeControllersUserSecrets...)...)
	toCreate = append(toCreate, e.esGatewayService())
	toCreate = append(toCreate, e.esGatewayRole())
	toCreate = append(toCreate, e.esGatewayRoleBinding())
	toCreate = append(toCreate, e.esGatewayServiceAccount())

	if e.cfg.Cloud.Enabled {
		// Copy the external ES certs and es-admin secret into the elasticsearch namespace so es-gateway can use them.
		if e.cfg.Cloud.ExternalCertsSecret != nil {
			toCreate = append(toCreate, secret.ToRuntimeObjects(secret.CopyToNamespace(render.ElasticsearchNamespace, e.cfg.Cloud.ExternalCertsSecret)...)...)
		}
		if e.cfg.Cloud.EsAdminUserSecret != nil {
			toCreate = append(toCreate, secret.ToRuntimeObjects(secret.CopyToNamespace(render.ElasticsearchNamespace, e.cfg.Cloud.EsAdminUserSecret)...)...)
		}

		toCreate = append(toCreate, e.cloudAccessNetworkPolicy())

		// allow-tigera Tier was renamed to calico-system
		toDelete = append(toDelete, networkpolicy.DeprecatedAllowTigeraNetworkPolicyObject("cloud-es-gateway-access", render.ElasticsearchNamespace))
	}

	// allow-tigera Tier was renamed to calico-system
	toDelete = append(toDelete, networkpolicy.DeprecatedAllowTigeraNetworkPolicyObject("es-gateway-access", e.cfg.Namespace))

	// The following secret is used by kube controllers and sent to managed clusters. It is also used by manifests in our docs.
	if e.cfg.ESGatewayKeyPair.UseCertificateManagement() {
		toCreate = append(toCreate, render.CreateCertificateSecret(e.cfg.Installation.CertificateManagement.CACert, elasticsearch.PublicCertSecret, e.cfg.TruthNamespace))
	} else {
		toCreate = append(toCreate, render.CreateCertificateSecret(e.cfg.ESGatewayKeyPair.GetCertificatePEM(), elasticsearch.PublicCertSecret, e.cfg.TruthNamespace))
	}
	// Create the deployment last to ensure all secrets have been created
	toCreate = append(toCreate, e.esGatewayDeployment())

	return toCreate, toDelete
}

func (e *esGateway) Ready() bool {
	return true
}

func (e *esGateway) SupportedOSType() rmeta.OSType {
	return rmeta.OSTypeLinux
}

func (e *esGateway) esGatewayRole() *rbacv1.Role {
	rules := []rbacv1.PolicyRule{
		{
			APIGroups:     []string{""},
			Resources:     []string{"secrets"},
			ResourceNames: []string{},
			Verbs:         []string{"get", "list", "watch"},
		},
	}

	if e.cfg.Installation.KubernetesProvider.IsOpenShift() {
		rules = append(rules, rbacv1.PolicyRule{
			APIGroups:     []string{"security.openshift.io"},
			Resources:     []string{"securitycontextconstraints"},
			Verbs:         []string{"use"},
			ResourceNames: []string{securitycontextconstraints.NonRootV2},
		})
	}

	return &rbacv1.Role{
		TypeMeta: metav1.TypeMeta{Kind: "Role", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      RoleName,
			Namespace: e.cfg.Namespace,
		},
		Rules: rules,
	}
}

func (e *esGateway) esGatewayRoleBinding() *rbacv1.RoleBinding {
	return &rbacv1.RoleBinding{
		TypeMeta: metav1.TypeMeta{Kind: "RoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      RoleName,
			Namespace: e.cfg.Namespace,
		},
		RoleRef: rbacv1.RoleRef{
			Kind:     "Role",
			Name:     RoleName,
			APIGroup: "rbac.authorization.k8s.io",
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      "ServiceAccount",
				Name:      ServiceAccountName,
				Namespace: e.cfg.Namespace,
			},
		},
	}
}

func (e *esGateway) esGatewayDeployment() *appsv1.Deployment {
	// The ES/Kibana endpoints and client cert paths default to the in-cluster values, but Calico
	// Cloud points es-gateway at an external ES/Kibana and (optionally) mounts mTLS client certs.
	// These are computed here rather than removed-and-re-added by the cloud path.
	elasticEndpoint := ElasticsearchHTTPSEndpoint
	kibanaEndpoint := KibanaHTTPSEndpoint
	elasticClientCertPath := e.cfg.TrustedBundle.MountPath()
	kibanaClientCertPath := e.cfg.TrustedBundle.MountPath()
	if e.cfg.Cloud.Enabled {
		if e.cfg.Cloud.ExternalElastic {
			elasticEndpoint = "https://" + e.cfg.Cloud.ExternalESDomain + ":443"
			kibanaEndpoint = "https://" + e.cfg.Cloud.ExternalKibanaDomain + ":443"
		}
		if e.cfg.Cloud.EnableMTLS {
			elasticClientCertPath = "/certs/elasticsearch/mtls/client.crt"
			kibanaClientCertPath = "/certs/kibana/mtls/client.crt"
		}
	}

	envVars := []corev1.EnvVar{
		{Name: "NAMESPACE", Value: e.cfg.Namespace},
		{Name: "ES_GATEWAY_LOG_LEVEL", Value: "INFO"},
		{Name: "ES_GATEWAY_ELASTIC_ENDPOINT", Value: elasticEndpoint},
		{Name: "ES_GATEWAY_KIBANA_ENDPOINT", Value: kibanaEndpoint},
		{Name: "ES_GATEWAY_HTTPS_CERT", Value: e.cfg.ESGatewayKeyPair.VolumeMountCertificateFilePath()},
		{Name: "ES_GATEWAY_HTTPS_KEY", Value: e.cfg.ESGatewayKeyPair.VolumeMountKeyFilePath()},
		{Name: "ES_GATEWAY_KIBANA_CLIENT_CERT_PATH", Value: kibanaClientCertPath},
		{Name: "ES_GATEWAY_ELASTIC_CLIENT_CERT_PATH", Value: elasticClientCertPath},
		{Name: "ES_GATEWAY_ELASTIC_CA_BUNDLE_PATH", Value: e.cfg.TrustedBundle.MountPath()},
		{Name: "ES_GATEWAY_KIBANA_CA_BUNDLE_PATH", Value: e.cfg.TrustedBundle.MountPath()},
		{Name: "ES_GATEWAY_ELASTIC_USERNAME", Value: e.cfg.EsAdminUserName},
		{Name: "ES_GATEWAY_ELASTIC_PASSWORD", ValueFrom: &corev1.EnvVarSource{
			SecretKeyRef: &corev1.SecretKeySelector{
				LocalObjectReference: corev1.LocalObjectReference{
					Name: render.ElasticsearchAdminUserSecret,
				},
				Key: e.cfg.EsAdminUserName,
			},
		}},
	}

	// Calico Cloud additions to the es-gateway env.
	if e.cfg.Cloud.Enabled {
		// Enable the prometheus metrics endpoint at :METRICS_PORT/metrics (default 9091).
		envVars = append(envVars, corev1.EnvVar{Name: "ES_GATEWAY_METRICS_ENABLED", Value: "true"})
		if e.cfg.Cloud.ExternalElastic {
			// Enable the ILM dummy route so fluentd cannot modify ILM but its POSTs still succeed.
			envVars = append(envVars, corev1.EnvVar{Name: "ES_GATEWAY_ILM_DUMMY_ROUTE_ENABLED", Value: "true"})
		}
		if e.cfg.Cloud.EnableMTLS {
			// Cert paths are set above; here we add the client key paths and enable flags.
			envVars = append(envVars,
				corev1.EnvVar{Name: "ES_GATEWAY_ELASTIC_CLIENT_KEY_PATH", Value: "/certs/elasticsearch/mtls/client.key"},
				corev1.EnvVar{Name: "ES_GATEWAY_ENABLE_ELASTIC_MUTUAL_TLS", Value: "true"},
				corev1.EnvVar{Name: "ES_GATEWAY_KIBANA_CLIENT_KEY_PATH", Value: "/certs/kibana/mtls/client.key"},
				corev1.EnvVar{Name: "ES_GATEWAY_ENABLE_KIBANA_MUTUAL_TLS", Value: "true"},
			)
		}
		if e.cfg.Cloud.TenantID != "" {
			envVars = append(envVars, corev1.EnvVar{Name: "ES_GATEWAY_TENANT_ID", Value: e.cfg.Cloud.TenantID})
		}
	}

	sc := securitycontext.NewNonRootContext()
	var initContainers []corev1.Container
	if e.cfg.ESGatewayKeyPair.UseCertificateManagement() {
		initContainers = append(initContainers, e.cfg.ESGatewayKeyPair.InitContainer(e.cfg.Namespace, sc))
	}

	volumes := []corev1.Volume{
		e.cfg.ESGatewayKeyPair.Volume(),
		e.cfg.TrustedBundle.Volume(),
	}

	volumeMounts := append(
		e.cfg.TrustedBundle.VolumeMounts(e.SupportedOSType()),
		e.cfg.ESGatewayKeyPair.VolumeMount(e.SupportedOSType()),
	)

	annotations := e.cfg.TrustedBundle.HashAnnotations()
	annotations[e.cfg.ESGatewayKeyPair.HashAnnotationKey()] = e.cfg.ESGatewayKeyPair.HashAnnotationValue()

	if e.cfg.Cloud.Enabled {
		if e.cfg.Cloud.EnableMTLS {
			// Mount the external certs secret so the mTLS client key/cert paths set above resolve.
			volumes = append(volumes, corev1.Volume{
				Name: logstorage.ExternalCertsVolumeName,
				VolumeSource: corev1.VolumeSource{
					Secret: &corev1.SecretVolumeSource{
						SecretName: logstorage.ExternalCertsSecret,
					},
				},
			})
			volumeMounts = append(volumeMounts,
				corev1.VolumeMount{Name: logstorage.ExternalCertsVolumeName, MountPath: "/certs/elasticsearch/mtls", ReadOnly: true},
				corev1.VolumeMount{Name: logstorage.ExternalCertsVolumeName, MountPath: "/certs/kibana/mtls", ReadOnly: true},
			)
		}
		if e.cfg.Cloud.ExternalCertsSecret != nil {
			annotations["hash.operator.tigera.io/cloud-external-es-secrets"] = rmeta.SecretsAnnotationHash(e.cfg.Cloud.ExternalCertsSecret)
		}
	}

	tolerations := e.cfg.Installation.ControlPlaneTolerations
	if e.cfg.Installation.KubernetesProvider.IsGKE() {
		tolerations = append(tolerations, rmeta.TolerateGKEARM64NoSchedule)
	}

	podTemplate := &corev1.PodTemplateSpec{
		ObjectMeta: metav1.ObjectMeta{
			Name:        DeploymentName,
			Namespace:   e.cfg.Namespace,
			Annotations: annotations,
		},
		Spec: corev1.PodSpec{
			Tolerations:        tolerations,
			NodeSelector:       e.cfg.Installation.ControlPlaneNodeSelector,
			ServiceAccountName: ServiceAccountName,
			ImagePullSecrets:   secret.GetReferenceList(e.cfg.PullSecrets),
			Volumes:            volumes,
			InitContainers:     initContainers,
			Containers: []corev1.Container{
				{
					Name:         DeploymentName,
					Image:        e.calicoImage,
					Command:      []string{components.CalicoBinaryPath, "component", "es-gateway"},
					Env:          envVars,
					VolumeMounts: volumeMounts,
					ReadinessProbe: &corev1.Probe{
						ProbeHandler: corev1.ProbeHandler{
							HTTPGet: &corev1.HTTPGetAction{
								Path:   "/health",
								Port:   intstr.FromInt(Port),
								Scheme: corev1.URISchemeHTTPS,
							},
						},
						InitialDelaySeconds: 10,
					},
					SecurityContext: sc,
				},
			},
		},
	}

	if e.cfg.Installation.ControlPlaneReplicas != nil && *e.cfg.Installation.ControlPlaneReplicas > 1 {
		podTemplate.Spec.Affinity = podaffinity.NewPodAntiAffinity(DeploymentName, []string{e.cfg.Namespace})
	}

	d := appsv1.Deployment{
		TypeMeta: metav1.TypeMeta{Kind: "Deployment", APIVersion: "apps/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      DeploymentName,
			Namespace: e.cfg.Namespace,
			Labels: map[string]string{
				"k8s-app": DeploymentName,
			},
		},
		Spec: appsv1.DeploymentSpec{
			Strategy: appsv1.DeploymentStrategy{
				Type: appsv1.RollingUpdateDeploymentStrategyType,
				RollingUpdate: &appsv1.RollingUpdateDeployment{
					MaxUnavailable: ptr.To(intstr.FromInt(0)),
					MaxSurge:       ptr.To(intstr.FromString("100%")),
				},
			},
			Template: *podTemplate,
			Replicas: e.cfg.Installation.ControlPlaneReplicas,
		},
	}

	if e.cfg.LogStorage != nil {
		if overrides := e.cfg.LogStorage.Spec.ESGatewayDeployment; overrides != nil {
			rcomponents.ApplyDeploymentOverrides(&d, overrides)
		}
	}

	return &d
}

func (e *esGateway) esGatewayServiceAccount() *corev1.ServiceAccount {
	return &corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Name:      ServiceAccountName,
			Namespace: e.cfg.Namespace,
		},
	}
}

func (e *esGateway) esGatewayService() *corev1.Service {
	return &corev1.Service{
		TypeMeta: metav1.TypeMeta{Kind: "Service", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      ServiceName,
			Namespace: e.cfg.Namespace,
		},
		Spec: corev1.ServiceSpec{
			Selector: map[string]string{"k8s-app": DeploymentName},
			Type:     corev1.ServiceTypeClusterIP,
			Ports: []corev1.ServicePort{
				{
					Name:       ElasticsearchPortName,
					Port:       int32(render.ElasticsearchDefaultPort),
					TargetPort: intstr.FromInt(Port),
					Protocol:   corev1.ProtocolTCP,
				},
				{
					Name:       KibanaPortName,
					Port:       int32(kibana.Port),
					TargetPort: intstr.FromInt(Port),
					Protocol:   corev1.ProtocolTCP,
				},
			},
		},
	}
}

// Allow access to ES Gateway from components that need to talk to Elasticsearch or Kibana.
func (e *esGateway) esGatewayCalicoSystemPolicy() *v3.NetworkPolicy {
	egressRules := []v3.Rule{}
	egressRules = networkpolicy.AppendDNSEgressRules(egressRules, e.cfg.Installation.KubernetesProvider.IsOpenShift())
	egressRules = append(egressRules, []v3.Rule{
		{
			Action:      v3.Allow,
			Protocol:    &networkpolicy.TCPProtocol,
			Destination: render.DexEntityRule,
		},
		{
			Action:      v3.Allow,
			Protocol:    &networkpolicy.TCPProtocol,
			Destination: networkpolicy.KubeAPIServerEntityRule,
		},
		{
			Action:      v3.Allow,
			Protocol:    &networkpolicy.TCPProtocol,
			Destination: render.ElasticsearchEntityRule,
		},
		{
			Action:      v3.Allow,
			Protocol:    &networkpolicy.TCPProtocol,
			Destination: kibana.EntityRule,
		},
	}...)

	esgatewayIngressDestinationEntityRule := v3.EntityRule{
		Ports: networkpolicy.Ports(Port),
	}
	return &v3.NetworkPolicy{
		TypeMeta: metav1.TypeMeta{Kind: "NetworkPolicy", APIVersion: "projectcalico.org/v3"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      PolicyName,
			Namespace: e.cfg.Namespace,
		},
		Spec: v3.NetworkPolicySpec{
			Order:    &networkpolicy.HighPrecedenceOrder,
			Tier:     networkpolicy.CalicoTierName,
			Selector: networkpolicy.KubernetesAppSelector(DeploymentName),
			Types:    []v3.PolicyType{v3.PolicyTypeIngress, v3.PolicyTypeEgress},
			Ingress: []v3.Rule{
				// Note: the log collector (fluent-bit) and the EKS log forwarder
				// ship to Linseed only — the fluentd-era direct-Elasticsearch
				// path through es-gateway is gone, so they carry no ingress
				// allowance here.
				{
					Action:      v3.Allow,
					Protocol:    &networkpolicy.TCPProtocol,
					Source:      render.IntrusionDetectionInstallerSourceEntityRule,
					Destination: esgatewayIngressDestinationEntityRule,
				},
				{
					Action:      v3.Allow,
					Protocol:    &networkpolicy.TCPProtocol,
					Source:      networkpolicy.DefaultHelper().ManagerSourceEntityRule(),
					Destination: esgatewayIngressDestinationEntityRule,
				},
				{
					Action:      v3.Allow,
					Protocol:    &networkpolicy.TCPProtocol,
					Source:      render.IntrusionDetectionSourceEntityRule,
					Destination: esgatewayIngressDestinationEntityRule,
				},
				{
					Action:      v3.Allow,
					Protocol:    &networkpolicy.TCPProtocol,
					Source:      render.ECKOperatorSourceEntityRule,
					Destination: esgatewayIngressDestinationEntityRule,
				},
				{
					Action:      v3.Allow,
					Protocol:    &networkpolicy.TCPProtocol,
					Source:      esmetrics.ESMetricsSourceEntityRule,
					Destination: esgatewayIngressDestinationEntityRule,
				},
				{
					Action:      v3.Allow,
					Protocol:    &networkpolicy.TCPProtocol,
					Destination: esgatewayIngressDestinationEntityRule,
					// The operator needs access to Elasticsearch and Kibana (through ES Gateway), however, since the
					// operator is on the hostnetwork it's hard to create specific network policies for it.
					// Allow all sources, as node CIDRs are not known. This also applies to DPI, which is host networked
				},
			},
			Egress: egressRules,
		},
	}
}

func (e *esGateway) cloudAccessNetworkPolicy() *v3.NetworkPolicy {
	// When using external elastic, allow egress to the external ES/Kibana endpoints.
	var egressRules []v3.Rule
	if e.cfg.Cloud.ExternalElastic {
		egressRules = append(egressRules, v3.Rule{
			Action:   v3.Allow,
			Protocol: &networkpolicy.TCPProtocol,
			Destination: v3.EntityRule{
				Ports:   []numorstring.Port{{MinPort: 443, MaxPort: 443}},
				Domains: []string{e.cfg.Cloud.ExternalESDomain, e.cfg.Cloud.ExternalKibanaDomain},
			},
		})
	}
	return &v3.NetworkPolicy{
		TypeMeta:   metav1.TypeMeta{Kind: "NetworkPolicy", APIVersion: "projectcalico.org/v3"},
		ObjectMeta: metav1.ObjectMeta{Name: CloudPolicyName, Namespace: render.ElasticsearchNamespace},
		Spec: v3.NetworkPolicySpec{
			Order:    &networkpolicy.HighPrecedenceOrder,
			Tier:     networkpolicy.CalicoTierName,
			Selector: networkpolicy.KubernetesAppSelector(DeploymentName),
			Types:    []v3.PolicyType{v3.PolicyTypeIngress, v3.PolicyTypeEgress},
			Ingress: []v3.Rule{{
				Action:   v3.Allow,
				Protocol: &networkpolicy.TCPProtocol,
				Source: v3.EntityRule{
					NamespaceSelector: "projectcalico.org/name == 'monitoring'",
					Selector:          "app == 'prometheus'",
				},
				// Allow prometheus to scrape the metrics endpoint, which is enabled only on
				// cloud (see ES_GATEWAY_METRICS_ENABLED added above).
				Destination: v3.EntityRule{
					Ports: []numorstring.Port{{MinPort: 9091, MaxPort: 9091}},
				},
			}},
			Egress: egressRules,
		},
	}
}
