// Copyright (c) 2025-2026 Tigera, Inc. All rights reserved.

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

package kibana

import (
	"fmt"
	"net/url"
	"strings"

	cmnv1 "github.com/elastic/cloud-on-k8s/v2/pkg/apis/common/v1"
	kbv1 "github.com/elastic/cloud-on-k8s/v2/pkg/apis/kibana/v1"

	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"sigs.k8s.io/controller-runtime/pkg/client"

	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/components"
	"github.com/tigera/operator/pkg/dns"
	"github.com/tigera/operator/pkg/render"
	rcomponents "github.com/tigera/operator/pkg/render/common/components"
	rmeta "github.com/tigera/operator/pkg/render/common/meta"
	"github.com/tigera/operator/pkg/render/common/networkpolicy"
	"github.com/tigera/operator/pkg/render/common/podaffinity"
	"github.com/tigera/operator/pkg/render/common/secret"
	"github.com/tigera/operator/pkg/render/common/securitycontext"
	"github.com/tigera/operator/pkg/render/common/securitycontextconstraints"
	"github.com/tigera/operator/pkg/tls/certificatemanagement"
)

const (

	// TigeraKibanaCertSecret is the TLS key pair that is mounted by the Kibana pods.
	TigeraKibanaCertSecret = "tigera-secure-kibana-cert"

	CRName       = "tigera-secure"
	ObjectName   = "tigera-kibana"
	Namespace    = ObjectName
	BasePath     = ObjectName
	ServiceName  = "tigera-secure-kb-http"
	DefaultRoute = "/app/kibana#/dashboards?%s&title=%s"
	PolicyName   = networkpolicy.CalicoComponentPolicyPrefix + "kibana-access"
	Port         = 5601

	TLSAnnotationHash = "hash.operator.tigera.io/kb-secrets"

	TimeFilter         = "_g=(time:(from:now-24h,to:now))"
	FlowsDashboardName = "Calico Flow Logs"
)

var EntityRule = networkpolicy.CreateEntityRule(Namespace, CRName, Port)

// CloudKibanaConfigOverrides holds Calico Cloud Kibana config overrides. It is populated only by the
// cloud-gated controller path; for regular Calico/Calico Enterprise it stays empty and is a no-op.
// TODO: This shouldn't be done with a global variable set by the controller; thread it through Configuration instead.
var CloudKibanaConfigOverrides = map[string]interface{}{}

// Kibana renders the components necessary for kibana and elasticsearch
func Kibana(cfg *Configuration) render.Component {
	return &kibana{
		cfg: cfg,
	}
}

// Configuration contains all the config information needed to render the component.
type Configuration struct {
	LogStorage      *operatorv1.LogStorage
	Installation    *operatorv1.InstallationSpec
	Kibana          *kbv1.Kibana
	KibanaKeyPair   certificatemanagement.KeyPairInterface
	PullSecrets     []*corev1.Secret
	Provider        operatorv1.Provider
	KbService       *corev1.Service
	ClusterDomain   string
	BaseURL         string // BaseUrl is where the manager is reachable, for setting Kibana publicBaseUrl
	TrustedBundle   certificatemanagement.TrustedBundleRO
	UnusedTLSSecret *corev1.Secret
	Enabled         bool
}

type kibana struct {
	cfg           *Configuration
	kibanaSecrets []*corev1.Secret
	kibanaImage   string
	csrImage      string
}

func (k *kibana) ResolveImages(is *operatorv1.ImageSet) error {
	reg := k.cfg.Installation.Registry
	path := k.cfg.Installation.ImagePath
	prefix := k.cfg.Installation.ImagePrefix

	var err error
	errMsgs := make([]string, 0)
	if err != nil {
		errMsgs = append(errMsgs, err.Error())
	}

	k.kibanaImage, err = components.GetReference(components.ComponentKibana, reg, path, prefix, is)
	if err != nil {
		errMsgs = append(errMsgs, err.Error())
	}

	if k.cfg.Installation.CertificateManagement != nil {
		k.csrImage, err = certificatemanagement.ResolveCSRInitImage(k.cfg.Installation, is)
		if err != nil {
			errMsgs = append(errMsgs, err.Error())
		}
	}

	if len(errMsgs) != 0 {
		return fmt.Errorf("%s", strings.Join(errMsgs, ","))
	}
	return nil
}

func (k *kibana) SupportedOSType() rmeta.OSType {
	return rmeta.OSTypeLinux
}

func (k *kibana) Objects() ([]client.Object, []client.Object) {
	var toCreate, toDelete []client.Object

	// Delete a previous Kibana CR if LogStorage is in the process of being deleted
	if k.cfg.LogStorage != nil && k.cfg.LogStorage.DeletionTimestamp != nil {
		if k.cfg.Kibana != nil {
			if k.cfg.Kibana.DeletionTimestamp == nil {
				toDelete = append(toDelete, k.cfg.Kibana)
			}
		}
		return toCreate, toDelete
	}

	if k.cfg.Enabled {
		// Kibana CRs
		// In order to use restricted, we need to change elastic-internal-init-config:
		// - securityContext.allowPrivilegeEscalation=false
		// - securityContext.capabilities.drop=["ALL"]
		// - securityContext.runAsNonRoot=true
		// - securityContext.seccompProfile.type to "RuntimeDefault" or "Localhost"
		toCreate = append(toCreate, render.CreateNamespace(Namespace, k.cfg.Installation.KubernetesProvider, render.PSSBaseline, k.cfg.Installation.Azure))
		toCreate = append(toCreate, k.calicoSystemPolicy())
		toCreate = append(toCreate, networkpolicy.CalicoSystemDefaultDeny(Namespace))
		toCreate = append(toCreate, render.CreateOperatorSecretsRoleBinding(Namespace))
		toCreate = append(toCreate, k.serviceAccount())

		// allow-tigera Tier was renamed to calico-system
		toDelete = append(toDelete,
			networkpolicy.DeprecatedAllowTigeraNetworkPolicyObject("kibana-access", Namespace),
			networkpolicy.DeprecatedAllowTigeraNetworkPolicyObject("default-deny", Namespace),
		)

		if k.cfg.Installation.KubernetesProvider.IsOpenShift() {
			toCreate = append(toCreate, k.clusterRole(), k.clusterRoleBinding())
		}

		if len(k.cfg.PullSecrets) > 0 {
			toCreate = append(toCreate, secret.ToRuntimeObjects(secret.CopyToNamespace(Namespace, k.cfg.PullSecrets...)...)...)
		}

		if len(k.kibanaSecrets) > 0 {
			toCreate = append(toCreate, secret.ToRuntimeObjects(k.kibanaSecrets...)...)
		}

		toCreate = append(toCreate, k.kibanaCR())
	} else {
		toDelete = append(toDelete, k.kibanaCR())
	}

	if k.cfg.KbService != nil && k.cfg.KbService.Spec.Type == corev1.ServiceTypeExternalName {
		toDelete = append(toDelete, k.cfg.KbService)
	}

	if k.cfg.Installation.CertificateManagement != nil {
		if k.cfg.KibanaKeyPair != nil && k.cfg.KibanaKeyPair.UseCertificateManagement() {
			// We need to render a secret. It won't ever be used by Kibana for TLS, but is needed to pass ECK's checks.
			// If the secret changes / gets reconciled, it will not trigger a re-render of Kibana.
			unusedSecret := k.cfg.KibanaKeyPair.Secret(Namespace)
			unusedSecret.Data = k.cfg.UnusedTLSSecret.Data
			toCreate = append(toCreate, unusedSecret)
		}
	} else if k.cfg.UnusedTLSSecret != nil {
		toDelete = append(toDelete, k.cfg.UnusedTLSSecret)
	}

	return toCreate, toDelete
}

func (k *kibana) Ready() bool {
	return true
}

func (k *kibana) serviceAccount() *corev1.ServiceAccount {
	return &corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Name:      ObjectName,
			Namespace: Namespace,
		},
	}
}

func (k *kibana) kibanaCR() *kbv1.Kibana {
	server := map[string]interface{}{
		"basePath":        fmt.Sprintf("/%s", BasePath),
		"rewriteBasePath": true,
		"defaultRoute":    fmt.Sprintf(DefaultRoute, TimeFilter, url.PathEscape(FlowsDashboardName)),
		"customResponseHeaders": map[string]interface{}{
			"X-Frame-Options": "DENY",
		},
	}

	if k.cfg.BaseURL != "" {
		server["publicBaseUrl"] = fmt.Sprintf("%s/%s", k.cfg.BaseURL, BasePath)
	}

	config := map[string]interface{}{
		"elasticsearch.ssl.certificateAuthorities": []string{"/usr/share/kibana/config/elasticsearch-certs/tls.crt"},
		"server":                             server,
		"xpack.security.session.lifespan":    "8h",
		"xpack.security.session.idleTimeout": "30m",
		"tigera": map[string]interface{}{
			"enabled":        true,
			"licenseEdition": "enterpriseEdition",
		},
		// Telemetry is unwanted for the majority of our customers and if enabled can cause blocked flows. This flag
		// can still be overwritten in the Kibana Settings if the user desires it.
		"telemetry.optIn": false,
		// Disabling all the fleet egress is a difficult task. It does not seem to adhere to the doocumented settings.
		// A combination of settings is required.
		"xpack.fleet.enabled":        false,
		"xpack.fleet.agents.enabled": false,
		"xpack.fleet.isAirGapped":    true,
		"xpack.fleet.packages":       []string{},
		"xpack.fleet.registryUrl":    "http://localhost:5601",
		// Without this, upgrades from Kibana 7.x crashloop on orphan `ingest_manager_settings` docs.
		"migrations.discardUnknownObjects": components.ComponentEckKibana.Version,
		// Setting this to false will prevent it from connecting to endpoints outside of this cluster.
		// See: https://www.elastic.co/guide/en/kibana/8.19/settings.html
		"newsfeed.enabled": false,
		// Setting this to localhost will prevent AI features from connecting to endpoints outside of this cluster.
		// No other way of disabling AI is possible at this time. We will still get this log, but at least it
		// prevents us from seeing denied traffic in the service graph:
		// "[INFO ][plugins.observabilityAIAssistant] Knowledge base index does not exist. Aborting updating index assets"
		// "[ERROR][plugins.taskManager] Failed to poll for work: Response aborted while reading the body"
		"xpack.productDocBase.artifactRepositoryUrl": "http://localhost:5601",
	}

	// TODO: This shouldn't be done with a global variable set by the controller.
	if len(CloudKibanaConfigOverrides) != 0 {
		for k, v := range CloudKibanaConfigOverrides {
			config[k] = v
		}
	}

	var initContainers []corev1.Container
	var volumes []corev1.Volume
	var automountToken bool
	volumeMounts := []corev1.VolumeMount{
		{
			// We need to override this mount and change the mountPath. Otherwise, ECK will mount an emptyDir in the
			// original location (/usr/share/kibana/plugins), which would remove our custom theme resulting in
			// crash-looping pods, because our custom config is unexpected.
			Name:      "kibana-plugins",
			MountPath: "/mnt/dummy-location/",
		},
	}
	sc := securitycontext.NewNonRootContext()
	if k.cfg.Installation.CertificateManagement != nil {
		config["elasticsearch.ssl.certificateAuthorities"] = []string{"/mnt/elastic-internal/http-certs/ca.crt"}
		automountToken = true
		csrInitContainer := certificatemanagement.CreateCSRInitContainer(
			k.cfg.Installation.CertificateManagement,
			render.CSRVolumeNameHTTP,
			k.csrImage,
			render.CSRVolumeNameHTTP,
			render.ElasticsearchServiceName,
			corev1.TLSPrivateKeyKey,
			corev1.TLSCertKey,
			dns.GetServiceDNSNames(ServiceName, Namespace, k.cfg.ClusterDomain),
			Namespace,
			sc,
		)

		initContainers = append(initContainers, csrInitContainer)
		volumeMounts = append(volumeMounts, corev1.VolumeMount{
			Name:      render.CSRVolumeNameHTTP,
			MountPath: "/mnt/elastic-internal/http-certs/",
		})
		volumes = append(volumes,
			corev1.Volume{
				Name: render.CSRVolumeNameHTTP,
				VolumeSource: corev1.VolumeSource{
					EmptyDir: &corev1.EmptyDirVolumeSource{},
				},
			},
			// Volume where we place the ca cert.
			corev1.Volume{
				Name: render.CAVolumeName,
				VolumeSource: corev1.VolumeSource{
					EmptyDir: &corev1.EmptyDirVolumeSource{},
				},
			})
	}

	count := int32(1)
	if k.cfg.LogStorage != nil && k.cfg.LogStorage.Spec.Kibana != nil &&
		k.cfg.LogStorage.Spec.Kibana.Spec != nil && k.cfg.LogStorage.Spec.Kibana.Spec.Replicas != nil {
		count = *k.cfg.LogStorage.Spec.Kibana.Spec.Replicas
	}

	tolerations := k.cfg.Installation.ControlPlaneTolerations
	if k.cfg.Installation.KubernetesProvider.IsGKE() {
		tolerations = append(tolerations, rmeta.TolerateGKEARM64NoSchedule)
	}

	kibana := &kbv1.Kibana{
		TypeMeta: metav1.TypeMeta{Kind: "Kibana", APIVersion: "kibana.k8s.elastic.co/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      CRName,
			Namespace: Namespace,
			Labels: map[string]string{
				"k8s-app": CRName,
			},
		},
		Spec: kbv1.KibanaSpec{
			Version: components.ComponentEckKibana.Version,
			Image:   k.kibanaImage,
			Config: &cmnv1.Config{
				Data: config,
			},
			Count: count,
			HTTP: cmnv1.HTTPConfig{
				TLS: cmnv1.TLSOptions{
					Certificate: cmnv1.SecretRef{
						SecretName: TigeraKibanaCertSecret,
					},
				},
			},
			ElasticsearchRef: cmnv1.ObjectSelector{
				Name:      render.ElasticsearchName,
				Namespace: render.ElasticsearchNamespace,
			},
			PodTemplate: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: Namespace,
					Annotations: map[string]string{
						TLSAnnotationHash: rmeta.SecretsAnnotationHash(k.kibanaSecrets...),
					},
					Labels: map[string]string{
						"name":    CRName,
						"k8s-app": CRName,
					},
				},
				Spec: corev1.PodSpec{
					ImagePullSecrets:             secret.GetReferenceList(k.cfg.PullSecrets),
					ServiceAccountName:           ObjectName,
					NodeSelector:                 k.cfg.Installation.ControlPlaneNodeSelector,
					Tolerations:                  tolerations,
					InitContainers:               initContainers,
					AutomountServiceAccountToken: &automountToken,
					Containers: []corev1.Container{{
						Name: "kibana",
						ReadinessProbe: &corev1.Probe{
							ProbeHandler: corev1.ProbeHandler{
								HTTPGet: &corev1.HTTPGetAction{
									Path: fmt.Sprintf("/%s/login", BasePath),
									Port: intstr.IntOrString{
										IntVal: Port,
									},
									Scheme: corev1.URISchemeHTTPS,
								},
							},
						},
						SecurityContext: sc,
						VolumeMounts:    volumeMounts,
					}},
					Volumes: volumes,
				},
			},
		},
	}

	if count > 1 {
		kibana.Spec.PodTemplate.Spec.Affinity = podaffinity.NewPodAntiAffinity(CRName, []string{Namespace})
	}

	if k.cfg.LogStorage != nil {
		if overrides := k.cfg.LogStorage.Spec.Kibana; overrides != nil {
			rcomponents.ApplyKibanaOverrides(kibana, overrides)
		}
	}

	return kibana
}

func (k *kibana) clusterRole() *rbacv1.ClusterRole {
	return &rbacv1.ClusterRole{
		TypeMeta: metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name: ObjectName,
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

func (k *kibana) clusterRoleBinding() *rbacv1.ClusterRoleBinding {
	return &rbacv1.ClusterRoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name: ObjectName,
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "ClusterRole",
			Name:     ObjectName,
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      "ServiceAccount",
				Name:      ObjectName,
				Namespace: Namespace,
			},
		},
	}
}

// Allow access to Kibana
func (k *kibana) calicoSystemPolicy() *v3.NetworkPolicy {
	egressRules := []v3.Rule{
		{
			Action:      v3.Allow,
			Protocol:    &networkpolicy.TCPProtocol,
			Source:      v3.EntityRule{},
			Destination: render.ElasticsearchEntityRule,
		},
	}
	egressRules = networkpolicy.AppendDNSEgressRules(egressRules, k.cfg.Provider.IsOpenShift())
	egressRules = append(egressRules, []v3.Rule{
		{
			Action:      v3.Allow,
			Protocol:    &networkpolicy.TCPProtocol,
			Destination: networkpolicy.KubeAPIServerEntityRule,
		},
		{
			Action:      v3.Allow,
			Protocol:    &networkpolicy.TCPProtocol,
			Destination: networkpolicy.DefaultHelper().ESGatewayEntityRule(),
		},
	}...)

	kibanaPortIngressDestination := v3.EntityRule{
		Ports: networkpolicy.Ports(Port),
	}
	return &v3.NetworkPolicy{
		TypeMeta: metav1.TypeMeta{Kind: "NetworkPolicy", APIVersion: "projectcalico.org/v3"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      PolicyName,
			Namespace: Namespace,
		},
		Spec: v3.NetworkPolicySpec{
			Order:    &networkpolicy.HighPrecedenceOrder,
			Tier:     networkpolicy.CalicoTierName,
			Selector: networkpolicy.KubernetesAppSelector(CRName),
			Types:    []v3.PolicyType{v3.PolicyTypeIngress, v3.PolicyTypeEgress},
			Ingress: []v3.Rule{
				{
					Action:   v3.Allow,
					Protocol: &networkpolicy.TCPProtocol,
					Source: v3.EntityRule{
						// This policy allows access to Kibana from anywhere.
						Nets: []string{"0.0.0.0/0"},
					},
					Destination: kibanaPortIngressDestination,
				},
				{
					Action:   v3.Allow,
					Protocol: &networkpolicy.TCPProtocol,
					Source: v3.EntityRule{
						// This policy allows access to Kibana from anywhere.
						Nets: []string{"::/0"},
					},
					Destination: kibanaPortIngressDestination,
				},
				{
					Action:      v3.Allow,
					Protocol:    &networkpolicy.TCPProtocol,
					Source:      networkpolicy.DefaultHelper().ESGatewaySourceEntityRule(),
					Destination: kibanaPortIngressDestination,
				},
				{
					Action:      v3.Allow,
					Protocol:    &networkpolicy.TCPProtocol,
					Source:      networkpolicy.DefaultHelper().DashboardInstallerSourceEntityRule(),
					Destination: kibanaPortIngressDestination,
				},
				{
					Action:      v3.Allow,
					Protocol:    &networkpolicy.TCPProtocol,
					Source:      render.ECKOperatorSourceEntityRule,
					Destination: kibanaPortIngressDestination,
				},
			},
			Egress: egressRules,
		},
	}
}
