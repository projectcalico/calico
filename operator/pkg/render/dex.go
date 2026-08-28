// Copyright (c) 2019-2026 Tigera, Inc. All rights reserved.

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
//

package render

import (
	"fmt"
	"net"
	"net/url"
	"strings"

	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	"github.com/tigera/api/pkg/lib/numorstring"
	"golang.org/x/net/http/httpproxy"
	"gopkg.in/yaml.v2"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"sigs.k8s.io/controller-runtime/pkg/client"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/components"
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
	DexNamespace     = "tigera-dex"
	DexObjectName    = "tigera-dex"
	DexPort          = 5556
	DexTLSSecretName = "tigera-dex-tls"
	DexClientId      = "tigera-manager"
	DexPolicyName    = networkpolicy.CalicoComponentPolicyPrefix + "dex"

	// TigeraCAPublicSecretName holds a copy of the operator's CA certificate (from tigera-ca-private)
	// in calico-system. It exists so that an OpenShift Ingress fronting the manager can reference it
	// via the destination-CA-certificate annotation on a reencrypt route. Only rendered when the
	// Authentication CR is configured to use the OpenShift IDP.
	TigeraCAPublicSecretName = "tigera-ca-public"
)

var DexEntityRule = networkpolicy.CreateEntityRule(DexNamespace, DexObjectName, DexPort)

func Dex(cfg *DexComponentConfiguration) Component {
	return &dexComponent{
		cfg:       cfg,
		connector: cfg.DexConfig.Connector(),
	}
}

// DexComponentConfiguration contains all the config information needed to render the component.
type DexComponentConfiguration struct {
	PullSecrets   []*corev1.Secret
	OpenShift     bool
	Installation  *operatorv1.InstallationSpec
	DexConfig     DexConfig
	ClusterDomain string
	DeleteDex     bool
	TLSKeyPair    certificatemanagement.KeyPairInterface
	TrustedBundle certificatemanagement.TrustedBundle

	// TigeraCAKeyPair is the operator CA keypair (backed by tigera-ca-private). Its certificate is
	// copied into the tigera-ca-public Secret when the OpenShift IDP is configured.
	TigeraCAKeyPair certificatemanagement.KeyPairInterface

	Authentication *operatorv1.Authentication

	// PodProxies represents the resolved proxy configuration for each Dex pod.
	// If this slice is empty, then resolution has not yet occurred. Pods with no proxy
	// configured are represented with a nil value.
	PodProxies []*httpproxy.Config
}

type dexComponent struct {
	cfg          *DexComponentConfiguration
	connector    map[string]interface{}
	image        string
	csrInitImage string
}

func (c *dexComponent) ResolveImages(is *operatorv1.ImageSet) error {
	reg := c.cfg.Installation.Registry
	path := c.cfg.Installation.ImagePath
	prefix := c.cfg.Installation.ImagePrefix
	var err error
	c.image, err = components.GetReference(components.ComponentDex, reg, path, prefix, is)

	var errMsgs []string
	if err != nil {
		errMsgs = append(errMsgs, err.Error())
	}

	if c.cfg.Installation.CertificateManagement != nil {
		c.csrInitImage, err = certificatemanagement.ResolveCSRInitImage(c.cfg.Installation, is)
		if err != nil {
			errMsgs = append(errMsgs, err.Error())
		}
	}

	if len(errMsgs) != 0 {
		return fmt.Errorf("%s", strings.Join(errMsgs, ","))
	}
	return nil
}

func (*dexComponent) SupportedOSType() rmeta.OSType {
	return rmeta.OSTypeLinux
}

func (c *dexComponent) Objects() ([]client.Object, []client.Object) {

	objs := []client.Object{
		CreateNamespace(DexObjectName, c.cfg.Installation.KubernetesProvider, PSSRestricted, c.cfg.Installation.Azure),
		c.calicoSystemNetworkPolicy(c.cfg.Installation.Variant),
		networkpolicy.CalicoSystemDefaultDeny(DexNamespace),
		CreateOperatorSecretsRoleBinding(DexNamespace),
		c.serviceAccount(),
		c.deployment(),
		c.service(),
		c.clusterRole(),
		c.clusterRoleBinding(),
		c.configMap(),
	}
	objectsToDelete := []client.Object{
		// Delete the secret called tigera-dex which in the past was used to store a client secret.
		&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: DexObjectName, Name: DexObjectName}},
		&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: common.OperatorNamespace(), Name: DexObjectName}},
		// allow-tigera Tier was renamed to calico-system
		networkpolicy.DeprecatedAllowTigeraNetworkPolicyObject("allow-tigera-dex", DexNamespace),
		networkpolicy.DeprecatedAllowTigeraNetworkPolicyObject("default-deny", DexNamespace),
	}

	// TODO Some of the secrets created in the operator namespace are created by the customer (i.e. oidc credentials)
	// TODO so we can't just do a blanket delete of the secrets in the operator namespace. We need to refactor
	// TODO the RequiredSecrets in the dex condig to not pass back secrets of this type.
	if !c.cfg.DeleteDex {
		objs = append(objs, secret.ToRuntimeObjects(c.cfg.DexConfig.RequiredSecrets(common.OperatorNamespace())...)...)

		// The Dex namespace exists only for non-Tigera OIDC types to create secrets within the namespace.
		objs = append(objs, secret.ToRuntimeObjects(c.cfg.DexConfig.RequiredSecrets(DexNamespace)...)...)
		objs = append(objs, secret.ToSecretProviderClassRuntimeObjects(c.cfg.DexConfig.RequiredSecretProviderClass(DexNamespace)...)...)
		objs = append(objs, secret.ToRuntimeObjects(secret.CopyToNamespace(DexNamespace, c.cfg.PullSecrets...)...)...)
	}

	if c.cfg.Installation.CertificateManagement != nil {
		objs = append(objs, certificatemanagement.CSRClusterRoleBinding(DexObjectName, DexNamespace))
	}

	if c.cfg.Authentication != nil && c.cfg.Authentication.Spec.Openshift != nil {
		objs = append(objs, c.tigeraCAPublicSecret())
	} else {
		objectsToDelete = append(objectsToDelete, &corev1.Secret{
			TypeMeta:   metav1.TypeMeta{Kind: "Secret", APIVersion: "v1"},
			ObjectMeta: metav1.ObjectMeta{Name: TigeraCAPublicSecretName, Namespace: common.CalicoNamespace},
		})
	}

	if c.cfg.DeleteDex {
		return nil, append(objs, objectsToDelete...)
	}
	return objs, objectsToDelete
}

// tigeraCAPublicSecret returns an Opaque Secret in calico-system with the operator's CA certificate
// under the tls.crt key. The customer points an Ingress at it via the
// route.openshift.io/destination-ca-certificate-secret annotation, and OpenShift's
// ingress-to-route controller copies this into the generated reencrypt Route's destinationCACertificate.
// Both the Ingress and this Secret must live in calico-system (same-namespace lookup in the upstream
// controller). Type Opaque (not kubernetes.io/tls) because we have no private key to pair with the cert.
func (c *dexComponent) tigeraCAPublicSecret() *corev1.Secret {
	return &corev1.Secret{
		TypeMeta: metav1.TypeMeta{Kind: "Secret", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      TigeraCAPublicSecretName,
			Namespace: common.CalicoNamespace,
		},
		Type: corev1.SecretTypeOpaque,
		Data: map[string][]byte{
			corev1.TLSCertKey: c.cfg.TigeraCAKeyPair.GetCertificatePEM(),
		},
	}
}

func (c *dexComponent) Ready() bool {
	return true
}

func (c *dexComponent) serviceAccount() *corev1.ServiceAccount {
	return &corev1.ServiceAccount{
		TypeMeta:   metav1.TypeMeta{Kind: "ServiceAccount", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{Name: DexObjectName, Namespace: DexNamespace},
	}
}

func (c *dexComponent) clusterRole() client.Object {
	rules := []rbacv1.PolicyRule{
		{
			APIGroups: []string{"dex.coreos.com"},
			Resources: []string{"*"},
			Verbs:     []string{"*"},
		},
		{
			APIGroups: []string{"apiextensions.k8s.io"},
			Resources: []string{"customresourcedefinitions"},
			Verbs:     []string{"create"},
		},
	}

	if c.cfg.OpenShift {
		rules = append(rules, rbacv1.PolicyRule{
			APIGroups:     []string{"security.openshift.io"},
			Resources:     []string{"securitycontextconstraints"},
			Verbs:         []string{"use"},
			ResourceNames: []string{securitycontextconstraints.NonRootV2},
		})
	}

	return &rbacv1.ClusterRole{
		TypeMeta: metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name: DexObjectName,
		},
		Rules: rules,
	}
}

func (c *dexComponent) clusterRoleBinding() client.Object {
	return &rbacv1.ClusterRoleBinding{
		TypeMeta: metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name: DexObjectName,
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "ClusterRole",
			Name:     DexObjectName,
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      "ServiceAccount",
				Name:      DexObjectName,
				Namespace: DexNamespace,
			},
		},
	}
}

func (c *dexComponent) deployment() client.Object {
	var initContainers []corev1.Container
	sc := securitycontext.NewNonRootContext()
	if c.cfg.TLSKeyPair.UseCertificateManagement() {
		initContainers = append(initContainers, c.cfg.TLSKeyPair.InitContainer(DexNamespace, sc))
	}

	annotations := c.cfg.DexConfig.RequiredAnnotations()
	for k, v := range c.cfg.TrustedBundle.HashAnnotations() {
		annotations[k] = v
	}
	annotations[c.cfg.TLSKeyPair.HashAnnotationKey()] = c.cfg.TLSKeyPair.HashAnnotationValue()

	mounts := c.cfg.DexConfig.RequiredVolumeMounts()
	mounts = append(mounts, c.cfg.TLSKeyPair.VolumeMount(c.SupportedOSType()))
	mounts = append(mounts, c.cfg.TrustedBundle.VolumeMounts(c.SupportedOSType())...)

	tolerations := append(c.cfg.Installation.ControlPlaneTolerations, rmeta.TolerateControlPlane...)
	if c.cfg.Installation.KubernetesProvider.IsGKE() {
		tolerations = append(tolerations, rmeta.TolerateGKEARM64NoSchedule)
	}

	envVars := c.cfg.DexConfig.RequiredEnv("")
	envVars = append(envVars, c.cfg.Installation.Proxy.EnvVars()...)
	if c.cfg.DexConfig.RequiredSecretProviderClass(DexNamespace) != nil {
		envVars = append(envVars, corev1.EnvVar{Name: "WATCH_DIR", Value: "/mnt/secrets-store"})
	}

	d := &appsv1.Deployment{
		TypeMeta: metav1.TypeMeta{Kind: "Deployment", APIVersion: "apps/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      DexObjectName,
			Namespace: DexNamespace,
		},
		Spec: appsv1.DeploymentSpec{
			Replicas: c.cfg.Installation.ControlPlaneReplicas,
			Strategy: appsv1.DeploymentStrategy{
				Type: appsv1.RecreateDeploymentStrategyType,
			},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Name:        DexObjectName,
					Namespace:   DexNamespace,
					Annotations: annotations,
				},
				Spec: corev1.PodSpec{
					NodeSelector:       c.cfg.Installation.ControlPlaneNodeSelector,
					ServiceAccountName: DexObjectName,
					Tolerations:        tolerations,
					ImagePullSecrets:   secret.GetReferenceList(c.cfg.PullSecrets),
					InitContainers:     initContainers,
					Containers: []corev1.Container{
						{
							Name:            DexObjectName,
							Image:           c.image,
							Env:             envVars,
							LivenessProbe:   c.probe(),
							SecurityContext: sc,

							Ports: []corev1.ContainerPort{
								{
									Name:          "https",
									ContainerPort: DexPort,
								},
							},
							VolumeMounts: mounts,
						},
					},
					Volumes: append(c.cfg.DexConfig.RequiredVolumes(), c.cfg.TLSKeyPair.Volume(), TrustedBundleVolume(c.cfg.TrustedBundle)),
				},
			},
		},
	}

	if c.cfg.Installation.ControlPlaneReplicas != nil && *c.cfg.Installation.ControlPlaneReplicas > 1 {
		d.Spec.Template.Spec.Affinity = podaffinity.NewPodAntiAffinity(DexObjectName, []string{DexNamespace})
	}

	if c.cfg.Authentication != nil {
		if overrides := c.cfg.Authentication.Spec.DexDeployment; overrides != nil {
			rcomponents.ApplyDeploymentOverrides(d, overrides)
		}
	}

	return d
}

func (c *dexComponent) service() client.Object {
	return &corev1.Service{
		TypeMeta: metav1.TypeMeta{Kind: "Service", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      DexObjectName,
			Namespace: DexNamespace,
		},
		Spec: corev1.ServiceSpec{
			Selector: map[string]string{
				"k8s-app": DexObjectName,
			},
			Ports: []corev1.ServicePort{
				{
					Name: DexObjectName,
					Port: DexPort,
					TargetPort: intstr.IntOrString{
						Type:   intstr.Int,
						IntVal: DexPort,
					},
					Protocol: corev1.ProtocolTCP,
				},
			},
		},
	}
}

// Perform a HTTP GET to determine if an endpoint is available.
func (c *dexComponent) probe() *corev1.Probe {
	return &corev1.Probe{
		ProbeHandler: corev1.ProbeHandler{
			HTTPGet: &corev1.HTTPGetAction{
				Path:   "/dex/.well-known/openid-configuration",
				Port:   intstr.FromInt(DexPort),
				Scheme: corev1.URISchemeHTTPS,
			},
		},
		InitialDelaySeconds: 90,
	}
}

func (c *dexComponent) configMap() *corev1.ConfigMap {
	bytes, err := yaml.Marshal(map[string]interface{}{
		"issuer": c.cfg.DexConfig.Issuer(),
		"storage": map[string]interface{}{
			"type": "kubernetes",
			"config": map[string]bool{
				"inCluster": true,
			},
		},
		"web": map[string]interface{}{
			"https":                   "0.0.0.0:5556",
			"tlsCert":                 c.cfg.TLSKeyPair.VolumeMountCertificateFilePath(),
			"tlsKey":                  c.cfg.TLSKeyPair.VolumeMountKeyFilePath(),
			"allowedOrigins":          []string{"*"},
			"discoveryAllowedOrigins": []string{"*"},
			"headers": map[string]string{
				"X-Content-Type-Options": "nosniff",
				"X-XSS-Protection":       "1; mode=block",
				// Since Dex is running on the same domain as the manager, this will allow an iFrame
				// to make a silent-callback to refresh access tokens.
				"X-Frame-Options":           "SAMEORIGIN",
				"Strict-Transport-Security": "max-age=31536000; includeSubDomains",
			},
		},
		"connectors": []map[string]interface{}{c.connector},
		"oauth2": map[string]interface{}{
			"skipApprovalScreen": true,
			"responseTypes":      []string{"id_token", "code", "token"},
		},
		"staticClients": []map[string]interface{}{
			{
				"id":           DexClientId,
				"redirectURIs": c.cfg.DexConfig.RedirectURIs(),
				"name":         "Calico Enterprise Manager",
				// When public is true, it enables the code PKCE flow as opposed to a client_secret,
				// which is not secure for SPA.
				"public": true,
			},
		},
		"expiry": map[string]string{
			// Default duration is 24h. This is too high for most organizations. Setting it to 15m.
			"idTokens": "15m",
		},
	})
	if err != nil {
		// Panic since this would be a developer error, as the marshaled struct is one created by our code.
		panic(err)
	}
	return &corev1.ConfigMap{
		TypeMeta: metav1.TypeMeta{Kind: "ConfigMap", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      DexObjectName,
			Namespace: DexNamespace,
		},
		Data: map[string]string{
			"config.yaml": string(bytes),
		},
	}
}

func (c *dexComponent) calicoSystemNetworkPolicy(installationVariant operatorv1.ProductVariant) *v3.NetworkPolicy {
	egressRules := []v3.Rule{}
	egressRules = networkpolicy.AppendDNSEgressRules(egressRules, c.cfg.OpenShift)
	egressRules = append(egressRules, []v3.Rule{
		{
			Action:      v3.Allow,
			Protocol:    &networkpolicy.TCPProtocol,
			Destination: networkpolicy.KubeAPIServerEntityRule,
		},
	}...)
	for _, egressRule := range c.resolveEgressRulesByDestination() {
		egressRules = append(egressRules, egressRule)
	}

	dexIngressPortDestination := v3.EntityRule{
		Ports: networkpolicy.Ports(DexPort),
	}

	return &v3.NetworkPolicy{
		TypeMeta: metav1.TypeMeta{Kind: "NetworkPolicy", APIVersion: "projectcalico.org/v3"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      DexPolicyName,
			Namespace: DexNamespace,
		},
		Spec: v3.NetworkPolicySpec{
			Order:    &networkpolicy.HighPrecedenceOrder,
			Tier:     networkpolicy.CalicoTierName,
			Selector: networkpolicy.KubernetesAppSelector(DexObjectName),
			Types:    []v3.PolicyType{v3.PolicyTypeIngress, v3.PolicyTypeEgress},
			Ingress: []v3.Rule{
				{
					Action:      v3.Allow,
					Protocol:    &networkpolicy.TCPProtocol,
					Source:      networkpolicy.DefaultHelper().ManagerSourceEntityRule(),
					Destination: dexIngressPortDestination,
				},
				{
					Action:      v3.Allow,
					Protocol:    &networkpolicy.TCPProtocol,
					Source:      networkpolicy.DefaultHelper().ESGatewaySourceEntityRule(),
					Destination: dexIngressPortDestination,
				},
				{
					Action:      v3.Allow,
					Protocol:    &networkpolicy.TCPProtocol,
					Source:      PacketCaptureSourceEntityRule,
					Destination: dexIngressPortDestination,
				},
				{
					Action:      v3.Allow,
					Protocol:    &networkpolicy.TCPProtocol,
					Source:      networkpolicy.PrometheusSourceEntityRule,
					Destination: dexIngressPortDestination,
				},
				{
					Action:      v3.Allow,
					Protocol:    &networkpolicy.TCPProtocol,
					Source:      networkpolicy.DefaultHelper().APIServerSourceEntityRule(installationVariant),
					Destination: dexIngressPortDestination,
				},
			},
			Egress: egressRules,
		},
	}
}

func (c *dexComponent) resolveEgressRulesByDestination() map[string]v3.Rule {
	egressRulesByDestination := make(map[string]v3.Rule)
	processedPodProxies := ProcessPodProxies(c.cfg.PodProxies)
	for i, podProxy := range processedPodProxies {
		egressDestinations, err := resolveEgressDestinationsForPod(podProxy)
		if err != nil {
			log.Error(err, fmt.Sprintf("failed to resolve egress destinations for pod %d, skipping for policy rendering", i))
			continue
		}

		for _, egressDestination := range egressDestinations {
			egressRule, err := resolveEgressRuleForDestination(egressDestination)
			if err != nil {
				log.Error(err, fmt.Sprintf("failed to resolve egress rule for pod %d, skipping for policy rendering", i))
				continue
			}

			egressRulesByDestination[egressDestination] = egressRule
		}
	}

	return egressRulesByDestination
}

// resolveEgressDestinationsForPod collects all possible http proxy destinations and all possible IdP destinations.
// In the future, this function may return only the specific destinations it expects Dex pods to connect to given the
// current issuer configuration (in the Authentication CR) and the HTTP proxy configuration.
func resolveEgressDestinationsForPod(podProxy *httpproxy.Config) ([]string, error) {
	var egressDestinations []string

	if podProxy == nil {
		podProxy = &httpproxy.Config{}
	}

	// From here, we resolve multiple destinations by assuming any of the configured proxies could be active, and that
	// an IdP could live at any IP.
	// idp-resolution: In the future, we could resolve a single destination by resolving our expected IdP
	// issuer URL and using podProxy.ProxyFunc to resolve a single expected destination URL.
	if podProxy.HTTPProxy != "" {
		httpProxyURL, err := url.Parse(podProxy.HTTPProxy)
		if err != nil {
			return nil, err
		}

		httpProxyDestination, err := parseHostPortFromURL(httpProxyURL)
		if err != nil {
			return nil, err
		}

		egressDestinations = append(egressDestinations, httpProxyDestination)
	}

	if podProxy.HTTPSProxy != "" {
		httpsProxyURL, err := url.Parse(podProxy.HTTPSProxy)
		if err != nil {
			return nil, err
		}

		httpsProxyDestination, err := parseHostPortFromURL(httpsProxyURL)
		if err != nil {
			return nil, err
		}

		egressDestinations = append(egressDestinations, httpsProxyDestination)
	}

	egressDestinations = append(egressDestinations, "0.0.0.0/0")
	egressDestinations = append(egressDestinations, "::/0")

	return egressDestinations, nil
}

func resolveEgressRuleForDestination(destination string) (v3.Rule, error) {
	// Support "any" destinations that signify any potential IdP destination IP.
	// idp-resolution: These cases can be removed if we are able to resolve specific IdP destinations based on the Authentication config.
	if destination == "0.0.0.0/0" {
		return v3.Rule{
			Action:   v3.Allow,
			Protocol: &networkpolicy.TCPProtocol,
			Destination: v3.EntityRule{
				Nets:  []string{"0.0.0.0/0"},
				Ports: networkpolicy.Ports(443, 6443, 389, 636),
			},
		}, nil
	}
	if destination == "::/0" {
		return v3.Rule{
			Action:   v3.Allow,
			Protocol: &networkpolicy.TCPProtocol,
			Destination: v3.EntityRule{
				Nets:  []string{"::/0"},
				Ports: networkpolicy.Ports(443, 6443, 389, 636),
			},
		}, nil
	}

	// Process specific destinations.
	var egressRule v3.Rule
	host, port, err := net.SplitHostPort(destination)
	if err != nil {
		return v3.Rule{}, err
	}
	parsedPort, err := numorstring.PortFromString(port)
	if err != nil {
		return v3.Rule{}, err
	}
	parsedIp := net.ParseIP(host)
	if parsedIp == nil {
		// Assume host is a valid hostname.
		egressRule = v3.Rule{
			Action:   v3.Allow,
			Protocol: &networkpolicy.TCPProtocol,
			Destination: v3.EntityRule{
				Domains: []string{host},
				Ports:   []numorstring.Port{parsedPort},
			},
		}
	} else {
		var netSuffix string
		if parsedIp.To4() != nil {
			netSuffix = "/32"
		} else {
			netSuffix = "/128"
		}

		egressRule = v3.Rule{
			Action:   v3.Allow,
			Protocol: &networkpolicy.TCPProtocol,
			Destination: v3.EntityRule{
				Nets:  []string{parsedIp.String() + netSuffix},
				Ports: []numorstring.Port{parsedPort},
			},
		}
	}

	return egressRule, nil
}

func parseHostPortFromURL(url *url.URL) (string, error) {
	if url.Port() != "" {
		// Host is already in host:port form.
		return url.Host, nil
	}

	switch url.Scheme {
	case "http":
		return net.JoinHostPort(url.Host, "80"), nil
	case "https":
		return net.JoinHostPort(url.Host, "443"), nil
	default:
		return "", fmt.Errorf("unexpected scheme for URL: %s", url.Scheme)
	}
}
