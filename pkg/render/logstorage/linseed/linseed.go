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

package linseed

import (
	"fmt"
	"strconv"
	"strings"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/apiserver/pkg/authentication/serviceaccount"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"

	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/components"
	"github.com/tigera/operator/pkg/render"
	rcomponents "github.com/tigera/operator/pkg/render/common/components"
	relasticsearch "github.com/tigera/operator/pkg/render/common/elasticsearch"
	rmeta "github.com/tigera/operator/pkg/render/common/meta"
	"github.com/tigera/operator/pkg/render/common/networkpolicy"
	"github.com/tigera/operator/pkg/render/common/podaffinity"
	"github.com/tigera/operator/pkg/render/common/secret"
	"github.com/tigera/operator/pkg/render/common/securitycontext"
	"github.com/tigera/operator/pkg/render/common/securitycontextconstraints"
	"github.com/tigera/operator/pkg/render/logstorage"
	"github.com/tigera/operator/pkg/render/logstorage/esmetrics"
	"github.com/tigera/operator/pkg/tls/certificatemanagement"
)

const (
	DeploymentName                                         = "tigera-linseed"
	ServiceAccountName                                     = "tigera-linseed"
	PolicyName                                             = networkpolicy.CalicoComponentPolicyPrefix + "linseed-access"
	PortName                                               = "tigera-linseed"
	TargetPort                                             = 8444
	Port                                                   = 443
	ClusterRoleName                                        = "tigera-linseed"
	MultiTenantManagedClustersAccessClusterRoleBindingName = "tigera-linseed-managed-cluster-access"
	ManagedClustersWatchRoleBindingName                    = "tigera-linseed-managed-cluster-watch"
)

func Linseed(c *Config) render.Component {
	return &linseed{
		cfg:       c,
		namespace: c.Namespace,
	}
}

type linseed struct {
	calicoImage string
	csrImage    string
	cfg         *Config

	// Namespace in which to provision namespaced resources.
	namespace string
}

// Config contains all the information needed to render the Linseed component.
type Config struct {
	// CustomResources provided by the user.
	Installation *operatorv1.InstallationSpec

	// Pull secrets provided by the user.
	PullSecrets []*corev1.Secret

	// Keypair to use for asserting Linseed's identity.
	KeyPair certificatemanagement.KeyPairInterface

	// Keypair to use for signing tokens.
	TokenKeyPair certificatemanagement.KeyPairInterface

	// Trusted bundle to use when validating client certificates.
	TrustedBundle certificatemanagement.TrustedBundleRO

	// ClusterDomain to use when building service URLs.
	ClusterDomain string

	// Whether this is a management cluster
	ManagementCluster bool

	// Elastic cluster configuration
	ESClusterConfig *relasticsearch.ClusterConfig

	// Indicates whether DPI is installed in the cluster or not
	HasDPIResource bool

	// Namespace to install into.
	Namespace string

	// Namespaces to which we must bind the Linseed cluster role.
	BindNamespaces []string

	// Tenant configuration, if running for a particular tenant.
	Tenant          *operatorv1.Tenant
	ExternalElastic bool

	// Secret containing client certificate and key for connecting to the Elastic cluster. If configured,
	// mTLS is used between Linseed and the external Elastic cluster.
	ElasticClientSecret *corev1.Secret

	// Secret containing the user linseed connects to Elasticsearch
	// In a zero tenant setup, es-kubecontrollers create this secret
	// In a multi-tenant setup, users controllers create this secret
	ElasticClientCredentialsSecret *corev1.Secret

	ElasticHost string
	ElasticPort string

	LogStorage *operatorv1.LogStorage

	// Cloud indicates Linseed is being rendered for a Calico Cloud install. When false (regular
	// Calico/Calico Enterprise) all cloud decorations are inert.
	Cloud bool
}

func (l *linseed) ResolveImages(is *operatorv1.ImageSet) error {
	reg := l.cfg.Installation.Registry
	path := l.cfg.Installation.ImagePath
	prefix := l.cfg.Installation.ImagePrefix
	var err error
	errMsgs := []string{}

	// Calculate the image(s) to use for Linseed, given user registry configuration.
	l.calicoImage, err = components.GetReference(components.CombinedCalicoImage(l.cfg.Installation), reg, path, prefix, is)
	if err != nil {
		errMsgs = append(errMsgs, err.Error())
	}

	if l.cfg.Installation.CertificateManagement != nil {
		l.csrImage, err = certificatemanagement.ResolveCSRInitImage(l.cfg.Installation, is)
		if err != nil {
			errMsgs = append(errMsgs, err.Error())
		}
	}
	if len(errMsgs) != 0 {
		return fmt.Errorf("%s", strings.Join(errMsgs, ","))
	}
	return nil
}

func (l *linseed) Objects() (toCreate, toDelete []client.Object) {
	toCreate = append(toCreate, l.linseedCalicoSystemPolicy())
	// allow-tigera Tier was renamed to calico-system
	toDelete = append(toDelete, networkpolicy.DeprecatedAllowTigeraNetworkPolicyObject("linseed-access", l.namespace))
	toCreate = append(toCreate, l.linseedService())
	toCreate = append(toCreate, l.linseedClusterRole())
	toCreate = append(toCreate, l.linseedClusterRoleBinding(l.cfg.BindNamespaces))
	toCreate = append(toCreate, l.linseedManagedClustersWatchRoleBindings())
	if l.cfg.Tenant != nil {
		toCreate = append(toCreate, l.multiTenantManagedClustersAccess()...)
	}
	toCreate = append(toCreate, l.linseedServiceAccount())
	toCreate = append(toCreate, l.linseedDeployment())
	if l.cfg.ElasticClientSecret != nil {
		// If using External ES, we need to copy the client certificates into Linseed's naespace to be mounted.
		toCreate = append(toCreate, secret.ToRuntimeObjects(secret.CopyToNamespace(l.cfg.Namespace, l.cfg.ElasticClientSecret)...)...)
	}

	if l.cfg.Cloud {
		// Add in Calico Cloud resources.
		ccToCreate, ccToDelete := l.getCloudObjects()
		toCreate = append(toCreate, ccToCreate...)
		toDelete = append(toDelete, ccToDelete...)
	}

	return toCreate, toDelete
}

func (l *linseed) Ready() bool {
	return true
}

func (l *linseed) SupportedOSType() rmeta.OSType {
	return rmeta.OSTypeLinux
}

// All linseeds in the cluster must be able to do this.
func (l *linseed) linseedClusterRole() *rbacv1.ClusterRole {
	rules := []rbacv1.PolicyRule{
		{
			// Linseed uses subject access review to perform authorization of clients.
			APIGroups:     []string{"authorization.k8s.io"},
			Resources:     []string{"subjectaccessreviews"},
			ResourceNames: []string{},
			Verbs:         []string{"create"},
		},
		{
			// Used to validate tokens from standalone and mangement cluster clients.
			APIGroups: []string{"authentication.k8s.io"},
			Resources: []string{"tokenreviews"},
			Verbs:     []string{"create"},
		},
		// These permissions are necessary to allow the management cluster to monitor secrets that we want to propagate
		// through to the managed cluster for identity verification such as the Voltron Linseed public certificate
		{
			APIGroups: []string{""},
			Resources: []string{"secrets"},
			Verbs:     []string{"get", "list", "watch"},
		},
	}

	if l.cfg.Tenant.MultiTenant() {
		// These rules are used by Linseed in a management cluster serving multiple tenants in order to appear to managed
		// clusters as the expected serviceaccount. They're only needed when there are multiple tenants sharing the same
		// management cluster.
		rules = append(rules, []rbacv1.PolicyRule{
			{
				APIGroups:     []string{""},
				Resources:     []string{"serviceaccounts"},
				Verbs:         []string{"impersonate"},
				ResourceNames: []string{render.LinseedServiceName},
			},
			{
				APIGroups: []string{""},
				Resources: []string{"groups"},
				Verbs:     []string{"impersonate"},
				ResourceNames: []string{
					serviceaccount.AllServiceAccountsGroup,
					"system:authenticated",
					fmt.Sprintf("%s%s", serviceaccount.ServiceAccountGroupPrefix, render.ElasticsearchNamespace),
				},
			},
		}...)
	}

	if l.cfg.Installation.KubernetesProvider.IsOpenShift() {
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
			Name: ClusterRoleName,
		},
		Rules: rules,
	}
}

func (l *linseed) linseedClusterRoleBinding(namespaces []string) client.Object {
	return rcomponents.ClusterRoleBinding(ClusterRoleName, ClusterRoleName, ServiceAccountName, namespaces)
}

func (l *linseed) linseedManagedClustersWatchRoleBindings() client.Object {
	if l.cfg.Tenant.MultiTenant() {
		return rcomponents.RoleBinding(ManagedClustersWatchRoleBindingName, render.ManagedClustersWatchClusterRoleName, ServiceAccountName, l.cfg.Namespace)
	}

	return rcomponents.ClusterRoleBinding(ManagedClustersWatchRoleBindingName, render.ManagedClustersWatchClusterRoleName, ServiceAccountName, []string{l.cfg.Namespace})
}

func (l *linseed) multiTenantManagedClustersAccess() []client.Object {
	var objects []client.Object

	// In a single tenant setup we want to create a role that binds using service account
	// tigera-linseed from tigera-elasticsearch namespace. In a multi-tenant setup Linseed from the tenant's
	// namespace impersonates service tigera-linseed from tigera-elasticsearch namespace
	objects = append(objects, &rbacv1.RoleBinding{
		TypeMeta:   metav1.TypeMeta{Kind: "RoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{Name: MultiTenantManagedClustersAccessClusterRoleBindingName, Namespace: l.cfg.Namespace},
		RoleRef: rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "ClusterRole",
			Name:     render.MultiTenantManagedClustersAccessClusterRoleName,
		},
		Subjects: []rbacv1.Subject{
			// requests for Linseed to managed clusters are done using service account tigera-linseed
			// from tigera-elasticsearch namespace regardless of tenancy mode (single tenant or multi-tenant)
			{
				Kind:      "ServiceAccount",
				Name:      ServiceAccountName,
				Namespace: render.ElasticsearchNamespace,
			},
		},
	})

	return objects
}

func (l *linseed) linseedDeployment() *appsv1.Deployment {
	envVars := []corev1.EnvVar{
		{Name: "LINSEED_LOG_LEVEL", Value: "INFO"},

		// Configure Linseed server certificate.
		{Name: "LINSEED_HTTPS_CERT", Value: l.cfg.KeyPair.VolumeMountCertificateFilePath()},
		{Name: "LINSEED_HTTPS_KEY", Value: l.cfg.KeyPair.VolumeMountKeyFilePath()},

		// Configure the CA certificate used for verifying client certs.
		{Name: "LINSEED_CA_CERT", Value: l.cfg.TrustedBundle.MountPath()},

		// Configure default shards and replicas for indices
		{Name: "ELASTIC_REPLICAS", Value: strconv.Itoa(l.cfg.ESClusterConfig.Replicas())},
		{Name: "ELASTIC_SHARDS", Value: strconv.Itoa(l.cfg.ESClusterConfig.Shards())},

		// Configure shards and replicas for special indices
		{Name: "ELASTIC_FLOWS_INDEX_REPLICAS", Value: strconv.Itoa(l.cfg.ESClusterConfig.Replicas())},
		{Name: "ELASTIC_DNS_INDEX_REPLICAS", Value: strconv.Itoa(l.cfg.ESClusterConfig.Replicas())},
		{Name: "ELASTIC_AUDIT_INDEX_REPLICAS", Value: strconv.Itoa(l.cfg.ESClusterConfig.Replicas())},
		{Name: "ELASTIC_BGP_INDEX_REPLICAS", Value: strconv.Itoa(l.cfg.ESClusterConfig.Replicas())},
		{Name: "ELASTIC_WAF_INDEX_REPLICAS", Value: strconv.Itoa(l.cfg.ESClusterConfig.Replicas())},
		{Name: "ELASTIC_L7_INDEX_REPLICAS", Value: strconv.Itoa(l.cfg.ESClusterConfig.Replicas())},
		{Name: "ELASTIC_RUNTIME_INDEX_REPLICAS", Value: strconv.Itoa(l.cfg.ESClusterConfig.Replicas())},

		{Name: "ELASTIC_FLOWS_INDEX_SHARDS", Value: strconv.Itoa(l.cfg.ESClusterConfig.FlowShards())},
		{Name: "ELASTIC_DNS_INDEX_SHARDS", Value: strconv.Itoa(l.cfg.ESClusterConfig.Shards())},
		{Name: "ELASTIC_AUDIT_INDEX_SHARDS", Value: strconv.Itoa(l.cfg.ESClusterConfig.Shards())},
		{Name: "ELASTIC_BGP_INDEX_SHARDS", Value: strconv.Itoa(l.cfg.ESClusterConfig.Shards())},
		{Name: "ELASTIC_WAF_INDEX_SHARDS", Value: strconv.Itoa(l.cfg.ESClusterConfig.Shards())},
		{Name: "ELASTIC_L7_INDEX_SHARDS", Value: strconv.Itoa(l.cfg.ESClusterConfig.Shards())},
		{Name: "ELASTIC_RUNTIME_INDEX_SHARDS", Value: strconv.Itoa(l.cfg.ESClusterConfig.Shards())},
		{Name: "ELASTIC_POLICY_ACTIVITY_INDEX_SHARDS", Value: strconv.Itoa(l.cfg.ESClusterConfig.Shards())},

		{Name: "ELASTIC_SCHEME", Value: "https"},
		{Name: "ELASTIC_HOST", Value: l.cfg.ElasticHost},
		{Name: "ELASTIC_PORT", Value: l.cfg.ElasticPort},
		{
			Name:      "ELASTIC_USERNAME",
			ValueFrom: secret.GetEnvVarSource(render.ElasticsearchLinseedUserSecret, "username", false),
		},
		{
			Name:      "ELASTIC_PASSWORD",
			ValueFrom: secret.GetEnvVarSource(render.ElasticsearchLinseedUserSecret, "password", false),
		},
		{Name: "ELASTIC_CA", Value: l.cfg.TrustedBundle.MountPath()},
	}

	volumes := []corev1.Volume{
		l.cfg.KeyPair.Volume(),
		l.cfg.TrustedBundle.Volume(),
	}

	volumeMounts := append(
		l.cfg.TrustedBundle.VolumeMounts(l.SupportedOSType()),
		l.cfg.KeyPair.VolumeMount(l.SupportedOSType()),
	)

	if l.cfg.ElasticClientSecret != nil {
		// Add a volume for the required client certificate and key.
		volumes = append(volumes, corev1.Volume{
			Name: logstorage.ExternalCertsVolumeName,
			VolumeSource: corev1.VolumeSource{
				Secret: &corev1.SecretVolumeSource{
					SecretName: logstorage.ExternalCertsSecret,
				},
			},
		})
		volumeMounts = append(volumeMounts, corev1.VolumeMount{
			Name:      logstorage.ExternalCertsVolumeName,
			MountPath: "/certs/elasticsearch/mtls",
			ReadOnly:  true,
		})

		// Configure Linseed to use the mounted client certificate and key.
		envVars = append(envVars, corev1.EnvVar{Name: "ELASTIC_MTLS_ENABLED", Value: "true"})
		envVars = append(envVars, corev1.EnvVar{Name: "ELASTIC_CLIENT_KEY", Value: "/certs/elasticsearch/mtls/client.key"})
		envVars = append(envVars, corev1.EnvVar{Name: "ELASTIC_CLIENT_CERT", Value: "/certs/elasticsearch/mtls/client.crt"})
	}

	if l.cfg.ManagementCluster {
		envVars = append(envVars,
			corev1.EnvVar{Name: "MANAGEMENT_OPERATOR_NS", Value: common.OperatorNamespace()},
		)
	}

	replicas := l.cfg.Installation.ControlPlaneReplicas
	if l.cfg.Tenant != nil {
		// Always set the expected tenant ID when a tenant is configured, regardless of
		// whether Elasticsearch is internal or external. This ensures tenant isolation
		// via the x-tenant-id header for all indices including shared single indices.
		envVars = append(envVars, corev1.EnvVar{Name: "LINSEED_EXPECTED_TENANT_ID", Value: l.cfg.Tenant.Spec.ID})

		if !l.cfg.ExternalElastic {
			// For internal Elasticsearch, existing multi-index indices were created without
			// tenant ID in the name. Disable tenant suffix in index names to preserve
			// backward compatibility while still enforcing tenant isolation at the query level.
			envVars = append(envVars, corev1.EnvVar{Name: "ELASTIC_MULTI_INDEX_TENANT_SUFFIX_ENABLED", Value: "false"})
		} else if l.cfg.Cloud {
			// For Calico Cloud's external Elasticsearch, single-index-format indices are created
			// out of band, so Linseed should not create them itself.
			envVars = append(envVars, corev1.EnvVar{Name: "ELASTIC_INDICES_CREATION_DISABLED", Value: "true"})
		}

		if l.cfg.Tenant.MultiTenant() {
			// For clusters shared between multiple tenants, we need to configure Linseed with the correct namespace information for its tenant.
			envVars = append(envVars, corev1.EnvVar{Name: "LINSEED_MULTI_CLUSTER_FORWARDING_ENDPOINT", Value: render.ManagerService(l.cfg.Tenant)})
			envVars = append(envVars, corev1.EnvVar{Name: "LINSEED_TENANT_NAMESPACE", Value: l.cfg.Tenant.Namespace})

			if l.cfg.Tenant.Spec.ManagedClusterVariant != nil {
				envVars = append(envVars, corev1.EnvVar{Name: "LINSEED_PRODUCT_VARIANT", Value: string(*l.cfg.Tenant.Spec.ManagedClusterVariant)})
			}

			// We also use shared indices for multi-tenant clusters.
			envVars = append(envVars, corev1.EnvVar{Name: "BACKEND", Value: "elastic-single-index"})
			for _, index := range l.cfg.Tenant.Spec.Indices {
				envVars = append(envVars, index.EnvVar())
			}

			if l.cfg.Tenant.Spec.ControlPlaneReplicas != nil {
				replicas = l.cfg.Tenant.Spec.ControlPlaneReplicas
			}
		}
	}
	sc := securitycontext.NewNonRootContext()
	var initContainers []corev1.Container
	if l.cfg.KeyPair.UseCertificateManagement() {
		initContainers = append(initContainers, l.cfg.KeyPair.InitContainer(l.namespace, sc))
	}

	annotations := l.cfg.TrustedBundle.HashAnnotations()
	annotations[l.cfg.KeyPair.HashAnnotationKey()] = l.cfg.KeyPair.HashAnnotationValue()
	if l.cfg.ElasticClientSecret != nil {
		annotations["hash.operator.tigera.io/elastic-client-secret"] = rmeta.SecretsAnnotationHash(l.cfg.ElasticClientSecret)
	}
	if l.cfg.ElasticClientCredentialsSecret != nil {
		annotations[fmt.Sprintf("hash.operator.tigera.io/%s", render.ElasticsearchLinseedUserSecret)] = rmeta.SecretsAnnotationHash(l.cfg.ElasticClientCredentialsSecret)
	}

	if l.cfg.TokenKeyPair != nil && !l.cfg.Tenant.ManagedClusterIsCalico() {
		// If a token key pair is provided, configure Linseed to use it.
		// We don't need to do this for OSS Calico managed clusters - they don't have permissions for the
		// token controller to create tokens.
		envVars = append(envVars,
			corev1.EnvVar{Name: "TOKEN_CONTROLLER_ENABLED", Value: "true"},
			corev1.EnvVar{Name: "LINSEED_TOKEN_KEY", Value: l.cfg.TokenKeyPair.VolumeMountKeyFilePath()},
		)
		volumes = append(volumes, l.cfg.TokenKeyPair.Volume())
		volumeMounts = append(volumeMounts, l.cfg.TokenKeyPair.VolumeMount(l.SupportedOSType()))
		if l.cfg.TokenKeyPair.UseCertificateManagement() {
			initContainers = append(initContainers, l.cfg.TokenKeyPair.InitContainer(l.namespace, sc))
		}
		annotations[l.cfg.TokenKeyPair.HashAnnotationKey()] = l.cfg.TokenKeyPair.HashAnnotationValue()
	}
	tolerations := l.cfg.Installation.ControlPlaneTolerations
	if l.cfg.Installation.KubernetesProvider.IsGKE() {
		tolerations = append(tolerations, rmeta.TolerateGKEARM64NoSchedule)
	}
	podTemplate := &corev1.PodTemplateSpec{
		ObjectMeta: metav1.ObjectMeta{
			Name:        DeploymentName,
			Namespace:   l.namespace,
			Annotations: annotations,
		},
		Spec: corev1.PodSpec{
			Tolerations:        tolerations,
			NodeSelector:       l.cfg.Installation.ControlPlaneNodeSelector,
			ServiceAccountName: ServiceAccountName,
			ImagePullSecrets:   secret.GetReferenceList(l.cfg.PullSecrets),
			Volumes:            volumes,
			InitContainers:     initContainers,
			Containers: []corev1.Container{
				{
					Name:            DeploymentName,
					Image:           l.calicoImage,
					Command:         []string{components.CalicoBinaryPath, "component", "linseed"},
					Env:             envVars,
					VolumeMounts:    volumeMounts,
					SecurityContext: sc,
					ReadinessProbe: &corev1.Probe{
						ProbeHandler: corev1.ProbeHandler{
							Exec: &corev1.ExecAction{
								Command: []string{components.CalicoBinaryPath, "component", "linseed", "ready"},
							},
						},
						InitialDelaySeconds: 10,
					},
					LivenessProbe: &corev1.Probe{
						ProbeHandler: corev1.ProbeHandler{
							Exec: &corev1.ExecAction{
								Command: []string{components.CalicoBinaryPath, "component", "linseed", "live"},
							},
						},
						InitialDelaySeconds: 10,
					},
				},
			},
		},
	}

	if replicas != nil && *replicas > 1 {
		podTemplate.Spec.Affinity = podaffinity.NewPodAntiAffinity(DeploymentName, []string{l.namespace})
	}

	d := appsv1.Deployment{
		TypeMeta: metav1.TypeMeta{Kind: "Deployment", APIVersion: "apps/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      DeploymentName,
			Namespace: l.namespace,
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
			Replicas: replicas,
		},
	}

	if l.cfg.Cloud {
		l.modifyDeploymentForCloud(&d)
	}

	if l.cfg.Tenant.MultiTenant() {
		if overrides := l.cfg.Tenant.Spec.LinseedDeployment; overrides != nil {
			rcomponents.ApplyDeploymentOverrides(&d, overrides)
		}
	} else if l.cfg.LogStorage != nil {
		if overrides := l.cfg.LogStorage.Spec.LinseedDeployment; overrides != nil {
			rcomponents.ApplyDeploymentOverrides(&d, overrides)
		}
	}

	return &d
}

func (l *linseed) linseedServiceAccount() *corev1.ServiceAccount {
	return &corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Name:      ServiceAccountName,
			Namespace: l.namespace,
		},
	}
}

func (l *linseed) linseedService() *corev1.Service {
	return &corev1.Service{
		TypeMeta: metav1.TypeMeta{Kind: "Service", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      render.LinseedServiceName,
			Namespace: l.namespace,
		},
		Spec: corev1.ServiceSpec{
			Selector: map[string]string{"k8s-app": DeploymentName},
			Type:     corev1.ServiceTypeClusterIP,
			Ports: []corev1.ServicePort{
				{
					Name:       PortName,
					Port:       Port,
					TargetPort: intstr.FromInt(TargetPort),
					Protocol:   corev1.ProtocolTCP,
				},
			},
		},
	}
}

// Allow access to Linseed from components that need it.
func (l *linseed) linseedCalicoSystemPolicy() *v3.NetworkPolicy {
	// Egress needs to be allowed to:
	// - Kubernetes API
	// - Cluster DNS
	// - Elasticsearch
	egressRules := []v3.Rule{}
	egressRules = networkpolicy.AppendDNSEgressRules(egressRules, l.cfg.Installation.KubernetesProvider.IsOpenShift())
	egressRules = append(egressRules, []v3.Rule{
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
	}...)

	networkpolicyHelper := networkpolicy.Helper(l.cfg.Tenant.MultiTenant(), l.cfg.Namespace)

	if l.cfg.ManagementCluster {
		// For management clusters, linseed talks to Voltron to create tokens.
		egressRules = append(egressRules, v3.Rule{
			Action:      v3.Allow,
			Protocol:    &networkpolicy.TCPProtocol,
			Destination: networkpolicyHelper.ManagerEntityRule(),
		})
	}

	// Ingress needs to be allowed from all clients.
	linseedIngressDestinationEntityRule := v3.EntityRule{
		Ports: networkpolicy.Ports(TargetPort),
	}

	ingressRules := []v3.Rule{
		{
			Action:      v3.Allow,
			Protocol:    &networkpolicy.TCPProtocol,
			Source:      render.FluentBitSourceEntityRule,
			Destination: linseedIngressDestinationEntityRule,
		},
		{
			Action:      v3.Allow,
			Protocol:    &networkpolicy.TCPProtocol,
			Source:      render.EKSLogForwarderEntityRule,
			Destination: linseedIngressDestinationEntityRule,
		},
		{
			Action:      v3.Allow,
			Protocol:    &networkpolicy.TCPProtocol,
			Source:      networkpolicyHelper.ManagerSourceEntityRule(),
			Destination: linseedIngressDestinationEntityRule,
		},
		{
			Action:      v3.Allow,
			Protocol:    &networkpolicy.TCPProtocol,
			Source:      networkpolicyHelper.ComplianceBenchmarkerSourceEntityRule(),
			Destination: linseedIngressDestinationEntityRule,
		},
		{
			Action:      v3.Allow,
			Protocol:    &networkpolicy.TCPProtocol,
			Source:      networkpolicyHelper.ComplianceControllerSourceEntityRule(),
			Destination: linseedIngressDestinationEntityRule,
		},
		{
			Action:      v3.Allow,
			Protocol:    &networkpolicy.TCPProtocol,
			Source:      networkpolicyHelper.ComplianceServerSourceEntityRule(),
			Destination: linseedIngressDestinationEntityRule,
		},
		{
			Action:      v3.Allow,
			Protocol:    &networkpolicy.TCPProtocol,
			Source:      networkpolicyHelper.ComplianceSnapshotterSourceEntityRule(),
			Destination: linseedIngressDestinationEntityRule,
		},
		{
			Action:      v3.Allow,
			Protocol:    &networkpolicy.TCPProtocol,
			Source:      networkpolicyHelper.ComplianceReporterSourceEntityRule(),
			Destination: linseedIngressDestinationEntityRule,
		},
		{
			Action:      v3.Allow,
			Protocol:    &networkpolicy.TCPProtocol,
			Source:      networkpolicyHelper.IntrusionDetectionSourceEntityRule(),
			Destination: linseedIngressDestinationEntityRule,
		},
		{
			Action:      v3.Allow,
			Protocol:    &networkpolicy.TCPProtocol,
			Source:      render.ECKOperatorSourceEntityRule,
			Destination: linseedIngressDestinationEntityRule,
		},
		{
			Action:      v3.Allow,
			Protocol:    &networkpolicy.TCPProtocol,
			Source:      esmetrics.ESMetricsSourceEntityRule,
			Destination: linseedIngressDestinationEntityRule,
		},
		{
			Action:      v3.Allow,
			Protocol:    &networkpolicy.TCPProtocol,
			Source:      networkpolicyHelper.PolicyRecommendationSourceEntityRule(),
			Destination: linseedIngressDestinationEntityRule,
		},
		{
			// Allow queryserver to read policy activity data.
			Action:      v3.Allow,
			Protocol:    &networkpolicy.TCPProtocol,
			Source:      networkpolicyHelper.APIServerSourceEntityRule(l.cfg.Installation.Variant),
			Destination: linseedIngressDestinationEntityRule,
		},
	}

	if l.cfg.HasDPIResource {
		// DPI needs to access Linseed, however, since the is on the host network
		// it's hard to create specific network policies for it.
		// Allow all sources, as node CIDRs are not known.
		ingressRules = append(ingressRules, v3.Rule{
			Action:      v3.Allow,
			Protocol:    &networkpolicy.TCPProtocol,
			Destination: linseedIngressDestinationEntityRule,
		})
	}

	return &v3.NetworkPolicy{
		TypeMeta: metav1.TypeMeta{Kind: "NetworkPolicy", APIVersion: "projectcalico.org/v3"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      PolicyName,
			Namespace: l.namespace,
		},
		Spec: v3.NetworkPolicySpec{
			Order:    &networkpolicy.HighPrecedenceOrder,
			Tier:     networkpolicy.CalicoTierName,
			Selector: networkpolicy.KubernetesAppSelector(DeploymentName),
			Types:    []v3.PolicyType{v3.PolicyTypeIngress, v3.PolicyTypeEgress},
			Ingress:  ingressRules,
			Egress:   egressRules,
		},
	}
}

// LinseedNamespace determine the namespace in which Linseed is running.
// For management and standalone clusters, this is always the tigera-elasticsearch
// namespace. For multi-tenant management clusters, this is the tenant namespace
func LinseedNamespace(tenant *operatorv1.Tenant) string {
	if tenant.MultiTenant() {
		return tenant.Namespace
	}
	return "tigera-elasticsearch"
}
