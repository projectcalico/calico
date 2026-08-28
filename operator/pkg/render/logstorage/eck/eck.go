// Copyright (c) 2024-2026 Tigera, Inc. All rights reserved.

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

package eck

import (
	"fmt"
	"strings"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/components"
	"github.com/tigera/operator/pkg/render"
	rcomponents "github.com/tigera/operator/pkg/render/common/components"
	rmeta "github.com/tigera/operator/pkg/render/common/meta"
	"github.com/tigera/operator/pkg/render/common/networkpolicy"
	"github.com/tigera/operator/pkg/render/common/secret"
	"github.com/tigera/operator/pkg/render/common/securitycontext"
	"github.com/tigera/operator/pkg/render/common/securitycontextconstraints"
)

const (
	OperatorName         = "elastic-operator"
	OperatorNamespace    = "tigera-eck-operator"
	LicenseConfigMapName = "elastic-licensing"
	OperatorPolicyName   = networkpolicy.CalicoComponentPolicyPrefix + "elastic-operator-access"
	EnterpriseTrial      = "eck-trial-license"
)

// ECK renders the components necessary for eck operator
func ECK(cfg *Configuration) render.Component {
	return &eck{
		cfg: cfg,
	}
}

// Configuration contains all the config information needed to render the component.
type Configuration struct {
	LogStorage         *operatorv1.LogStorage
	Installation       *operatorv1.InstallationSpec
	ManagementCluster  *operatorv1.ManagementCluster
	PullSecrets        []*corev1.Secret
	Provider           operatorv1.Provider
	ElasticLicenseType render.ElasticsearchLicenseType
	ApplyTrial         bool
}

type eck struct {
	cfg             *Configuration
	esOperatorImage string
}

func (e *eck) ResolveImages(is *operatorv1.ImageSet) error {
	reg := e.cfg.Installation.Registry
	path := e.cfg.Installation.ImagePath
	prefix := e.cfg.Installation.ImagePrefix
	errMsgs := make([]string, 0)

	var err error
	e.esOperatorImage, err = components.GetReference(components.ComponentElasticsearchOperator, reg, path, prefix, is)
	if err != nil {
		errMsgs = append(errMsgs, err.Error())
	}

	if len(errMsgs) != 0 {
		return fmt.Errorf("%s", strings.Join(errMsgs, ","))
	}
	return nil
}

func (e *eck) SupportedOSType() rmeta.OSType {
	return rmeta.OSTypeLinux
}

func (e *eck) Objects() ([]client.Object, []client.Object) {
	var toCreate, toDelete []client.Object

	toCreate = append(toCreate,
		render.CreateNamespace(OperatorNamespace, e.cfg.Installation.KubernetesProvider, render.PSSRestricted, e.cfg.Installation.Azure),
		e.operatorCalicoSystemPolicy(),
	)
	// allow-tigera Tier was renamed to calico-system
	toDelete = append(toDelete, networkpolicy.DeprecatedAllowTigeraNetworkPolicyObject("elastic-operator-access", OperatorNamespace))

	toCreate = append(toCreate, render.CreateOperatorSecretsRoleBinding(OperatorNamespace))

	toCreate = append(toCreate, secret.ToRuntimeObjects(secret.CopyToNamespace(OperatorNamespace, e.cfg.PullSecrets...)...)...)

	toCreate = append(toCreate,
		e.operatorClusterRole(),
		e.operatorClusterRoleBinding(),
		e.operatorServiceAccount(),
	)
	// This is needed for the operator to be able to set privileged mode for pods.
	// https://docs.docker.com/ee/ucp/authorization/#secure-kubernetes-defaults
	if e.cfg.Provider.IsDockerEE() {
		toCreate = append(toCreate, e.operatorClusterAdminClusterRoleBinding())
	}

	if e.cfg.ApplyTrial {
		toCreate = append(toCreate, e.elasticEnterpriseTrial())
	}
	toCreate = append(toCreate, e.operatorStatefulSet())

	return toCreate, toDelete

}

func (e *eck) Ready() bool {
	return true
}

func (e *eck) operatorClusterRole() *rbacv1.ClusterRole {
	rules := []rbacv1.PolicyRule{
		{
			APIGroups: []string{"authorization.k8s.io"},
			Resources: []string{"subjectaccessreviews"},
			Verbs:     []string{"create"},
		},
		{
			APIGroups: []string{"coordination.k8s.io"},
			Resources: []string{"leases"},
			Verbs:     []string{"create"},
		},
		{
			APIGroups:     []string{"coordination.k8s.io"},
			Resources:     []string{"leases"},
			ResourceNames: []string{"elastic-operator-leader"},
			Verbs:         []string{"get", "watch", "update"},
		},
		{
			APIGroups: []string{""},
			Resources: []string{"endpoints"},
			Verbs:     []string{"get", "list", "watch"},
		},
		{
			APIGroups: []string{""},
			Resources: []string{"pods", "events", "persistentvolumeclaims", "secrets", "services", "configmaps"},
			Verbs:     []string{"get", "list", "watch", "create", "update", "patch", "delete"},
		},
		{
			APIGroups: []string{"apps"},
			Resources: []string{"deployments", "statefulsets", "daemonsets"},
			Verbs:     []string{"get", "list", "watch", "create", "update", "patch", "delete"},
		},
		{
			APIGroups: []string{"policy"},
			Resources: []string{"poddisruptionbudgets"},
			Verbs:     []string{"get", "list", "watch", "create", "update", "patch", "delete"},
		},
		{
			APIGroups: []string{"elasticsearch.k8s.elastic.co"},
			Resources: []string{"elasticsearches", "elasticsearches/status", "elasticsearches/finalizers"},
			Verbs:     []string{"get", "list", "watch", "create", "update", "patch"},
		},
		{
			APIGroups: []string{"autoscaling.k8s.elastic.co"},
			Resources: []string{"elasticsearchautoscalers", "elasticsearchautoscalers/status", "elasticsearchautoscalers/finalizers"},
			Verbs:     []string{"get", "list", "watch", "create", "update", "patch"},
		},
		{
			APIGroups: []string{"kibana.k8s.elastic.co"},
			Resources: []string{"kibanas", "kibanas/status", "kibanas/finalizers"},
			Verbs:     []string{"get", "list", "watch", "create", "update", "patch"},
		},
		{
			APIGroups: []string{"apm.k8s.elastic.co"},
			Resources: []string{"apmservers", "apmservers/status", "apmservers/finalizers"},
			Verbs:     []string{"get", "list", "watch", "create", "update", "patch"},
		},
		{
			APIGroups: []string{"enterprisesearch.k8s.elastic.co"},
			Resources: []string{"enterprisesearches", "enterprisesearches/status", "enterprisesearches/finalizers"},
			Verbs:     []string{"get", "list", "watch", "create", "update", "patch"},
		},
		{
			APIGroups: []string{"beat.k8s.elastic.co"},
			Resources: []string{"beats", "beats/status", "beats/finalizers"},
			Verbs:     []string{"get", "list", "watch", "create", "update", "patch"},
		},
		{
			APIGroups: []string{"agent.k8s.elastic.co"},
			Resources: []string{"agents", "agents/status", "agents/finalizers"},
			Verbs:     []string{"get", "list", "watch", "create", "update", "patch"},
		},
		{
			APIGroups: []string{"maps.k8s.elastic.co"},
			Resources: []string{"elasticmapsservers", "elasticmapsservers/status", "elasticmapsservers/finalizers"},
			Verbs:     []string{"get", "list", "watch", "create", "update", "patch"},
		},
		{
			APIGroups: []string{"stackconfigpolicy.k8s.elastic.co"},
			Resources: []string{"stackconfigpolicies", "stackconfigpolicies/status", "stackconfigpolicies/finalizers"},
			Verbs:     []string{"get", "list", "watch", "create", "update", "patch"},
		},
		{
			APIGroups: []string{"logstash.k8s.elastic.co"},
			Resources: []string{"logstashes", "logstashes/status", "logstashes/finalizers"},
			Verbs:     []string{"get", "list", "watch", "create", "update", "patch"},
		},
		{
			APIGroups: []string{"autoops.k8s.elastic.co"},
			Resources: []string{"autoopsagentpolicies", "autoopsagentpolicies/status", "autoopsagentpolicies/finalizers"},
			Verbs:     []string{"get", "list", "watch"},
		},
		{
			APIGroups: []string{"packageregistry.k8s.elastic.co"},
			Resources: []string{"packageregistries", "packageregistries/status", "packageregistries/finalizers"},
			Verbs:     []string{"get", "list", "watch"},
		},
		{
			APIGroups: []string{"storage.k8s.io"},
			Resources: []string{"storageclasses"},
			Verbs:     []string{"get", "list", "watch"},
		},
		{
			APIGroups: []string{"admissionregistration.k8s.io"},
			Resources: []string{"validatingwebhookconfigurations"},
			Verbs:     []string{"get", "list", "watch", "create", "update", "patch", "delete"},
		},
		{
			APIGroups: []string{""},
			Resources: []string{"nodes"},
			Verbs:     []string{"get", "list", "watch"},
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

	return &rbacv1.ClusterRole{
		TypeMeta: metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name: "elastic-operator",
		},
		Rules: rules,
	}
}

func (e *eck) operatorClusterRoleBinding() *rbacv1.ClusterRoleBinding {
	return &rbacv1.ClusterRoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name: OperatorName,
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "ClusterRole",
			Name:     OperatorName,
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      "ServiceAccount",
				Name:      "elastic-operator",
				Namespace: OperatorNamespace,
			},
		},
	}
}

func (e *eck) operatorClusterAdminClusterRoleBinding() *rbacv1.ClusterRoleBinding {
	return &rbacv1.ClusterRoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name: "elastic-operator-docker-enterprise",
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "ClusterRole",
			Name:     "cluster-admin",
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      "ServiceAccount",
				Name:      "elastic-operator",
				Namespace: OperatorNamespace,
			},
		},
	}
}

func (e *eck) operatorServiceAccount() *corev1.ServiceAccount {
	return &corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Name:      OperatorName,
			Namespace: OperatorNamespace,
		},
	}
}

func (e *eck) operatorStatefulSet() *appsv1.StatefulSet {
	gracePeriod := int64(10)
	memoryLimit := resource.Quantity{}
	memoryRequest := resource.Quantity{}
	for _, c := range e.cfg.LogStorage.Spec.ComponentResources {
		if c.ComponentName == operatorv1.ComponentNameECKOperator {
			memoryLimit = c.ResourceRequirements.Limits[corev1.ResourceMemory]
			memoryRequest = c.ResourceRequirements.Requests[corev1.ResourceMemory]
		}
	}
	tolerations := e.cfg.Installation.ControlPlaneTolerations
	if e.cfg.Installation.KubernetesProvider.IsGKE() {
		tolerations = append(tolerations, rmeta.TolerateGKEARM64NoSchedule)
	}
	s := &appsv1.StatefulSet{
		TypeMeta: metav1.TypeMeta{Kind: "StatefulSet", APIVersion: "apps/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      OperatorName,
			Namespace: OperatorNamespace,
			Labels: map[string]string{
				"control-plane": "elastic-operator",
				"k8s-app":       "elastic-operator",
			},
		},
		Spec: appsv1.StatefulSetSpec{
			Selector: &metav1.LabelSelector{
				MatchLabels: map[string]string{
					"control-plane": "elastic-operator",
					"k8s-app":       "elastic-operator",
				},
			},
			ServiceName: OperatorName,
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: map[string]string{
						"control-plane": "elastic-operator",
						"k8s-app":       "elastic-operator",
					},
					Annotations: map[string]string{
						// Rename the fields "error" to "error.message" and "source" to "event.source"
						// This is to avoid a conflict with the ECS "error" and "source" documents.
						"co.elastic.logs/raw": "[{\"type\":\"container\",\"json.keys_under_root\":true,\"paths\":[\"/var/log/containers/*${data.kubernetes.container.id}.log\"],\"processors\":[{\"convert\":{\"mode\":\"rename\",\"ignore_missing\":true,\"fields\":[{\"from\":\"error\",\"to\":\"_error\"}]}},{\"convert\":{\"mode\":\"rename\",\"ignore_missing\":true,\"fields\":[{\"from\":\"_error\",\"to\":\"error.message\"}]}},{\"convert\":{\"mode\":\"rename\",\"ignore_missing\":true,\"fields\":[{\"from\":\"source\",\"to\":\"_source\"}]}},{\"convert\":{\"mode\":\"rename\",\"ignore_missing\":true,\"fields\":[{\"from\":\"_source\",\"to\":\"event.source\"}]}}]}]",
					},
				},
				Spec: corev1.PodSpec{
					DNSPolicy:          corev1.DNSClusterFirst,
					ServiceAccountName: "elastic-operator",
					ImagePullSecrets:   secret.GetReferenceList(e.cfg.PullSecrets),
					HostNetwork:        false,
					NodeSelector:       e.cfg.Installation.ControlPlaneNodeSelector,
					Tolerations:        tolerations,
					Containers: []corev1.Container{{
						Image: e.esOperatorImage,
						Name:  "manager",
						// Verbosity level of logs. -2=Error, -1=Warn, 0=Info, 0 and above=Debug
						Args: []string{
							"manager",
							"--namespaces=tigera-elasticsearch,tigera-kibana",
							"--log-verbosity=0",
							"--metrics-port=0",
							"--container-registry=" + e.cfg.Installation.Registry,
							"--max-concurrent-reconciles=3",
							"--ca-cert-validity=8760h",
							"--ca-cert-rotate-before=720h",
							"--cert-rotate-before=720h",
							"--cert-validity=8760h",
							"--enable-webhook=false",
							"--manage-webhook-certs=false",
						},
						Env: []corev1.EnvVar{
							{
								Name: "OPERATOR_NAMESPACE",
								ValueFrom: &corev1.EnvVarSource{
									FieldRef: &corev1.ObjectFieldSelector{
										FieldPath: "metadata.namespace",
									},
								},
							},
							{Name: "OPERATOR_IMAGE", Value: e.esOperatorImage},
						},
						Resources: corev1.ResourceRequirements{
							Limits: corev1.ResourceList{
								"cpu":    resource.MustParse("1"),
								"memory": memoryLimit,
							},
							Requests: corev1.ResourceList{
								"cpu":    resource.MustParse("100m"),
								"memory": memoryRequest,
							},
						},
						SecurityContext: securitycontext.NewNonRootContext(),
					}},
					TerminationGracePeriodSeconds: &gracePeriod,
				},
			},
		},
	}
	if e.cfg.LogStorage != nil {
		if overrides := e.cfg.LogStorage.Spec.ECKOperatorStatefulSet; overrides != nil {
			rcomponents.ApplyStatefulSetOverrides(s, overrides)
		}
	}
	return s
}

// Applying this in the eck namespace will start a trial license for enterprise features.
func (e *eck) elasticEnterpriseTrial() *corev1.Secret {
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      EnterpriseTrial,
			Namespace: OperatorNamespace,
			Labels: map[string]string{
				"license.k8s.elastic.co/type": "enterprise-trial",
			},
			Annotations: map[string]string{
				"elastic.co/eula": "accepted",
			},
		},
	}
}

// Allow the elastic-operator to communicate with API server, DNS and elastic search.
func (e *eck) operatorCalicoSystemPolicy() *v3.NetworkPolicy {
	egressRules := []v3.Rule{}
	egressRules = networkpolicy.AppendDNSEgressRules(egressRules, e.cfg.Provider.IsOpenShift())
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

	return &v3.NetworkPolicy{
		TypeMeta: metav1.TypeMeta{Kind: "NetworkPolicy", APIVersion: "projectcalico.org/v3"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      OperatorPolicyName,
			Namespace: OperatorNamespace,
		},
		Spec: v3.NetworkPolicySpec{
			Order:    &networkpolicy.HighPrecedenceOrder,
			Tier:     networkpolicy.CalicoTierName,
			Selector: networkpolicy.KubernetesAppSelector(OperatorName),
			Types:    []v3.PolicyType{v3.PolicyTypeEgress},
			Egress:   egressRules,
		},
	}
}
