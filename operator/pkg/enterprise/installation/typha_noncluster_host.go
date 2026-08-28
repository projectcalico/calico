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

package installation

import (
	"context"
	"slices"

	"github.com/sirupsen/logrus"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"

	operatorv1 "github.com/projectcalico/calico/operator/api/v1"
	"github.com/projectcalico/calico/operator/pkg/common"
	"github.com/projectcalico/calico/operator/pkg/controller"
	"github.com/projectcalico/calico/operator/pkg/controller/k8sapi"
	"github.com/projectcalico/calico/operator/pkg/controller/typhaautoscaler"
	"github.com/projectcalico/calico/operator/pkg/controller/utils"
	eutils "github.com/projectcalico/calico/operator/pkg/enterprise/utils"
	"github.com/projectcalico/calico/operator/pkg/extensions"
	"github.com/projectcalico/calico/operator/pkg/render"
	rmeta "github.com/projectcalico/calico/operator/pkg/render/common/meta"
	"github.com/projectcalico/calico/operator/pkg/render/common/networkpolicy"
	"github.com/projectcalico/calico/operator/pkg/tls/certificatemanagement"
)

// nonClusterHostRenderData is the non-cluster-host state the typha modifiers read.
// The zero value means the feature is off.
type nonClusterHostRenderData struct {
	enabled bool

	// typhaSecret is the serving keypair for the pod-networked Typha that
	// non-cluster hosts connect to.
	typhaSecret certificatemanagement.KeyPairInterface

	// nodeCommonName and nodeURISAN identify the Felix clients on non-cluster hosts.
	nodeCommonName string
	nodeURISAN     string
}

// buildNonClusterHostData produces the non-cluster-host Typha state from the
// NonClusterHost resource. The keypair is returned separately for the controller to manage.
func buildNonClusterHostData(ctx context.Context, ci controller.Inputs) (nonClusterHostRenderData, certificatemanagement.KeyPairInterface, error) {
	if !ci.RenderInputs.Installation.Variant.IsEnterprise() {
		return nonClusterHostRenderData{}, nil, nil
	}

	nch, err := eutils.GetNonClusterHost(ctx, ci.Client)
	if err != nil {
		return nonClusterHostRenderData{}, nil, extensions.Degradedf(operatorv1.ResourceReadError, "Failed to query NonClusterHost resource: %w", err)
	}
	if nch == nil {
		return nonClusterHostRenderData{}, nil, nil
	}

	typhaSecret, err := ci.CertificateManager.GetOrCreateKeyPair(
		ci.Client,
		render.TyphaTLSSecretNameNonClusterHost,
		common.OperatorNamespace(),
		[]string{render.TyphaCommonName + render.TyphaNonClusterHostSuffix},
	)
	if err != nil {
		return nonClusterHostRenderData{}, nil, extensions.Degradedf(operatorv1.ResourceCreateError, "error creating the non-cluster-host typha TLS certificate: %w", err)
	}

	data := nonClusterHostRenderData{
		enabled:     true,
		typhaSecret: typhaSecret,
		// This is the default common name in CSR from non-cluster hosts.
		nodeCommonName: render.FelixCommonName + render.TyphaNonClusterHostSuffix,
	}

	// Attempt to retrieve the BYO node certificates for non-cluster hosts if they are present.
	secret, err := utils.GetSecret(ctx, ci.Client, render.NodeTLSSecretNameNonClusterHost, common.OperatorNamespace())
	if err != nil {
		logrus.WithError(err).Warn("failed to retrieve BYO non-cluster host node TLS secret. Using default common name instead.")
		return data, typhaSecret, nil
	}
	if secret != nil {
		cn, urisan, err := utils.ParseCommonNameAndURISAN(secret)
		if err != nil {
			logrus.WithError(err).Warn("failed to parse common name or URI SAN in BYO non-cluster host node TLS secret. Using default common name instead.")
		}

		data.nodeCommonName = cn
		data.nodeURISAN = urisan
	}
	return data, typhaSecret, nil
}

// ensureTyphaAutoscaler starts the non-cluster-host Typha autoscaler once, then
// re-triggers it whenever it reports degraded.
func (e *Extension) ensureTyphaAutoscaler(ci controller.Inputs) error {
	if e.typhaAutoscaler == nil {
		name := common.TyphaDeploymentName + render.TyphaNonClusterHostSuffix
		e.typhaAutoscaler = typhaautoscaler.New(ci.Client, name, typhaautoscaler.HostEndpointReplicaCounter, ci.Status)
		e.typhaAutoscaler.Start(ci.ShutdownContext)
		return nil
	}

	if e.typhaAutoscaler.IsDegraded() {
		if err := e.typhaAutoscaler.TriggerRun(); err != nil {
			return extensions.Degradedf(operatorv1.ResourceScalingError, "Failed to scale typha for noncluster hosts: %w", err)
		}
	}
	return nil
}

// addNonClusterHostTypha renders a second Typha Deployment and Service, copied from
// the in-cluster pair and moved onto the pod network.
func addNonClusterHostTypha(cfg *render.TyphaConfiguration, data nonClusterHostRenderData, objs []client.Object) []client.Object {
	if dep, ok := extensions.FindObject[*appsv1.Deployment](objs, common.TyphaDeploymentName); ok {
		objs = append(objs, nonClusterHostDeployment(cfg, data, dep))
	}
	if svc, ok := extensions.FindObject[*corev1.Service](objs, render.TyphaServiceName); ok {
		objs = append(objs, nonClusterHostService(svc))
	}
	return objs
}

func nonClusterHostDeployment(cfg *render.TyphaConfiguration, data nonClusterHostRenderData, base *appsv1.Deployment) *appsv1.Deployment {
	dep := base.DeepCopy()
	dep.Name += render.TyphaNonClusterHostSuffix

	// Replace Typha secret annotation for NonClusterHost deployment.
	delete(dep.Spec.Template.Annotations, cfg.TLS.TyphaSecret.HashAnnotationKey())
	dep.Spec.Template.Annotations[data.typhaSecret.HashAnnotationKey()] = data.typhaSecret.HashAnnotationValue()

	// Remove the affinity and use pod network
	spec := &dep.Spec.Template.Spec
	spec.Affinity = nil
	spec.HostNetwork = false

	spec.Volumes = []corev1.Volume{cfg.TLS.TrustedBundle.Volume(), data.typhaSecret.Volume()}
	if spec.InitContainers != nil && data.typhaSecret.UseCertificateManagement() {
		c := render.MustContainer(spec, render.TyphaContainerName)
		spec.InitContainers = []corev1.Container{data.typhaSecret.InitContainer(common.CalicoNamespace, c.SecurityContext)}
	}

	c := render.MustContainer(spec, render.TyphaContainerName)
	c.Env = nonClusterHostEnvVars(data, c.Env)
	c.VolumeMounts = append(
		cfg.TLS.TrustedBundle.VolumeMounts(rmeta.OSTypeLinux),
		data.typhaSecret.VolumeMount(rmeta.OSTypeLinux),
	)

	// This Typha is pod-networked, so kubelet probes it on the pod IP.
	c.LivenessProbe.HTTPGet.Host = ""
	c.ReadinessProbe.HTTPGet.Host = ""
	return dep
}

func nonClusterHostEnvVars(data nonClusterHostRenderData, env []corev1.EnvVar) []corev1.EnvVar {
	env = slices.Clone(env)
	env = replaceOrAppendEnvVar(env, "TYPHA_SERVERCERTFILE", data.typhaSecret.VolumeMountCertificateFilePath())
	env = replaceOrAppendEnvVar(env, "TYPHA_SERVERKEYFILE", data.typhaSecret.VolumeMountKeyFilePath())

	// Update Typha client common name or URISAN for non-cluster hosts.
	// At least one of TYPHA_CLIENTCN or TYPHA_CLIENTURISAN must be set.
	env = replaceOrAppendEnvVar(env, "TYPHA_CLIENTCN", data.nodeCommonName)
	env = replaceOrAppendEnvVar(env, "TYPHA_CLIENTURISAN", data.nodeURISAN)

	// The host-network apiserver endpoint may be unreachable from the pod network,
	// so fall back to the pod-network endpoint.
	env = slices.DeleteFunc(env, func(e corev1.EnvVar) bool {
		return e.Name == "KUBERNETES_SERVICE_HOST" || e.Name == "KUBERNETES_SERVICE_PORT"
	})
	env = append(env, k8sapi.PodNetworkEndpoint.EnvVars()...)

	// Tell the health aggregator to listen on all interfaces.
	return append(env, corev1.EnvVar{Name: "TYPHA_HEALTHHOST", Value: "0.0.0.0"})
}

func replaceOrAppendEnvVar(envVars []corev1.EnvVar, key, value string) []corev1.EnvVar {
	found := false
	for i := range envVars {
		if envVars[i].Name == key {
			envVars[i].Value = value
			found = true
		}
	}

	if !found && value != "" {
		envVars = append(envVars, corev1.EnvVar{Name: key, Value: value})
	}
	return envVars
}

func nonClusterHostService(base *corev1.Service) *corev1.Service {
	svc := base.DeepCopy()
	svc.Name += render.TyphaNonClusterHostSuffix
	svc.Labels[render.AppLabelName] += render.TyphaNonClusterHostSuffix
	svc.Spec.Selector[render.AppLabelName] += render.TyphaNonClusterHostSuffix
	return svc
}

// nonClusterHostPolicy is the calico-system policy for the non-cluster-host Typha.
func nonClusterHostPolicy(ri render.Inputs) (add, del []client.Object) {
	egressRules := []v3.Rule{}
	egressRules = networkpolicy.AppendDNSEgressRules(egressRules, ri.Installation.KubernetesProvider.IsOpenShift())
	egressRules = append(egressRules, v3.Rule{
		Action:      v3.Allow,
		Protocol:    &networkpolicy.TCPProtocol,
		Destination: networkpolicy.KubeAPIServerEntityRule,
	})
	if r, err := k8sapi.Endpoint.DestinationEntityRule(); r != nil && err == nil {
		egressRules = append(egressRules, v3.Rule{
			Action:      v3.Allow,
			Protocol:    &networkpolicy.TCPProtocol,
			Destination: *r,
		})
	}

	healthPort := render.TyphaHealthPort(*ri.FelixConfiguration.Spec.HealthPort)
	ingressRules := []v3.Rule{
		{
			Action:   v3.Allow,
			Protocol: &networkpolicy.TCPProtocol,
			Destination: v3.EntityRule{
				Ports: networkpolicy.Ports(uint16(render.TyphaPort), uint16(healthPort)),
			},
		},
	}

	policy := &v3.NetworkPolicy{
		TypeMeta: metav1.TypeMeta{Kind: "NetworkPolicy", APIVersion: "projectcalico.org/v3"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      render.TyphaNonClusterHostNetworkPolicyName,
			Namespace: common.CalicoNamespace,
		},
		Spec: v3.NetworkPolicySpec{
			Order:    &networkpolicy.HighPrecedenceOrder,
			Tier:     networkpolicy.CalicoTierName,
			Selector: networkpolicy.KubernetesAppSelector(common.TyphaDeploymentName + render.TyphaNonClusterHostSuffix),
			Types:    []v3.PolicyType{v3.PolicyTypeEgress, v3.PolicyTypeIngress},
			Egress:   egressRules,
			Ingress:  ingressRules,
		},
	}

	// allow-tigera Tier was renamed to calico-system
	deprecated := networkpolicy.DeprecatedAllowTigeraNetworkPolicyObject("typha-noncluster-host-access", common.CalicoNamespace)
	return []client.Object{policy}, []client.Object{deprecated}
}
