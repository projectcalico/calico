// Copyright (c) 2021-2026 Tigera, Inc. All rights reserved.
//
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

package render

import (
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"

	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"

	operatorv1 "github.com/projectcalico/calico/operator/api/v1"
	"github.com/projectcalico/calico/operator/pkg/common"
	"github.com/projectcalico/calico/operator/pkg/components"
	"github.com/projectcalico/calico/operator/pkg/render/common/authentication"
	rcomponents "github.com/projectcalico/calico/operator/pkg/render/common/components"
	"github.com/projectcalico/calico/operator/pkg/render/common/configmap"
	rmeta "github.com/projectcalico/calico/operator/pkg/render/common/meta"
	"github.com/projectcalico/calico/operator/pkg/render/common/networkpolicy"
	"github.com/projectcalico/calico/operator/pkg/render/common/secret"
	"github.com/projectcalico/calico/operator/pkg/render/common/securitycontext"
	"github.com/projectcalico/calico/operator/pkg/render/common/securitycontextconstraints"
	"github.com/projectcalico/calico/operator/pkg/tls/certificatemanagement"
)

// The names of the components related to the PacketCapture APIs related rendered objects.
const (
	PacketCaptureContainerName          = "tigera-packetcapture-server"
	PacketCaptureName                   = "tigera-packetcapture"
	PacketCaptureNamespace              = PacketCaptureName
	PacketCaptureServiceAccountName     = PacketCaptureName
	PacketCaptureClusterRoleName        = PacketCaptureName
	PacketCaptureClusterRoleBindingName = PacketCaptureName
	// PacketCapturePodExecRole/Binding grant the PacketCapture API pod/exec
	// access in the calico-system namespace. These keep their historical names
	// (previously rendered by the log-collector component) so the move to this
	// component adopts the existing objects in place.
	PacketCapturePodExecRoleName        = "packetcapture-api-role"
	PacketCapturePodExecRoleBindingName = "packetcapture-api-role-binding"
	PacketCaptureDeploymentName         = PacketCaptureName
	PacketCaptureServiceName            = PacketCaptureName
	PacketCapturePolicyName             = networkpolicy.CalicoComponentPolicyPrefix + PacketCaptureName
	PacketCapturePort                   = 8444
	PacketCaptureServerCert             = "tigera-packetcapture-server-tls"
)

var (
	PacketCaptureEntityRule       = networkpolicy.CreateEntityRule(PacketCaptureNamespace, PacketCaptureDeploymentName, PacketCapturePort)
	PacketCaptureSourceEntityRule = networkpolicy.CreateSourceEntityRule(PacketCaptureNamespace, PacketCaptureDeploymentName)
)

// PacketCaptureApiConfiguration contains all the config information needed to render the component.
type PacketCaptureApiConfiguration struct {
	PullSecrets                 []*corev1.Secret
	OpenShift                   bool
	Installation                *operatorv1.InstallationSpec
	KeyValidatorConfig          authentication.KeyValidatorConfig
	ServerCertSecret            certificatemanagement.KeyPairInterface
	TrustedBundle               certificatemanagement.TrustedBundle
	ClusterDomain               string
	ManagementClusterConnection *operatorv1.ManagementClusterConnection

	PacketCaptureAPI *operatorv1.PacketCaptureAPI
}

type packetCaptureApiComponent struct {
	cfg         *PacketCaptureApiConfiguration
	calicoImage string
}

func PacketCaptureAPI(cfg *PacketCaptureApiConfiguration) Component {
	return &packetCaptureApiComponent{
		cfg: cfg,
	}
}

func PacketCaptureAPIPolicy(cfg *PacketCaptureApiConfiguration) Component {
	return NewPassthrough(
		[]client.Object{calicoSystemPolicy(cfg)},
		[]client.Object{
			// allow-tigera Tier was renamed to calico-system
			networkpolicy.DeprecatedAllowTigeraNetworkPolicyObject("tigera-packetcapture", PacketCaptureNamespace),
		},
	)
}

func (pc *packetCaptureApiComponent) ResolveImages(is *operatorv1.ImageSet) error {
	reg := pc.cfg.Installation.Registry
	path := pc.cfg.Installation.ImagePath
	prefix := pc.cfg.Installation.ImagePrefix

	var err error
	pc.calicoImage, err = components.GetReference(components.ComponentTigeraCalico, reg, path, prefix, is)
	if err != nil {
		return err
	}
	return nil
}

func (pc *packetCaptureApiComponent) SupportedOSType() rmeta.OSType {
	return rmeta.OSTypeLinux
}

func (pc *packetCaptureApiComponent) Objects() ([]client.Object, []client.Object) {
	objs := []client.Object{
		CreateNamespace(PacketCaptureNamespace, pc.cfg.Installation.KubernetesProvider, PSSRestricted, pc.cfg.Installation.Azure),
	}

	objs = append(objs, CreateOperatorSecretsRoleBinding(PacketCaptureNamespace))
	objs = append(objs, secret.ToRuntimeObjects(secret.CopyToNamespace(PacketCaptureNamespace, pc.cfg.PullSecrets...)...)...)

	objs = append(objs,
		pc.serviceAccount(),
		pc.clusterRole(),
		pc.clusterRoleBinding(),
		pc.podExecRole(),
		pc.podExecRoleBinding(),
		pc.deployment(),
		pc.service(),
	)

	if pc.cfg.KeyValidatorConfig != nil {
		objs = append(objs, secret.ToRuntimeObjects(pc.cfg.KeyValidatorConfig.RequiredSecrets(PacketCaptureNamespace)...)...)
		objs = append(objs, configmap.ToRuntimeObjects(pc.cfg.KeyValidatorConfig.RequiredConfigMaps(PacketCaptureNamespace)...)...)
	}

	if pc.cfg.TrustedBundle != nil {
		objs = append(objs, pc.cfg.TrustedBundle.ConfigMap(PacketCaptureNamespace))
	}

	return objs, nil
}

func (pc *packetCaptureApiComponent) Ready() bool {
	return true
}

func (pc *packetCaptureApiComponent) service() *corev1.Service {
	return &corev1.Service{
		TypeMeta: metav1.TypeMeta{Kind: "Service", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      PacketCaptureServiceName,
			Namespace: PacketCaptureNamespace,
		},
		Spec: corev1.ServiceSpec{
			Selector: map[string]string{
				"k8s-app": PacketCaptureName,
			},
			Ports: []corev1.ServicePort{
				{
					Name:       PacketCaptureName,
					Port:       443,
					Protocol:   corev1.ProtocolTCP,
					TargetPort: intstr.FromInt(PacketCapturePort),
				},
			},
		},
	}
}

func (pc *packetCaptureApiComponent) serviceAccount() *corev1.ServiceAccount {
	return &corev1.ServiceAccount{
		TypeMeta:   metav1.TypeMeta{Kind: "ServiceAccount", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{Name: PacketCaptureServiceAccountName, Namespace: PacketCaptureNamespace},
	}
}

func (pc *packetCaptureApiComponent) clusterRole() client.Object {
	rules := []rbacv1.PolicyRule{
		{
			APIGroups: []string{"authorization.k8s.io"},
			Resources: []string{"subjectaccessreviews"},
			Verbs:     []string{"create"},
		},
		{
			APIGroups: []string{"authentication.k8s.io"},
			Resources: []string{"tokenreviews"},
			Verbs:     []string{"create"},
		},
		{
			APIGroups: []string{"projectcalico.org"},
			Resources: []string{"packetcaptures"},
			Verbs:     []string{"get"},
		},
		{
			APIGroups: []string{"projectcalico.org"},
			Resources: []string{"packetcaptures/status"},
			Verbs:     []string{"update"},
		},
	}

	if pc.cfg.OpenShift {
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
			Name: PacketCaptureClusterRoleName,
		},
		Rules: rules,
	}
}

func (pc *packetCaptureApiComponent) clusterRoleBinding() *rbacv1.ClusterRoleBinding {
	return &rbacv1.ClusterRoleBinding{
		TypeMeta: metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name: PacketCaptureClusterRoleBindingName,
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "ClusterRole",
			Name:     PacketCaptureClusterRoleName,
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      "ServiceAccount",
				Name:      PacketCaptureServiceAccountName,
				Namespace: PacketCaptureNamespace,
			},
		},
	}
}

// podExecRole grants the PacketCapture API pod/exec and pod/list in the
// calico-system namespace. The API retrieves capture files by exec-ing into the
// per-node calico-node pod, which writes captures to the node's /var/log/calico
// hostPath. Namespaced to calico-system to keep the grant least-privilege.
func (pc *packetCaptureApiComponent) podExecRole() *rbacv1.Role {
	return &rbacv1.Role{
		TypeMeta: metav1.TypeMeta{Kind: "Role", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      PacketCapturePodExecRoleName,
			Namespace: common.CalicoNamespace,
		},
		Rules: []rbacv1.PolicyRule{
			{
				APIGroups: []string{""},
				Resources: []string{"pods/exec"},
				Verbs:     []string{"create"},
			},
			{
				APIGroups: []string{""},
				Resources: []string{"pods"},
				Verbs:     []string{"list"},
			},
		},
	}
}

func (pc *packetCaptureApiComponent) podExecRoleBinding() *rbacv1.RoleBinding {
	return &rbacv1.RoleBinding{
		TypeMeta: metav1.TypeMeta{Kind: "RoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      PacketCapturePodExecRoleBindingName,
			Namespace: common.CalicoNamespace,
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "Role",
			Name:     PacketCapturePodExecRoleName,
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      "ServiceAccount",
				Name:      PacketCaptureServiceAccountName,
				Namespace: PacketCaptureNamespace,
			},
		},
	}
}

func (pc *packetCaptureApiComponent) deployment() *appsv1.Deployment {
	tolerations := append(pc.cfg.Installation.ControlPlaneTolerations, rmeta.TolerateCriticalAddonsAndControlPlane...)
	if pc.cfg.Installation.KubernetesProvider.IsGKE() {
		tolerations = append(tolerations, rmeta.TolerateGKEARM64NoSchedule)
	}
	container := pc.container()
	var initContainers []corev1.Container
	if pc.cfg.ServerCertSecret.UseCertificateManagement() {
		initContainers = append(initContainers, pc.cfg.ServerCertSecret.InitContainer(PacketCaptureNamespace, container.SecurityContext))
	}
	d := &appsv1.Deployment{
		TypeMeta: metav1.TypeMeta{Kind: "Deployment", APIVersion: "apps/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      PacketCaptureDeploymentName,
			Namespace: PacketCaptureNamespace,
		},
		Spec: appsv1.DeploymentSpec{
			Replicas: ptr.To(int32(1)),
			Strategy: appsv1.DeploymentStrategy{
				Type: appsv1.RecreateDeploymentStrategyType,
			},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Name:        PacketCaptureDeploymentName,
					Namespace:   PacketCaptureNamespace,
					Annotations: pc.annotations(),
				},
				Spec: corev1.PodSpec{
					NodeSelector:       pc.cfg.Installation.ControlPlaneNodeSelector,
					ServiceAccountName: PacketCaptureServiceAccountName,
					Tolerations:        tolerations,
					ImagePullSecrets:   secret.GetReferenceList(pc.cfg.PullSecrets),
					InitContainers:     initContainers,
					Containers:         []corev1.Container{container},
					Volumes:            pc.volumes(),
				},
			},
		},
	}

	if pc.cfg.PacketCaptureAPI != nil {
		if overrides := pc.cfg.PacketCaptureAPI.Spec.PacketCaptureAPIDeployment; overrides != nil {
			rcomponents.ApplyDeploymentOverrides(d, overrides)
		}
	}

	return d
}

func (pc *packetCaptureApiComponent) container() corev1.Container {
	volumeMounts := []corev1.VolumeMount{
		pc.cfg.ServerCertSecret.VolumeMount(pc.SupportedOSType()),
	}
	env := []corev1.EnvVar{
		{Name: "PACKETCAPTURE_API_LOG_LEVEL", Value: "Info"},
		{Name: "PACKETCAPTURE_API_HTTPS_KEY", Value: pc.cfg.ServerCertSecret.VolumeMountKeyFilePath()},
		{Name: "PACKETCAPTURE_API_HTTPS_CERT", Value: pc.cfg.ServerCertSecret.VolumeMountCertificateFilePath()},
	}

	if pc.cfg.KeyValidatorConfig != nil {
		env = append(env, pc.cfg.KeyValidatorConfig.RequiredEnv("PACKETCAPTURE_API_")...)
	}
	if pc.cfg.TrustedBundle != nil {
		volumeMounts = append(volumeMounts, pc.cfg.TrustedBundle.VolumeMounts(pc.SupportedOSType())...)
	}

	return corev1.Container{
		Name:            PacketCaptureContainerName,
		Image:           pc.calicoImage,
		Command:         []string{components.CalicoBinaryPath, "component", "packetcapture"},
		LivenessProbe:   pc.healthProbe(),
		ReadinessProbe:  pc.healthProbe(),
		SecurityContext: securitycontext.NewNonRootContext(),
		Env:             env,
		VolumeMounts:    volumeMounts,
	}
}

func (pc *packetCaptureApiComponent) healthProbe() *corev1.Probe {
	return &corev1.Probe{
		ProbeHandler: corev1.ProbeHandler{
			HTTPGet: &corev1.HTTPGetAction{
				Path:   "/health",
				Port:   intstr.FromInt(PacketCapturePort),
				Scheme: corev1.URISchemeHTTPS,
			},
		},
		InitialDelaySeconds: 30,
	}
}

func (pc *packetCaptureApiComponent) volumes() []corev1.Volume {
	volumes := []corev1.Volume{
		pc.cfg.ServerCertSecret.Volume(),
	}

	if pc.cfg.TrustedBundle != nil {
		volumes = append(volumes, pc.cfg.TrustedBundle.Volume())
	}

	return volumes
}

func (pc *packetCaptureApiComponent) annotations() map[string]string {
	annotations := map[string]string{
		pc.cfg.ServerCertSecret.HashAnnotationKey(): pc.cfg.ServerCertSecret.HashAnnotationValue(),
	}

	return annotations
}

func calicoSystemPolicy(cfg *PacketCaptureApiConfiguration) *v3.NetworkPolicy {
	managedCluster := cfg.ManagementClusterConnection != nil
	egressRules := []v3.Rule{
		{
			Action:      v3.Allow,
			Protocol:    &networkpolicy.TCPProtocol,
			Destination: networkpolicy.KubeAPIServerEntityRule,
		},
	}
	egressRules = networkpolicy.AppendDNSEgressRules(egressRules, cfg.OpenShift)
	if !managedCluster {
		egressRules = append(egressRules, v3.Rule{
			Action:      v3.Allow,
			Protocol:    &networkpolicy.TCPProtocol,
			Destination: DexEntityRule,
		})
	}

	ingressRules := []v3.Rule{}
	if managedCluster {
		ingressRules = append(ingressRules, v3.Rule{
			Action:   v3.Allow,
			Protocol: &networkpolicy.TCPProtocol,
			Source:   GuardianSourceEntityRule,
			Destination: v3.EntityRule{
				Ports: networkpolicy.Ports(PacketCapturePort),
			},
		})
	} else {
		ingressRules = append(ingressRules, v3.Rule{
			Action:   v3.Allow,
			Protocol: &networkpolicy.TCPProtocol,
			Source:   networkpolicy.DefaultHelper().ManagerSourceEntityRule(),
			Destination: v3.EntityRule{
				Ports: networkpolicy.Ports(PacketCapturePort),
			},
		})
	}

	return &v3.NetworkPolicy{
		TypeMeta: metav1.TypeMeta{Kind: "NetworkPolicy", APIVersion: "projectcalico.org/v3"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      PacketCapturePolicyName,
			Namespace: PacketCaptureNamespace,
		},
		Spec: v3.NetworkPolicySpec{
			Order:    &networkpolicy.HighPrecedenceOrder,
			Tier:     networkpolicy.CalicoTierName,
			Selector: networkpolicy.KubernetesAppSelector(PacketCaptureName),
			Types:    []v3.PolicyType{v3.PolicyTypeIngress, v3.PolicyTypeEgress},
			Ingress:  ingressRules,
			Egress:   egressRules,
		},
	}
}
