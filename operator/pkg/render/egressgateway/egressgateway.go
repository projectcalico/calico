// Copyright (c) 2023-2026 Tigera, Inc. All rights reserved.

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

package egressgateway

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	ocsv1 "github.com/openshift/api/security/v1"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/components"
	"github.com/tigera/operator/pkg/render"
	rcomp "github.com/tigera/operator/pkg/render/common/components"
	rmeta "github.com/tigera/operator/pkg/render/common/meta"
	"github.com/tigera/operator/pkg/render/common/secret"
	"github.com/tigera/operator/pkg/render/common/securitycontext"
	"github.com/tigera/operator/pkg/render/common/securitycontextconstraints"
)

const (
	egwPortName             = "health"
	DefaultVXLANPort  int   = 4790
	DefaultVXLANVNI   int   = 4097
	DefaultHealthPort int32 = 8080
	OpenShiftSCCName        = "tigera-egressgateway"
)

var log = logf.Log.WithName("render")

func EgressGateway(
	config *Config,
) render.Component {
	return &component{
		config: config,
	}
}

type component struct {
	config *Config
}

// Config contains all the config information EgressGateway needs to render component.
type Config struct {
	PullSecrets  []*corev1.Secret
	Installation *operatorv1.InstallationSpec
	OSType       rmeta.OSType
	EgressGW     *operatorv1.EgressGateway

	egwImage        string
	VXLANVNI        int
	VXLANPort       int
	IptablesBackend string

	OpenShift         bool
	NamespaceAndNames []string
}

func (c *component) ResolveImages(is *operatorv1.ImageSet) error {
	reg := c.config.Installation.Registry
	path := c.config.Installation.ImagePath
	prefix := c.config.Installation.ImagePrefix

	if c.config.OSType != c.SupportedOSType() {
		//nolint:staticcheck // Ignore ST1005 error strings should not be capitalized
		return fmt.Errorf("Egress Gateway is supported only on %s", c.SupportedOSType())
	}

	var err error
	c.config.egwImage, err = components.GetReference(components.ComponentEgressGateway, reg, path, prefix, is)
	return err
}

func (c *component) SupportedOSType() rmeta.OSType {
	return rmeta.OSTypeLinux
}

func (c *component) Objects() ([]client.Object, []client.Object) {
	var objectsToCreate []client.Object
	objectsToCreate = append(objectsToCreate, c.egwOperatorSecretsRoleBinding())
	objectsToCreate = append(objectsToCreate, secret.ToRuntimeObjects(c.egwPullSecrets()...)...)
	objectsToCreate = append(objectsToCreate, c.egwServiceAccount())

	var objectsToDelete []client.Object
	if c.config.OpenShift {
		objectsToCreate = append(objectsToCreate, c.egwRole(), c.egwRoleBinding())
		if c.config.OpenShift {
			objectsToCreate = append(objectsToCreate, c.getSecurityContextConstraints())
		}
	} else {
		// It is possible to have multiple egress gateway resources in different namespaces.
		// We only delete namespaced role and role binding here. The cluster-level scc
		// is deleted in egressgateway_controller when no egress gateway is in the cluster.
		objectsToDelete = append(objectsToDelete, c.egwRole(), c.egwRoleBinding())
	}

	objectsToCreate = append(objectsToCreate, c.egwDeployment())
	return objectsToCreate, objectsToDelete
}

func (c *component) egwOperatorSecretsRoleBinding() *rbacv1.RoleBinding {
	operatorSecretRB := render.CreateOperatorSecretsRoleBinding(c.config.EgressGW.Namespace)
	operatorSecretRB.Labels = common.MapExistsOrInitialize(operatorSecretRB.Labels)
	// The tigera-operator-secrets RoleBinding is shared across all EGW CRs in this namespace.
	// As such, we mark it as having multiple owners so that we maintain multiple owner references
	// when creating the rolebinding so that it will only be GC'd when all of its owners have been deleted.
	operatorSecretRB.Labels[common.MultipleOwnersLabel] = "true"
	return operatorSecretRB
}

func (c *component) Ready() bool {
	return true
}

func (c *component) egwDeployment() *appsv1.Deployment {
	d := appsv1.Deployment{
		TypeMeta: metav1.TypeMeta{Kind: "Deployment", APIVersion: "apps/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      c.config.EgressGW.Name,
			Namespace: c.config.EgressGW.Namespace,
			Labels:    c.config.EgressGW.Spec.Template.Metadata.Labels,
		},
		Spec: appsv1.DeploymentSpec{
			Selector: &metav1.LabelSelector{MatchLabels: c.config.EgressGW.Spec.Template.Metadata.Labels},
			Template: *c.deploymentPodTemplate(),
		},
	}

	if overrides := c.config.EgressGW; overrides != nil {
		rcomp.ApplyDeploymentOverrides(&d, overrides)
	}

	// Add AWS specific resource requests/limits after applying overrides to avoid being overwritten
	// if the user has specified their own.
	c.addAWSResources(&d)
	return &d
}

func (c *component) deploymentPodTemplate() *corev1.PodTemplateSpec {
	var ps []corev1.LocalObjectReference
	for _, x := range c.config.PullSecrets {
		ps = append(ps, corev1.LocalObjectReference{Name: x.Name})
	}
	var tolerations []corev1.Toleration
	if c.config.Installation.KubernetesProvider.IsGKE() {
		tolerations = append(tolerations, rmeta.TolerateGKEARM64NoSchedule)
	}
	return &corev1.PodTemplateSpec{
		ObjectMeta: metav1.ObjectMeta{
			Annotations: c.egwBuildAnnotations(),
		},
		Spec: corev1.PodSpec{
			ImagePullSecrets:   ps,
			InitContainers:     []corev1.Container{*c.egwInitContainer()},
			Containers:         []corev1.Container{*c.egwContainer()},
			ServiceAccountName: c.config.EgressGW.Name,
			Tolerations:        tolerations,
			Volumes:            []corev1.Volume{*c.egwVolume()},
		},
	}
}

func (c *component) egwBuildAnnotations() map[string]string {
	annotations := map[string]string{}
	annotations["cni.projectcalico.org/ipv4pools"] = c.getIPPools()
	if c.config.EgressGW.Spec.AWS != nil && len(c.config.EgressGW.Spec.AWS.ElasticIPs) > 0 {
		annotations["cni.projectcalico.org/awsElasticIPs"] = c.getElasticIPs()
	}
	if len(c.config.EgressGW.Spec.ExternalNetworks) > 0 {
		annotations["egress.projectcalico.org/externalNetworkNames"] = c.getExternalNetworks()
	}
	return annotations
}

func (c *component) egwInitContainer() *corev1.Container {
	return &corev1.Container{
		Name:            "egress-gateway-init",
		Image:           c.config.egwImage,
		Command:         []string{"/init-gateway.sh"},
		SecurityContext: securitycontext.NewRootContext(true),
		Env:             c.egwInitEnvVars(),
	}
}

func (c *component) egwContainer() *corev1.Container {
	sc := securitycontext.NewRootContext(false)
	sc.Capabilities.Add = []corev1.Capability{"NET_ADMIN", "NET_RAW"}

	return &corev1.Container{
		Name:            "egress-gateway",
		Image:           c.config.egwImage,
		Env:             c.egwEnvVars(),
		VolumeMounts:    c.egwVolumeMounts(),
		Ports:           c.egwPorts(),
		Command:         []string{"/start-gateway.sh"},
		ReadinessProbe:  c.egwReadinessProbe(),
		SecurityContext: sc,
	}
}

func (c *component) egwReadinessProbe() *corev1.Probe {
	return &corev1.Probe{
		ProbeHandler: corev1.ProbeHandler{
			HTTPGet: &corev1.HTTPGetAction{
				Path: "/readiness",
				Port: intstr.FromInt(int(DefaultHealthPort)),
			},
		},
		// during testing it was found that the default initial delay wasn't enough
		// in some cases so the default has been increased
		InitialDelaySeconds: 10,
	}
}

func (c *component) egwPorts() []corev1.ContainerPort {
	return []corev1.ContainerPort{
		{
			ContainerPort: DefaultHealthPort,
			Name:          egwPortName,
			Protocol:      corev1.ProtocolTCP,
		},
	}
}

func (c *component) egwVolume() *corev1.Volume {
	return &corev1.Volume{
		Name:         "policysync",
		VolumeSource: corev1.VolumeSource{CSI: &corev1.CSIVolumeSource{Driver: "csi.tigera.io"}},
	}
}

func (c *component) egwVolumeMounts() []corev1.VolumeMount {
	return []corev1.VolumeMount{
		{Name: "policysync", MountPath: "/var/run/calico"},
	}
}

func (c *component) egwEnvVars() []corev1.EnvVar {
	egressPodIp := &corev1.EnvVarSource{FieldRef: &corev1.ObjectFieldSelector{FieldPath: "status.podIP"}}
	egressPodIps := &corev1.EnvVarSource{FieldRef: &corev1.ObjectFieldSelector{FieldPath: "status.podIPs"}}
	envVar := []corev1.EnvVar{
		{Name: "HEALTH_PORT", Value: fmt.Sprintf("%d", DefaultHealthPort)},
		{Name: "EGRESS_POD_IP", ValueFrom: egressPodIp},
		{Name: "EGRESS_POD_IPS", ValueFrom: egressPodIps},
		{Name: "EGRESS_VXLAN_VNI", Value: fmt.Sprintf("%d", c.config.VXLANVNI)},
		{Name: "LOG_SEVERITY", Value: c.config.EgressGW.GetLogSeverity()},
	}

	icmpProbeIPs, icmpInterval, icmpTimeout := c.getICMPProbe()
	if icmpProbeIPs != "" {
		icmpEnvVar := []corev1.EnvVar{
			{Name: "ICMP_PROBE_IPS", Value: icmpProbeIPs},
			{Name: "ICMP_PROBE_INTERVAL", Value: icmpInterval},
			{Name: "ICMP_PROBE_TIMEOUT", Value: icmpTimeout},
		}
		envVar = append(envVar, icmpEnvVar...)
	}

	httpProbeURLs, httpInterval, httpTimeout := c.getHTTPProbe()
	if httpProbeURLs != "" {
		httpEnvVar := []corev1.EnvVar{
			{Name: "HTTP_PROBE_URLS", Value: httpProbeURLs},
			{Name: "HTTP_PROBE_INTERVAL", Value: httpInterval},
			{Name: "HTTP_PROBE_TIMEOUT", Value: httpTimeout},
		}
		envVar = append(envVar, httpEnvVar...)
	}
	healthTimeOutDS := c.getHealthTimeoutDs()
	if healthTimeOutDS != "" {
		dsEnv := corev1.EnvVar{Name: "HEALTH_TIMEOUT_DATASTORE", Value: healthTimeOutDS}
		envVar = append(envVar, dsEnv)
	}
	return envVar
}

func (c *component) egwInitEnvVars() []corev1.EnvVar {
	egressPodIp := &corev1.EnvVarSource{FieldRef: &corev1.ObjectFieldSelector{FieldPath: "status.podIP"}}
	egressPodIps := &corev1.EnvVarSource{FieldRef: &corev1.ObjectFieldSelector{FieldPath: "status.podIPs"}}
	dataplane := "iptables"
	if c.config.Installation.IsNftables() {
		dataplane = "nftables"
	}
	envVar := []corev1.EnvVar{
		{Name: "EGRESS_VXLAN_VNI", Value: fmt.Sprintf("%d", c.config.VXLANVNI)},
		{Name: "EGRESS_VXLAN_PORT", Value: fmt.Sprintf("%d", c.config.VXLANPort)},
		{Name: "EGRESS_POD_IP", ValueFrom: egressPodIp},
		{Name: "EGRESS_POD_IPS", ValueFrom: egressPodIps},
		{Name: "DATAPLANE", Value: dataplane},
	}
	if c.config.IptablesBackend != "" {
		envVar = append(envVar, corev1.EnvVar{Name: "IPTABLES_BACKEND", Value: c.config.IptablesBackend})
	}
	return envVar
}

func (c *component) egwPullSecrets() []*corev1.Secret {
	var secrets []*corev1.Secret
	for _, secret := range c.config.PullSecrets {
		x := secret.DeepCopy()
		x.ObjectMeta = metav1.ObjectMeta{Name: secret.Name, Namespace: c.config.EgressGW.Namespace}
		x.Labels = common.MapExistsOrInitialize(x.Labels)
		// Each pull secret is shared across all of the EGW deployments in this namespace.
		// As such, we mark it as having multiple owners so that we maintain multiple owner references
		// when creating the secret so that it will only be GC'd when all of its owners have been deleted.
		x.Labels[common.MultipleOwnersLabel] = "true"
		secrets = append(secrets, x)
	}
	return secrets
}

func (c *component) egwRole() *rbacv1.Role {
	return &rbacv1.Role{
		TypeMeta: metav1.TypeMeta{Kind: "Role", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      c.config.EgressGW.Name,
			Namespace: c.config.EgressGW.Namespace,
		},
		Rules: []rbacv1.PolicyRule{
			{
				APIGroups:     []string{"security.openshift.io"},
				Resources:     []string{"securitycontextconstraints"},
				Verbs:         []string{"use"},
				ResourceNames: []string{OpenShiftSCCName},
			},
		},
	}
}

func (c *component) egwRoleBinding() *rbacv1.RoleBinding {
	return &rbacv1.RoleBinding{
		TypeMeta: metav1.TypeMeta{Kind: "RoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      c.config.EgressGW.Name,
			Namespace: c.config.EgressGW.Namespace,
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "Role",
			Name:     c.config.EgressGW.Name,
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      "ServiceAccount",
				Name:      c.config.EgressGW.Name,
				Namespace: c.config.EgressGW.Namespace,
			},
		},
	}
}

func (c *component) egwServiceAccount() *corev1.ServiceAccount {
	return &corev1.ServiceAccount{
		TypeMeta: metav1.TypeMeta{Kind: "ServiceAccount", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      c.config.EgressGW.Name,
			Namespace: c.config.EgressGW.Namespace,
		},
	}
}

func (c *component) getICMPProbe() (string, string, string) {
	probeIPs := ""
	interval := ""
	timeout := ""
	if c.config.EgressGW.Spec.EgressGatewayFailureDetection != nil {
		if c.config.EgressGW.Spec.EgressGatewayFailureDetection.ICMPProbe != nil {
			icmpProbes := c.config.EgressGW.Spec.EgressGatewayFailureDetection.ICMPProbe
			probeIPs = strings.Join(icmpProbes.IPs, ",")
			interval = fmt.Sprintf("%ds", *icmpProbes.IntervalSeconds)
			timeout = fmt.Sprintf("%ds", *icmpProbes.TimeoutSeconds)
		}
	}
	return probeIPs, interval, timeout
}

func (c *component) getHTTPProbe() (string, string, string) {
	probeURLs := ""
	interval := ""
	timeout := ""
	if c.config.EgressGW.Spec.EgressGatewayFailureDetection != nil {
		if c.config.EgressGW.Spec.EgressGatewayFailureDetection.HTTPProbe != nil {
			httpProbes := c.config.EgressGW.Spec.EgressGatewayFailureDetection.HTTPProbe
			probeURLs = strings.Join(httpProbes.URLs, ",")
			interval = fmt.Sprintf("%ds", *httpProbes.IntervalSeconds)
			timeout = fmt.Sprintf("%ds", *httpProbes.TimeoutSeconds)
		}
	}
	return probeURLs, interval, timeout
}

func (c *component) addAWSResources(d *appsv1.Deployment) {
	egw := c.config.EgressGW
	if egw.Spec.AWS == nil || *egw.Spec.AWS.NativeIP == operatorv1.NativeIPDisabled {
		return
	}
	recommendedQuantity := resource.NewQuantity(1, resource.DecimalSI)
	resourceRequirements := &d.Spec.Template.Spec.Containers[0].Resources
	if resourceRequirements.Limits == nil {
		resourceRequirements.Limits = corev1.ResourceList{}
	}
	if resourceRequirements.Requests == nil {
		resourceRequirements.Requests = corev1.ResourceList{}
	}
	resourceRequirements.Limits["projectcalico.org/aws-secondary-ipv4"] = *recommendedQuantity
	resourceRequirements.Requests["projectcalico.org/aws-secondary-ipv4"] = *recommendedQuantity
}

func (c *component) getIPPools() string {
	egw := c.config.EgressGW
	ippools := []string{}
	for _, ippool := range egw.Spec.IPPools {
		if ippool.Name != "" {
			ippools = append(ippools, ippool.Name)
		} else if ippool.CIDR != "" {
			ippools = append(ippools, ippool.CIDR)
		}
	}
	return concatString(ippools)
}

func (c *component) getElasticIPs() string {
	egw := c.config.EgressGW
	if egw.Spec.AWS != nil {
		if len(egw.Spec.AWS.ElasticIPs) > 0 {
			return concatString(egw.Spec.AWS.ElasticIPs)
		}
	}
	return ""
}

func (c *component) getExternalNetworks() string {
	egw := c.config.EgressGW
	return concatString(egw.Spec.ExternalNetworks)
}

func (c *component) getHealthTimeoutDs() string {
	if c.config.EgressGW.Spec.EgressGatewayFailureDetection != nil {
		if c.config.EgressGW.Spec.EgressGatewayFailureDetection.HealthTimeoutDataStoreSeconds != nil {
			egw := c.config.EgressGW
			return fmt.Sprintf("%ds", *egw.Spec.EgressGatewayFailureDetection.HealthTimeoutDataStoreSeconds)
		}
	}
	return ""
}

func (c *component) getSecurityContextConstraints() *ocsv1.SecurityContextConstraints {
	scc := SecurityContextConstraints()
	sort.Strings(c.config.NamespaceAndNames)
	for _, egwNames := range c.config.NamespaceAndNames {
		scc.Users = append(scc.Users, fmt.Sprintf("system:serviceaccount:%s", egwNames))
	}
	return scc
}

func SecurityContextConstraints() *ocsv1.SecurityContextConstraints {
	scc := securitycontextconstraints.NewNonRootSecurityContextConstraints(OpenShiftSCCName, []string{})
	scc.AllowPrivilegeEscalation = ptr.To(true)
	scc.AllowPrivilegedContainer = true
	scc.AllowedCapabilities = []corev1.Capability{corev1.Capability("NET_ADMIN"), corev1.Capability("NET_RAW")}
	scc.ReadOnlyRootFilesystem = false
	return scc
}

func concatString(arr []string) string {
	str, err := json.Marshal(arr)
	if err != nil {
		log.Info("error marshaling data %v", arr)
		return ""
	}
	return string(str)
}
