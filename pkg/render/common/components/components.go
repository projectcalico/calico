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

package components

import (
	"fmt"
	"reflect"
	"strings"

	kbv1 "github.com/elastic/cloud-on-k8s/v2/pkg/apis/kibana/v1"
	envoyapi "github.com/envoyproxy/gateway/api/v1alpha1"
	monitoringv1 "github.com/prometheus-operator/prometheus-operator/pkg/apis/monitoring/v1"
	operator "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/common"
	batchv1 "k8s.io/api/batch/v1"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	policyv1 "k8s.io/api/policy/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

var log = logf.Log.WithName("components")

// CustomOverridesAnnotation is set on workloads when the render package applies user-specified
// probe timing or resource overrides. The value is a comma-separated list of override types.
const CustomOverridesAnnotation = "operator.tigera.io/custom-overrides"

// containerNameAliases maps deprecated container names to their current names.
// When a user provides an override using a deprecated name, it is transparently
// resolved to the current name before matching against rendered containers.
// To support a rename: add an entry mapping old name → current name.
// Values must not also appear as keys (no transitive aliases).
var containerNameAliases = map[string]string{
	"tigera-manager":  "calico-manager",
	"tigera-voltron":  "calico-voltron",
	"tigera-ui-apis":  "calico-ui-apis",
	"tigera-es-proxy": "calico-ui-apis",
	"tigera-voltron-linseed-tls-key-cert-provisioner": "calico-voltron-linseed-tls-key-cert-provisioner",
	"fluentd": "calico-fluent-bit",
	"tigera-fluentd-prometheus-tls-key-cert-provisioner": "calico-fluent-bit-tls-key-cert-provisioner",
}

func resolveContainerName(name string) string {
	if current, ok := containerNameAliases[name]; ok {
		return current
	}
	return name
}

// replicatedPodResource contains the overridable data for a Deployment or DaemonSet.
type replicatedPodResource struct {
	labels             map[string]string
	annotations        map[string]string
	replicas           *int32
	minReadySeconds    *int32
	podTemplateSpec    *corev1.PodTemplateSpec
	deploymentStrategy *appsv1.DeploymentStrategy // Deployments only
}

func GetMetadata(overrides any) *operator.Metadata {
	value := getField(overrides, "Metadata")
	if !value.IsValid() || value.IsNil() {
		return nil
	}
	return value.Interface().(*operator.Metadata)
}

func GetReplicas(overrides any) *int32 {
	value := getField(overrides, "Spec", "Replicas")
	if !value.IsValid() || value.IsNil() {
		return nil
	}
	return value.Interface().(*int32)
}

func GetMinReadySeconds(overrides any) *int32 {
	value := getField(overrides, "Spec", "MinReadySeconds")
	if !value.IsValid() || value.IsNil() {
		return nil
	}
	return value.Interface().(*int32)
}

func GetPodTemplateMetadata(overrides any) *operator.Metadata {
	value := getField(overrides, "Spec", "Template", "Metadata")
	if !value.IsValid() || value.IsNil() {
		return nil
	}
	// SPECIAL CASE: EgressGateway uses a different type for its metadata.
	if v, egressGatewayCase := value.Interface().(*operator.EgressGatewayMetadata); egressGatewayCase {
		return &operator.Metadata{Labels: v.Labels, Annotations: v.Annotations}
	}
	return value.Interface().(*operator.Metadata)
}

func GetTerminationGracePeriodSeconds(overrides any) *int64 {
	value := getField(overrides, "Spec", "Template", "Spec", "TerminationGracePeriodSeconds")
	if !value.IsValid() || value.IsNil() {
		return nil
	}
	return value.Interface().(*int64)
}

func GetDeploymentStrategy(overrides any) *appsv1.DeploymentStrategy {
	value := getField(overrides, "Spec", "Strategy", "RollingUpdate")
	if !value.IsValid() || value.IsNil() {
		return nil
	}
	return &appsv1.DeploymentStrategy{
		Type:          appsv1.RollingUpdateDeploymentStrategyType,
		RollingUpdate: value.Interface().(*appsv1.RollingUpdateDeployment),
	}
}

func GetInitContainers(overrides any) []corev1.Container {
	value := getField(overrides, "Spec", "Template", "Spec", "InitContainers")
	if !value.IsValid() || value.IsNil() {
		return nil
	}
	return valueToContainers(value)
}

func GetContainers(overrides any) []corev1.Container {
	value := getField(overrides, "Spec", "Template", "Spec", "Containers")
	if !value.IsValid() || value.IsNil() {
		return nil
	}
	return valueToContainers(value)
}

func GetHostNetwork(overrides any) *bool {
	value := getField(overrides, "Spec", "Template", "Spec", "HostNetwork")
	if !value.IsValid() || value.IsNil() {
		return nil
	}
	return value.Interface().(*bool)
}

func GetDNSPolicy(overrides any) (corev1.DNSPolicy, bool) {
	value := getField(overrides, "Spec", "Template", "Spec", "DNSPolicy")

	// If the value is not valid or is an empty string, return an empty DNSPolicy.
	if !value.IsValid() || value.IsNil() {
		return "", false
	}
	return *value.Interface().(*corev1.DNSPolicy), true
}

func GetDNSConfig(overrides any) *corev1.PodDNSConfig {
	value := getField(overrides, "Spec", "Template", "Spec", "DNSConfig")
	if !value.IsValid() || value.IsNil() {
		return nil
	}
	return value.Interface().(*corev1.PodDNSConfig)
}

// containerOverride holds override values extracted from a container override struct,
// including probe timing overrides that can't be represented in corev1.Container.
type containerOverride struct {
	Name           string
	Resources      *corev1.ResourceRequirements
	Ports          []corev1.ContainerPort
	ReadinessProbe *operator.ProbeOverride
	LivenessProbe  *operator.ProbeOverride
}

// GetContainerOverrides returns the full container overrides including probe timing.
func GetContainerOverrides(overrides any) []containerOverride {
	value := getField(overrides, "Spec", "Template", "Spec", "Containers")
	if !value.IsValid() || value.IsNil() {
		return nil
	}
	return valueToContainerOverrides(value)
}

func valueToContainerOverrides(value reflect.Value) []containerOverride {
	cs := make([]containerOverride, 0, value.Len())
	for _, v := range value.Seq2() {
		name := v.FieldByName("Name")
		co := containerOverride{Name: resolveContainerName(name.String())}

		if resources := v.FieldByName("Resources"); resources.IsValid() && !resources.IsNil() {
			r := resources.Interface().(*corev1.ResourceRequirements)
			co.Resources = r
		}
		co.Ports = valueToContainerPorts(v)
		if rp := v.FieldByName("ReadinessProbe"); rp.IsValid() && !rp.IsNil() {
			co.ReadinessProbe = rp.Interface().(*operator.ProbeOverride)
		}
		if lp := v.FieldByName("LivenessProbe"); lp.IsValid() && !lp.IsNil() {
			co.LivenessProbe = lp.Interface().(*operator.ProbeOverride)
		}

		if co.Resources != nil || co.Ports != nil || co.ReadinessProbe != nil || co.LivenessProbe != nil {
			cs = append(cs, co)
		}
	}
	return cs
}

func valueToContainers(value reflect.Value) []corev1.Container {
	cs := make([]corev1.Container, 0, value.Len())
	for _, v := range value.Seq2() {
		name := v.FieldByName("Name")
		resources := v.FieldByName("Resources")
		ports := valueToContainerPorts(v)
		if !resources.IsNil() || ports != nil {
			container := corev1.Container{
				Name: resolveContainerName(name.String()),
			}
			if !resources.IsNil() {
				container.Resources = *(resources.Interface().(*corev1.ResourceRequirements))
			}
			if ports != nil {
				container.Ports = ports
			}
			cs = append(cs, container)
		}
	}
	return cs
}

func valueToContainerPorts(v reflect.Value) []corev1.ContainerPort {
	portOverrides := v.FieldByName("Ports")
	if !portOverrides.IsValid() || portOverrides.IsNil() {
		return nil
	}
	ports := make([]corev1.ContainerPort, 0, portOverrides.Len())
	for i := 0; i < portOverrides.Len(); i++ {
		p := portOverrides.Index(i)
		port := corev1.ContainerPort{
			ContainerPort: int32(p.FieldByName("ContainerPort").Int()),
		}
		if name := p.FieldByName("Name"); name.IsValid() && name.String() != "" {
			port.Name = name.String()
		}
		ports = append(ports, port)
	}
	return ports
}

func GetAffinity(overrides any) *corev1.Affinity {
	value := getField(overrides, "Spec", "Template", "Spec", "Affinity")
	if !value.IsValid() || value.IsNil() {
		return nil
	}
	return value.Interface().(*corev1.Affinity)
}

func GetNodeSelector(overrides any) map[string]string {
	value := getField(overrides, "Spec", "Template", "Spec", "NodeSelector")
	if !value.IsValid() || value.IsNil() {
		return nil
	}
	return value.Interface().(map[string]string)
}

func GetTopologySpreadConstraints(overrides any) []corev1.TopologySpreadConstraint {
	value := getField(overrides, "Spec", "Template", "Spec", "TopologySpreadConstraints")
	if !value.IsValid() || value.IsNil() {
		return nil
	}
	return value.Interface().([]corev1.TopologySpreadConstraint)
}

func GetTolerations(overrides any) []corev1.Toleration {
	value := getField(overrides, "Spec", "Template", "Spec", "Tolerations")
	if !value.IsValid() || value.IsNil() {
		return nil
	}
	return value.Interface().([]corev1.Toleration)
}

func GetPriorityClassName(overrides any) string {
	value := getField(overrides, "Spec", "Template", "Spec", "PriorityClassName")
	if !value.IsValid() {
		return ""
	}
	if value.Kind() == reflect.String {
		return value.String()
	}
	return ""
}

// normalizeFieldPath applies type-specific path adjustments before lookup.
// Extracted so test code that wraps getField can reproduce the same path
// transformations when recording.
func normalizeFieldPath(overrides any, fieldNames []string) []string {
	return fieldNames
}

// getField is a var rather than a func so tests can swap in a recording
// wrapper. Production code never replaces it. See recordHandledFields in the
// test file. NOT safe to swap concurrently with calls.
var getField = func(overrides any, fieldNames ...string) (value reflect.Value) {
	fieldNames = normalizeFieldPath(overrides, fieldNames)

	typ := reflect.TypeOf(overrides)
	for _, fieldName := range fieldNames {
		if typ.Kind() == reflect.Pointer {
			typ = typ.Elem()
		}
		field, hasField := typ.FieldByName(fieldName)
		if !hasField {
			return
		}
		typ = field.Type
	}
	value = reflect.ValueOf(overrides)
	for _, fieldName := range fieldNames {
		if value.Kind() == reflect.Pointer {
			if value.IsNil() {
				return
			}
			value = value.Elem()
		}
		value = value.FieldByName(fieldName)
	}
	return
}

// applyReplicatedPodResourceOverrides takes the given replicated pod resource data and applies the overrides.
func applyReplicatedPodResourceOverrides(r *replicatedPodResource, overrides any) *replicatedPodResource {
	// If `overrides` has a Metadata field, and it's non-nil, non-clashing labels and annotations from that
	// metadata are added into `r.labels` and `r.annotations`.
	if metadata := GetMetadata(overrides); metadata != nil {
		if len(metadata.Labels) > 0 {
			r.labels = common.MapExistsOrInitialize(r.labels)
			common.MergeMaps(metadata.Labels, r.labels)
		}
		if len(metadata.Annotations) > 0 {
			r.annotations = common.MapExistsOrInitialize(r.annotations)
			common.MergeMaps(metadata.Annotations, r.annotations)
		}
	}

	// If `overrides` has a Spec.Replicas field. and it's non-nil, it sets
	// `r.replicas`.
	if replicas := GetReplicas(overrides); replicas != nil {
		r.replicas = replicas
	}

	// If `overrides` has a Spec.MinReadySeconds field. and it's non-nil, it sets
	// `r.minReadySeconds`.
	if minReadySeconds := GetMinReadySeconds(overrides); minReadySeconds != nil {
		r.minReadySeconds = minReadySeconds
	}

	// If `overrides` has a Spec.Template.Metadata field, and it's non-nil, non-clashing labels
	// and annotations from that metadata are added into the labels and annotations of
	// `r.podTemplateSpec`.
	if podTemplateMetadata := GetPodTemplateMetadata(overrides); podTemplateMetadata != nil {
		if len(podTemplateMetadata.Labels) > 0 {
			r.podTemplateSpec.Labels = common.MapExistsOrInitialize(r.podTemplateSpec.Labels)
			common.MergeMaps(podTemplateMetadata.Labels, r.podTemplateSpec.Labels)
		}
		if len(podTemplateMetadata.Annotations) > 0 {
			r.podTemplateSpec.Annotations = common.MapExistsOrInitialize(r.podTemplateSpec.Annotations)
			common.MergeMaps(podTemplateMetadata.Annotations, r.podTemplateSpec.Annotations)
		}
	}

	// If `overrides` has a Spec.Template.Spec.TerminationGracePeriodSeconds field, and it's
	// non-nil, it sets the Spec.TerminationGracePeriodSeconds field of `r.podTemplateSpec`.
	if tgp := GetTerminationGracePeriodSeconds(overrides); tgp != nil {
		r.podTemplateSpec.Spec.TerminationGracePeriodSeconds = tgp
	}

	// If `overrides` has a Spec.Strategy.RollingUpdate field, and it's non-nil, it sets
	// `r.deploymentStrategy`.
	if ds := GetDeploymentStrategy(overrides); ds != nil {
		r.deploymentStrategy = ds
	}

	// If `overrides` has a Spec.Template.Spec.InitContainers field, and it includes containers
	// with the same name as those in `r.podTemplateSpec.Spec.InitContainers`, and with non-nil
	// `Resources` or non-nil `Ports`, those attributes replace those for the corresponding container in
	// `r.podTemplateSpec.Spec.InitContainers`.
	if initContainers := GetInitContainers(overrides); initContainers != nil {
		mergeContainers(r.podTemplateSpec.Spec.InitContainers, initContainers)
	}

	// If `overrides` has a Spec.Template.Spec.Containers field, and it includes containers with
	// the same name as those in `r.podTemplateSpec.Spec.Containers`, resources, ports, and
	// probe timing overrides are applied to the corresponding container.
	if cos := GetContainerOverrides(overrides); cos != nil {
		mergeContainerOverrides(r.podTemplateSpec.Spec.Containers, cos)

		// Track which override types were applied for status correlation.
		seen := map[string]bool{}
		var overrideTypes []string
		for _, co := range cos {
			if co.ReadinessProbe != nil && !seen["readinessProbe"] {
				seen["readinessProbe"] = true
				overrideTypes = append(overrideTypes, "readinessProbe")
			}
			if co.LivenessProbe != nil && !seen["livenessProbe"] {
				seen["livenessProbe"] = true
				overrideTypes = append(overrideTypes, "livenessProbe")
			}
			if co.Resources != nil && !seen["resources"] {
				seen["resources"] = true
				overrideTypes = append(overrideTypes, "resources")
			}
		}
		if len(overrideTypes) > 0 {
			r.annotations = common.MapExistsOrInitialize(r.annotations)
			r.annotations[CustomOverridesAnnotation] = strings.Join(overrideTypes, ",")
		}
	}

	// If `overrides` has a Spec.Template.Spec.Affinity field, and it's non-nil, it sets
	// `r.podTemplateSpec.Spec.Affinity`.
	if affinity := GetAffinity(overrides); affinity != nil {
		r.podTemplateSpec.Spec.Affinity = affinity
	}

	// If `overrides` has a Spec.Template.Spec.NodeSelector field, and it's a non-nil map,
	// non-clashing entries from that map are added into `r.podTemplateSpec.Spec.NodeSelector`.
	if nodeSelector := GetNodeSelector(overrides); nodeSelector != nil {
		r.podTemplateSpec.Spec.NodeSelector = common.MapExistsOrInitialize(r.podTemplateSpec.Spec.NodeSelector)
		common.MergeMaps(nodeSelector, r.podTemplateSpec.Spec.NodeSelector)
	}

	// If `overrides` has a Spec.Template.Spec.TopologySpreadConstraints field, and it's
	// non-nil, it sets `r.podTemplateSpec.Spec.TopologySpreadConstraints`.
	if constraints := GetTopologySpreadConstraints(overrides); constraints != nil {
		r.podTemplateSpec.Spec.TopologySpreadConstraints = constraints
	}

	// If `overrides` has a Spec.Template.Spec.Tolerations field, and it's non-nil, it sets
	// `r.podTemplateSpec.Spec.Tolerations`.
	if tolerations := GetTolerations(overrides); tolerations != nil {
		r.podTemplateSpec.Spec.Tolerations = tolerations
	}

	// If `overrides` has a Spec.Template.Spec.PriorityClassName field, and it's non-empty, it
	// sets `r.podTemplateSpec.Spec.PriorityClassName`.
	if priorityClassName := GetPriorityClassName(overrides); priorityClassName != "" {
		r.podTemplateSpec.Spec.PriorityClassName = priorityClassName
	}

	// If `overrides` has a Spec.Template.Spec.HostNetwork field, and it's non-nil, it sets
	// `r.podTemplateSpec.Spec.HostNetwork`.
	if hostNetwork := GetHostNetwork(overrides); hostNetwork != nil {
		r.podTemplateSpec.Spec.HostNetwork = *hostNetwork
	}

	// If `overrides` has a Spec.Template.Spec.DNSPolicy field, and it's non-empty, it sets
	// `r.podTemplateSpec.Spec.DNSPolicy`.
	if dnsPolicy, ok := GetDNSPolicy(overrides); ok {
		r.podTemplateSpec.Spec.DNSPolicy = dnsPolicy
	}

	// If `overrides` has a Spec.Template.Spec.DNSConfig field, and it's non-nil, it sets
	// `r.podTemplateSpec.Spec.DNSConfig`.
	if dnsConfig := GetDNSConfig(overrides); dnsConfig != nil {
		r.podTemplateSpec.Spec.DNSConfig = dnsConfig
	}

	return r
}

// ApplyDaemonSetOverrides applies the overrides to the given DaemonSet.
// Note: overrides must not be nil pointer.
func ApplyDaemonSetOverrides(ds *appsv1.DaemonSet, overrides any) {
	// Catch if caller passes in an explicit nil.
	if overrides == nil {
		return
	}

	// Pull out the data we'll override from the DaemonSet.
	r := &replicatedPodResource{
		labels:          ds.Labels,
		annotations:     ds.Annotations,
		minReadySeconds: &ds.Spec.MinReadySeconds,
		podTemplateSpec: &ds.Spec.Template,
	}
	// Apply the overrides.
	applyReplicatedPodResourceOverrides(r, overrides)

	// Set the possibly new fields back onto the DaemonSet.
	ds.Labels = r.labels
	ds.Annotations = r.annotations
	ds.Spec.MinReadySeconds = *r.minReadySeconds
	ds.Spec.Template = *r.podTemplateSpec
}

// ApplyDeploymentOverrides applies the overrides to the given Deployment.
// Note: overrides must not be nil pointer.
func ApplyDeploymentOverrides(d *appsv1.Deployment, overrides any) {
	// Catch if caller passes in an explicit nil.
	if overrides == nil {
		return
	}

	// Pull out the data we'll override from the Deployment.
	r := &replicatedPodResource{
		labels:             d.Labels,
		annotations:        d.Annotations,
		replicas:           d.Spec.Replicas,
		minReadySeconds:    &d.Spec.MinReadySeconds,
		podTemplateSpec:    &d.Spec.Template,
		deploymentStrategy: &d.Spec.Strategy,
	}
	// Apply the overrides.
	applyReplicatedPodResourceOverrides(r, overrides)

	// Set the possibly new fields back onto the Deployment.
	d.Labels = r.labels
	d.Annotations = r.annotations
	d.Spec.Replicas = r.replicas
	d.Spec.MinReadySeconds = *r.minReadySeconds
	d.Spec.Template = *r.podTemplateSpec
	d.Spec.Strategy = *r.deploymentStrategy
}

// ApplyJobOverrides applies the overrides to the given Job.
func ApplyJobOverrides(job *batchv1.Job, overrides any) {
	// Catch if caller passes in an explicit nil.
	if overrides == nil || job == nil {
		return
	}

	// Pull out the data we'll override from the Job.
	r := &replicatedPodResource{
		labels:          job.Labels,
		annotations:     job.Annotations,
		podTemplateSpec: &job.Spec.Template,
	}
	// Apply the overrides.
	applyReplicatedPodResourceOverrides(r, overrides)

	// Set the possibly new fields back onto the Job.
	job.Labels = r.labels
	job.Annotations = r.annotations
	job.Spec.Template = *r.podTemplateSpec
}

// ApplyPodDisruptionBudgetOverrides applies the overrides to the given PodDisruptionBudget.
// Overrides that are nil leave the corresponding field on the PDB untouched, preserving
// the operator's default. Setting Spec.MinAvailable clears Spec.MaxUnavailable and vice
// versa (the PDB API mandates these are mutually exclusive). The PDB's selector is never
// modified. Labels and annotations from Metadata are merged into the PDB's existing
// labels and annotations.
func ApplyPodDisruptionBudgetOverrides(pdb *policyv1.PodDisruptionBudget, overrides *operator.PodDisruptionBudgetOverride) {
	if pdb == nil || overrides == nil {
		return
	}
	if md := overrides.Metadata; md != nil {
		if len(md.Labels) > 0 {
			pdb.Labels = common.MapExistsOrInitialize(pdb.Labels)
			common.MergeMaps(md.Labels, pdb.Labels)
		}
		if len(md.Annotations) > 0 {
			pdb.Annotations = common.MapExistsOrInitialize(pdb.Annotations)
			common.MergeMaps(md.Annotations, pdb.Annotations)
		}
	}
	spec := overrides.Spec
	if spec == nil {
		return
	}
	if spec.MinAvailable != nil {
		pdb.Spec.MinAvailable = spec.MinAvailable
		pdb.Spec.MaxUnavailable = nil
	}
	if spec.MaxUnavailable != nil {
		pdb.Spec.MaxUnavailable = spec.MaxUnavailable
		pdb.Spec.MinAvailable = nil
	}
	if spec.UnhealthyPodEvictionPolicy != nil {
		pdb.Spec.UnhealthyPodEvictionPolicy = spec.UnhealthyPodEvictionPolicy
	}
}

// ApplyStatefulSetOverrides applies the overrides to the given DaemonSet.
// Note: overrides must not be nil pointer.
func ApplyStatefulSetOverrides(s *appsv1.StatefulSet, overrides any) {
	// Catch if caller passes in an explicit nil.
	if overrides == nil {
		return
	}

	// Pull out the data we'll override from the DaemonSet.
	r := &replicatedPodResource{
		labels:          s.Labels,
		annotations:     s.Annotations,
		minReadySeconds: &s.Spec.MinReadySeconds,
		podTemplateSpec: &s.Spec.Template,
	}
	// Apply the overrides.
	applyReplicatedPodResourceOverrides(r, overrides)

	// Set the possibly new fields back onto the DaemonSet.
	s.Labels = r.labels
	s.Annotations = r.annotations
	s.Spec.MinReadySeconds = *r.minReadySeconds
	s.Spec.Template = *r.podTemplateSpec
}

// ApplyPodTemplateOverrides applies the overrides to the given PodTemplate.
func ApplyPodTemplateOverrides(podtemplate *corev1.PodTemplate, overrides any) {
	// Catch if caller passes in an explicit nil.
	if overrides == nil || podtemplate == nil {
		return
	}

	// Pull out the data we'll override from the PodTemplate.
	r := &replicatedPodResource{
		labels:          podtemplate.Labels,
		annotations:     podtemplate.Annotations,
		podTemplateSpec: &podtemplate.Template,
	}
	// Apply the overrides.
	applyReplicatedPodResourceOverrides(r, overrides)

	// Set the possibly new fields back onto the PodTemplate.
	podtemplate.Labels = r.labels
	podtemplate.Annotations = r.annotations
	podtemplate.Template = *r.podTemplateSpec
}

// ApplyKibanaOverrides applies the overrides to the given Kibana.
// Note: overrides must not be nil pointer.
func ApplyKibanaOverrides(k *kbv1.Kibana, overrides any) {
	// Catch if caller passes in an explicit nil.
	if overrides == nil {
		return
	}

	// Pull out the data we'll override from the DaemonSet.
	r := &replicatedPodResource{
		podTemplateSpec: &k.Spec.PodTemplate,
	}
	// Apply the overrides.
	applyReplicatedPodResourceOverrides(r, overrides)

	// Set the possibly new fields back onto the kibana.
	k.Spec.PodTemplate = *r.podTemplateSpec
}

// ApplyPrometheusOverrides applies the overrides to the given Prometheus.
// Note: overrides must not be nil pointer.
func ApplyPrometheusOverrides(prom *monitoringv1.Prometheus, overrides *operator.Prometheus) {
	// Catch if caller passes in an explicit nil.
	if overrides == nil {
		return
	}

	prometheusFields := &prom.Spec.CommonPrometheusFields

	// Override additional or operator generated containers.
	if containers := overrides.GetContainers(); containers != nil {
		mergeContainers(prometheusFields.Containers, containers)
	}

	// Define resources requests and limits for prometheus Pods.
	if resources := overrides.GetPrometheusResource(); resources != nil {
		prometheusFields.Resources = *resources
	}

	prom.Spec.CommonPrometheusFields = *prometheusFields
}

// mergeContainers copies the ResourceRequirements from the provided containers
// to the current corev1.Containers.
func mergeContainers(current []corev1.Container, provided []corev1.Container) {
	providedMap := make(map[string]corev1.Container)
	for _, c := range provided {
		providedMap[c.Name] = c
	}

	for i, c := range current {
		if override, ok := providedMap[c.Name]; ok {
			if !reflect.DeepEqual(override.Resources, corev1.ResourceRequirements{}) {
				current[i].Resources = override.Resources
			}
			if len(override.Ports) > 0 {
				current[i].Ports = override.Ports
			}
		} else {
			log.V(1).Info(fmt.Sprintf("WARNING: the container %q was provided for an override and passed CRD validation but the container does not currently exist", c.Name))
		}
	}
}

// mergeContainerOverrides applies resource, port, and probe timing overrides
// from the Installation API to the rendered containers.
func mergeContainerOverrides(current []corev1.Container, overrides []containerOverride) {
	overrideMap := make(map[string]containerOverride)
	for _, co := range overrides {
		overrideMap[co.Name] = co
	}

	for i, c := range current {
		co, ok := overrideMap[c.Name]
		if !ok {
			continue
		}
		if co.Resources != nil {
			current[i].Resources = *co.Resources
		}
		if len(co.Ports) > 0 {
			current[i].Ports = co.Ports
		}
		if co.ReadinessProbe != nil && current[i].ReadinessProbe != nil {
			applyProbeOverride(current[i].ReadinessProbe, co.ReadinessProbe)
		}
		if co.LivenessProbe != nil && current[i].LivenessProbe != nil {
			applyProbeOverride(current[i].LivenessProbe, co.LivenessProbe)
		}
	}
}

func applyProbeOverride(probe *corev1.Probe, override *operator.ProbeOverride) {
	if override.PeriodSeconds != nil {
		probe.PeriodSeconds = *override.PeriodSeconds
	}
	if override.TimeoutSeconds != nil {
		probe.TimeoutSeconds = *override.TimeoutSeconds
	}
	if override.FailureThreshold != nil {
		probe.FailureThreshold = *override.FailureThreshold
	}
	if override.InitialDelaySeconds != nil {
		probe.InitialDelaySeconds = *override.InitialDelaySeconds
	}
}

// ClusterRoleBinding returns a cluster role binding with the given name, that binds the given cluster role
// to the service account in each of the provided namespaces.
func ClusterRoleBinding(name, clusterRole, sa string, namespaces []string) *rbacv1.ClusterRoleBinding {
	subjects := []rbacv1.Subject{}
	for _, ns := range namespaces {
		subjects = append(subjects, rbacv1.Subject{
			Kind:      "ServiceAccount",
			Name:      sa,
			Namespace: ns,
		})
	}
	return &rbacv1.ClusterRoleBinding{
		TypeMeta:   metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{Name: name},
		RoleRef: rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "ClusterRole",
			Name:     clusterRole,
		},
		Subjects: subjects,
	}
}

// RoleBinding returns a role binding with the given name, that binds the given cluster role
// to the service account in the provided namespace.
func RoleBinding(name, clusterRole, sa string, namespace string) *rbacv1.RoleBinding {
	return &rbacv1.RoleBinding{
		TypeMeta:   metav1.TypeMeta{Kind: "RoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace},
		RoleRef: rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "ClusterRole",
			Name:     clusterRole,
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      "ServiceAccount",
				Name:      sa,
				Namespace: namespace,
			},
		},
	}
}

// ApplyEnvoyProxyOverrides applies the overrides to the given EnvoyProxy.
// Note: overrides must not be nil pointer.
func ApplyEnvoyProxyOverrides(ep *envoyapi.EnvoyProxy, overrides any) {
	// Catch if caller passes in an explicit nil.
	if overrides == nil {
		return
	}

	// Initialize a pod template spec for the override logic to work on.
	r := &replicatedPodResource{
		podTemplateSpec: &corev1.PodTemplateSpec{
			Spec: corev1.PodSpec{
				Containers: []corev1.Container{{
					Name: "envoy",
				}},
			},
		},
	}
	if ep.Spec.Provider.Kubernetes.EnvoyDaemonSet != nil {
		// EnvoyProxy indicates deployment as a DaemonSet.
		r.podTemplateSpec.Annotations = ep.Spec.Provider.Kubernetes.EnvoyDaemonSet.Pod.Annotations
		r.podTemplateSpec.Labels = ep.Spec.Provider.Kubernetes.EnvoyDaemonSet.Pod.Labels
	} else {
		// Deployment as a Deployment.
		r.podTemplateSpec.Annotations = ep.Spec.Provider.Kubernetes.EnvoyDeployment.Pod.Annotations
		r.podTemplateSpec.Labels = ep.Spec.Provider.Kubernetes.EnvoyDeployment.Pod.Labels
	}

	// Apply the overrides.
	applyReplicatedPodResourceOverrides(r, overrides)

	// Merge overridden fields into the EnvoyProxy.
	if ep.Spec.Provider.Kubernetes.EnvoyDaemonSet != nil {
		// EnvoyProxy indicates deployment as a DaemonSet.
		if r.podTemplateSpec.Annotations != nil {
			ep.Spec.Provider.Kubernetes.EnvoyDaemonSet.Pod.Annotations = r.podTemplateSpec.Annotations
		}
		if r.podTemplateSpec.Labels != nil {
			ep.Spec.Provider.Kubernetes.EnvoyDaemonSet.Pod.Labels = r.podTemplateSpec.Labels
		}
		if r.podTemplateSpec.Spec.Affinity != nil {
			ep.Spec.Provider.Kubernetes.EnvoyDaemonSet.Pod.Affinity = r.podTemplateSpec.Spec.Affinity
		}
		if r.podTemplateSpec.Spec.Tolerations != nil {
			ep.Spec.Provider.Kubernetes.EnvoyDaemonSet.Pod.Tolerations = r.podTemplateSpec.Spec.Tolerations
		}
		if r.podTemplateSpec.Spec.NodeSelector != nil {
			ep.Spec.Provider.Kubernetes.EnvoyDaemonSet.Pod.NodeSelector = r.podTemplateSpec.Spec.NodeSelector
		}
		if r.podTemplateSpec.Spec.TopologySpreadConstraints != nil {
			ep.Spec.Provider.Kubernetes.EnvoyDaemonSet.Pod.TopologySpreadConstraints = r.podTemplateSpec.Spec.TopologySpreadConstraints
		}
		if !reflect.DeepEqual(r.podTemplateSpec.Spec.Containers[0].Resources, corev1.ResourceRequirements{}) {
			ep.Spec.Provider.Kubernetes.EnvoyDaemonSet.Container.Resources = &r.podTemplateSpec.Spec.Containers[0].Resources
		}
	} else {
		// Deployment as a Deployment.
		if r.replicas != nil {
			ep.Spec.Provider.Kubernetes.EnvoyDeployment.Replicas = r.replicas
		}
		if r.deploymentStrategy != nil {
			ep.Spec.Provider.Kubernetes.EnvoyDeployment.Strategy = r.deploymentStrategy
		}
		if r.podTemplateSpec.Annotations != nil {
			ep.Spec.Provider.Kubernetes.EnvoyDeployment.Pod.Annotations = r.podTemplateSpec.Annotations
		}
		if r.podTemplateSpec.Labels != nil {
			ep.Spec.Provider.Kubernetes.EnvoyDeployment.Pod.Labels = r.podTemplateSpec.Labels
		}
		if r.podTemplateSpec.Spec.Affinity != nil {
			ep.Spec.Provider.Kubernetes.EnvoyDeployment.Pod.Affinity = r.podTemplateSpec.Spec.Affinity
		}
		if r.podTemplateSpec.Spec.Tolerations != nil {
			ep.Spec.Provider.Kubernetes.EnvoyDeployment.Pod.Tolerations = r.podTemplateSpec.Spec.Tolerations
		}
		if r.podTemplateSpec.Spec.NodeSelector != nil {
			ep.Spec.Provider.Kubernetes.EnvoyDeployment.Pod.NodeSelector = r.podTemplateSpec.Spec.NodeSelector
		}
		if r.podTemplateSpec.Spec.TopologySpreadConstraints != nil {
			ep.Spec.Provider.Kubernetes.EnvoyDeployment.Pod.TopologySpreadConstraints = r.podTemplateSpec.Spec.TopologySpreadConstraints
		}
		if !reflect.DeepEqual(r.podTemplateSpec.Spec.Containers[0].Resources, corev1.ResourceRequirements{}) {
			ep.Spec.Provider.Kubernetes.EnvoyDeployment.Container.Resources = &r.podTemplateSpec.Spec.Containers[0].Resources
		}
	}
}
