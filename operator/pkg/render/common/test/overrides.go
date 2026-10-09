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

package test

import (
	"fmt"
	"reflect"
	"strings"

	envoyapi "github.com/envoyproxy/gateway/api/v1alpha1"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	apiextenv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"

	operatorv1 "github.com/projectcalico/calico/operator/api/v1"
	"github.com/projectcalico/calico/operator/pkg/crds"
)

// The sentinel values FillOverrides writes. Each differs from anything a component
// renders by default, so finding one on a rendered object proves the override landed.
const (
	sentinelKey             = "override-test"
	sentinelMinReadySeconds = int32(17)
	sentinelReplicas        = int32(3)
	sentinelGracePeriod     = int64(99)
	sentinelProbePeriod     = int32(42)
	sentinelPort            = int32(7777)
	sentinelPriorityClass   = "override-test"
	sentinelNameserver      = "10.0.0.10"
)

var (
	sentinelResources = corev1.ResourceRequirements{
		Requests: corev1.ResourceList{corev1.ResourceCPU: resource.MustParse("777m"), corev1.ResourceMemory: resource.MustParse("77Mi")},
		Limits:   corev1.ResourceList{corev1.ResourceCPU: resource.MustParse("778m"), corev1.ResourceMemory: resource.MustParse("78Mi")},
	}
	sentinelMaxUnavailable = intstr.FromInt32(5)
	sentinelAffinity       = corev1.Affinity{
		NodeAffinity: &corev1.NodeAffinity{
			RequiredDuringSchedulingIgnoredDuringExecution: &corev1.NodeSelector{
				NodeSelectorTerms: []corev1.NodeSelectorTerm{{
					MatchExpressions: []corev1.NodeSelectorRequirement{{Key: sentinelKey, Operator: corev1.NodeSelectorOpExists}},
				}},
			},
		},
	}
	sentinelTolerations = []corev1.Toleration{{Key: sentinelKey, Operator: corev1.TolerationOpExists}}
	sentinelSpread      = []corev1.TopologySpreadConstraint{{MaxSkew: 1, TopologyKey: sentinelKey, WhenUnsatisfiable: corev1.DoNotSchedule}}
)

// FilledOverrides records what FillOverrides set, so ExpectOverridesApplied
// checks exactly those fields and nothing the override type lacks.
type FilledOverrides struct {
	Fields          map[string]bool
	Containers      []string
	InitContainers  []string
	ContainerPorts  bool
	ContainerProbes map[string]bool
}

// FillOverrides sets every field of the override that field points at, such as
// &installation.CalicoNodeDaemonSet, to a sentinel. A field without a sentinel
// fails the test, so a new override field can't go uncovered.
func FillOverrides(field any, containers, initContainers []string) FilledOverrides {
	ptrVal := reflect.ValueOf(field)
	ExpectWithOffset(1, ptrVal.Kind()).To(Equal(reflect.Pointer), "field must point at the override field")
	slot := ptrVal.Elem()
	ExpectWithOffset(1, slot.Kind()).To(Equal(reflect.Pointer), "the override field must be a pointer to a struct")

	f := FilledOverrides{
		Fields:          map[string]bool{},
		Containers:      containers,
		InitContainers:  initContainers,
		ContainerProbes: map[string]bool{},
	}
	o := reflect.New(slot.Type().Elem())
	f.fillStruct(o.Elem(), "")
	slot.Set(o)
	return f
}

func (f *FilledOverrides) fillStruct(v reflect.Value, prefix string) {
	for i := range v.NumField() {
		name := prefix + v.Type().Field(i).Name
		fieldValue := v.Field(i)
		switch name {
		case "Metadata", "Spec.Template.Metadata":
			fieldValue.Set(reflect.ValueOf(&operatorv1.Metadata{
				Labels:      map[string]string{sentinelKey: name},
				Annotations: map[string]string{sentinelKey: name},
			}))
		case "Spec", "Spec.Template", "Spec.Template.Spec", "Spec.Strategy":
			n := reflect.New(fieldValue.Type().Elem())
			f.fillStruct(n.Elem(), name+".")
			fieldValue.Set(n)
		case "Spec.MinReadySeconds":
			fieldValue.Set(reflect.ValueOf(ptr.To(sentinelMinReadySeconds)))
		case "Spec.Replicas":
			fieldValue.Set(reflect.ValueOf(ptr.To(sentinelReplicas)))
		case "Spec.Strategy.RollingUpdate":
			fieldValue.Set(reflect.ValueOf(&appsv1.RollingUpdateDeployment{MaxUnavailable: &sentinelMaxUnavailable}))
		case "Spec.Template.Spec.Containers":
			fieldValue.Set(f.containerList(fieldValue.Type(), f.Containers))
		case "Spec.Template.Spec.InitContainers":
			fieldValue.Set(f.containerList(fieldValue.Type(), f.InitContainers))
		case "Spec.Template.Spec.Affinity":
			fieldValue.Set(reflect.ValueOf(sentinelAffinity.DeepCopy()))
		case "Spec.Template.Spec.NodeSelector":
			fieldValue.Set(reflect.ValueOf(map[string]string{sentinelKey: "selector"}))
		case "Spec.Template.Spec.Tolerations":
			fieldValue.Set(reflect.ValueOf(sentinelTolerations))
		case "Spec.Template.Spec.TopologySpreadConstraints":
			fieldValue.Set(reflect.ValueOf(sentinelSpread))
		case "Spec.Template.Spec.PriorityClassName":
			fieldValue.SetString(sentinelPriorityClass)
		case "Spec.Template.Spec.TerminationGracePeriodSeconds":
			fieldValue.Set(reflect.ValueOf(ptr.To(sentinelGracePeriod)))
		case "Spec.Template.Spec.Resources":
			fieldValue.Set(reflect.ValueOf(sentinelResources.DeepCopy()))
		case "Spec.Template.Spec.HostNetwork":
			fieldValue.Set(reflect.ValueOf(ptr.To(false)))
		case "Spec.Template.Spec.DNSPolicy":
			fieldValue.Set(reflect.ValueOf(ptr.To(corev1.DNSDefault)))
		case "Spec.Template.Spec.DNSConfig":
			fieldValue.Set(reflect.ValueOf(&corev1.PodDNSConfig{Nameservers: []string{sentinelNameserver}}))
		default:
			Fail(fmt.Sprintf("no sentinel for override field %s on %s; add one to FillOverrides", name, v.Type()))
		}
		f.Fields[name] = true
	}
}

// containerList builds one override entry per name, setting every field the
// entry type has.
func (f *FilledOverrides) containerList(t reflect.Type, names []string) reflect.Value {
	list := reflect.MakeSlice(t, 0, len(names))
	for _, n := range names {
		entry := reflect.New(t.Elem()).Elem()
		for i := range entry.NumField() {
			fv := entry.Field(i)
			switch fname := entry.Type().Field(i).Name; fname {
			case "Name":
				fv.SetString(n)
			case "Resources":
				fv.Set(reflect.ValueOf(sentinelResources.DeepCopy()))
			case "Ports":
				port := reflect.New(fv.Type().Elem()).Elem()
				port.FieldByName("ContainerPort").SetInt(int64(sentinelPort))
				fv.Set(reflect.Append(reflect.MakeSlice(fv.Type(), 0, 1), port))
				f.ContainerPorts = true
			case "ReadinessProbe", "LivenessProbe", "StartupProbe":
				fv.Set(reflect.ValueOf(&operatorv1.ProbeOverride{PeriodSeconds: ptr.To(sentinelProbePeriod)}))
				f.ContainerProbes[fname] = true
			default:
				Fail(fmt.Sprintf("no sentinel for container override field %s on %s; add one to FillOverrides", fname, t.Elem()))
			}
		}
		list = reflect.Append(list, entry)
	}
	return list
}

// renderedWorkload is the part of a rendered object that overrides reach.
type renderedWorkload struct {
	labels          map[string]string
	annotations     map[string]string
	replicas        *int32
	minReadySeconds *int32
	strategy        *appsv1.DeploymentStrategy
	template        *corev1.PodTemplateSpec
}

func workloadOf(obj client.Object) renderedWorkload {
	switch o := obj.(type) {
	case *appsv1.DaemonSet:
		return renderedWorkload{o.Labels, o.Annotations, nil, &o.Spec.MinReadySeconds, nil, &o.Spec.Template}
	case *appsv1.Deployment:
		return renderedWorkload{o.Labels, o.Annotations, o.Spec.Replicas, &o.Spec.MinReadySeconds, &o.Spec.Strategy, &o.Spec.Template}
	case *batchv1.Job:
		return renderedWorkload{o.Labels, o.Annotations, nil, nil, nil, &o.Spec.Template}
	case *envoyapi.EnvoyProxy:
		return envoyWorkloadOf(o)
	}
	Fail(fmt.Sprintf("no override check for %T", obj))
	return renderedWorkload{}
}

// envoyWorkloadOf rebuilds the pod template the EnvoyProxy overrides write into.
func envoyWorkloadOf(ep *envoyapi.EnvoyProxy) renderedWorkload {
	k := ep.Spec.Provider.Kubernetes
	template := &corev1.PodTemplateSpec{}
	var replicas *int32
	var strategy *appsv1.DeploymentStrategy
	var pod *envoyapi.KubernetesPodSpec
	var container *envoyapi.KubernetesContainerSpec
	if ds := k.EnvoyDaemonSet; ds != nil {
		pod, container = ds.Pod, ds.Container
	} else if dep := k.EnvoyDeployment; dep != nil {
		pod, container, replicas, strategy = dep.Pod, dep.Container, dep.Replicas, dep.Strategy
	}
	if pod != nil {
		template.Labels, template.Annotations = pod.Labels, pod.Annotations
		template.Spec.Affinity, template.Spec.NodeSelector, template.Spec.Tolerations = pod.Affinity, pod.NodeSelector, pod.Tolerations
		template.Spec.TopologySpreadConstraints = pod.TopologySpreadConstraints
		template.Spec.PriorityClassName = ptr.Deref(pod.PriorityClassName, "")
	}
	if container != nil {
		envoy := corev1.Container{Name: "envoy"}
		if container.Resources != nil {
			envoy.Resources = *container.Resources
		}
		template.Spec.Containers = []corev1.Container{envoy}
	}
	return renderedWorkload{template: template, replicas: replicas, strategy: strategy}
}

// ExpectOverridesApplied checks every field f filled on the rendered object and
// returns the override container names it found rendered there. aliases maps an
// override name to the container name the component renders for it.
func ExpectOverridesApplied(obj client.Object, f FilledOverrides, aliases map[string]string) []string {
	workload := workloadOf(obj)
	where := fmt.Sprintf("%T %s", obj, obj.GetName())
	for field := range f.Fields {
		desc := fmt.Sprintf("override %s on %s", field, where)
		spec := &workload.template.Spec
		switch field {
		case "Metadata":
			ExpectWithOffset(1, workload.labels).To(HaveKeyWithValue(sentinelKey, field), desc)
			ExpectWithOffset(1, workload.annotations).To(HaveKeyWithValue(sentinelKey, field), desc)
		case "Spec.Template.Metadata":
			ExpectWithOffset(1, workload.template.Labels).To(HaveKeyWithValue(sentinelKey, field), desc)
			ExpectWithOffset(1, workload.template.Annotations).To(HaveKeyWithValue(sentinelKey, field), desc)
		case "Spec.MinReadySeconds":
			ExpectWithOffset(1, workload.minReadySeconds).To(HaveValue(Equal(sentinelMinReadySeconds)), desc)
		case "Spec.Replicas":
			ExpectWithOffset(1, workload.replicas).To(HaveValue(Equal(sentinelReplicas)), desc)
		case "Spec.Strategy.RollingUpdate":
			ExpectWithOffset(1, workload.strategy).NotTo(BeNil(), desc)
			ExpectWithOffset(1, workload.strategy.RollingUpdate).NotTo(BeNil(), desc)
			ExpectWithOffset(1, workload.strategy.RollingUpdate.MaxUnavailable).To(HaveValue(Equal(sentinelMaxUnavailable)), desc)
		case "Spec.Template.Spec.Affinity":
			ExpectWithOffset(1, spec.Affinity).To(Equal(&sentinelAffinity), desc)
		case "Spec.Template.Spec.NodeSelector":
			ExpectWithOffset(1, spec.NodeSelector).To(HaveKeyWithValue(sentinelKey, "selector"), desc)
		case "Spec.Template.Spec.Tolerations":
			ExpectWithOffset(1, spec.Tolerations).To(Equal(sentinelTolerations), desc)
		case "Spec.Template.Spec.TopologySpreadConstraints":
			ExpectWithOffset(1, spec.TopologySpreadConstraints).To(Equal(sentinelSpread), desc)
		case "Spec.Template.Spec.PriorityClassName":
			ExpectWithOffset(1, spec.PriorityClassName).To(Equal(sentinelPriorityClass), desc)
		case "Spec.Template.Spec.TerminationGracePeriodSeconds":
			ExpectWithOffset(1, spec.TerminationGracePeriodSeconds).To(HaveValue(Equal(sentinelGracePeriod)), desc)
		case "Spec.Template.Spec.Resources":
			for _, c := range spec.Containers {
				ExpectWithOffset(1, c.Resources).To(Equal(sentinelResources), "%s, container %s", desc, c.Name)
			}
		case "Spec.Template.Spec.HostNetwork":
			ExpectWithOffset(1, spec.HostNetwork).To(BeFalse(), desc)
		case "Spec.Template.Spec.DNSPolicy":
			ExpectWithOffset(1, spec.DNSPolicy).To(Equal(corev1.DNSDefault), desc)
		case "Spec.Template.Spec.DNSConfig":
			ExpectWithOffset(1, spec.DNSConfig).To(Equal(&corev1.PodDNSConfig{Nameservers: []string{sentinelNameserver}}), desc)
		}
	}

	var found []string
	for _, n := range f.Containers {
		c, ok := findContainer(workload.template.Spec.Containers, resolveAlias(n, aliases))
		if !ok {
			continue
		}
		found = append(found, n)
		desc := fmt.Sprintf("container override %q on %s", n, where)
		ExpectWithOffset(1, c.Resources).To(Equal(sentinelResources), desc)
		if f.ContainerPorts {
			ExpectWithOffset(1, c.Ports).To(ConsistOf(HaveField("ContainerPort", sentinelPort)), desc)
		}
		probes := map[string]*corev1.Probe{
			"ReadinessProbe": c.ReadinessProbe,
			"LivenessProbe":  c.LivenessProbe,
			"StartupProbe":   c.StartupProbe,
		}
		for name, p := range probes {
			if p != nil && f.ContainerProbes[name] {
				ExpectWithOffset(1, p.PeriodSeconds).To(Equal(sentinelProbePeriod), "%s %s", desc, name)
			}
		}
	}
	for _, n := range f.InitContainers {
		c, ok := findContainer(workload.template.Spec.InitContainers, resolveAlias(n, aliases))
		if !ok {
			continue
		}
		found = append(found, n)
		ExpectWithOffset(1, c.Resources).To(Equal(sentinelResources), fmt.Sprintf("init container override %q on %s", n, where))
	}
	return found
}

func resolveAlias(name string, aliases map[string]string) string {
	if a, ok := aliases[name]; ok {
		return a
	}
	return name
}

func findContainer(cs []corev1.Container, name string) (corev1.Container, bool) {
	for _, c := range cs {
		if c.Name == name {
			return c, true
		}
	}
	return corev1.Container{}, false
}

// CRDContainerNames returns the container and init container names the CRD's
// schema allows under the override at path, such as "spec.calicoNodeDaemonSet".
// A "[]" path element steps into a list's items.
func CRDContainerNames(variant operatorv1.ProductVariant, crdName, path string) ([]string, []string) {
	var crd *apiextenv1.CustomResourceDefinition
	for _, c := range crds.GetCRDs(variant, true) {
		if c.Name == crdName {
			crd = c
		}
	}
	ExpectWithOffset(1, crd).NotTo(BeNil(), "no CRD %s", crdName)
	schema := crd.Spec.Versions[0].Schema.OpenAPIV3Schema
	for _, p := range strings.Split(path+".spec.template.spec", ".") {
		if p == "[]" {
			schema = schema.Items.Schema
			continue
		}
		next, ok := schema.Properties[p]
		if !ok {
			// The override has no pod template spec, so no container names.
			return nil, nil
		}
		schema = &next
	}
	return enumNames(schema, "containers"), enumNames(schema, "initContainers")
}

func enumNames(podSpec *apiextenv1.JSONSchemaProps, field string) []string {
	list, ok := podSpec.Properties[field]
	if !ok || list.Items == nil || list.Items.Schema == nil {
		return nil
	}
	var names []string
	for _, e := range list.Items.Schema.Properties["name"].Enum {
		names = append(names, strings.Trim(string(e.Raw), `"`))
	}
	return names
}
