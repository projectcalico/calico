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
	"reflect"
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	v1 "github.com/tigera/operator/api/v1"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	policyv1 "k8s.io/api/policy/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/utils/ptr"

	"github.com/tigera/operator/test"
)

var _ = Describe("Common components render tests", func() {
	var three int32
	var resources1 corev1.ResourceRequirements
	var resources2 corev1.ResourceRequirements
	var resources3 corev1.ResourceRequirements
	var affinity corev1.Affinity
	var nodeSelector map[string]string
	var tolerations []corev1.Toleration

	BeforeEach(func() {
		three = 3
		resources1 = corev1.ResourceRequirements{
			Limits: corev1.ResourceList{
				"cpu":     resource.MustParse("2"),
				"memory":  resource.MustParse("300Mi"),
				"storage": resource.MustParse("20Gi"),
			},
			Requests: corev1.ResourceList{
				"cpu":     resource.MustParse("1"),
				"memory":  resource.MustParse("150Mi"),
				"storage": resource.MustParse("10Gi"),
			},
		}
		resources2 = corev1.ResourceRequirements{
			Limits: corev1.ResourceList{
				"cpu":    resource.MustParse("2"),
				"memory": resource.MustParse("2000Mi"),
			},
			Requests: corev1.ResourceList{
				"cpu":    resource.MustParse("2"),
				"memory": resource.MustParse("2000Mi"),
			},
		}
		resources3 = corev1.ResourceRequirements{
			Limits: corev1.ResourceList{
				"storage": resource.MustParse("10Gi"),
			},
			Requests: corev1.ResourceList{
				"storage": resource.MustParse("10Gi"),
			},
		}
		affinity = corev1.Affinity{
			NodeAffinity: &corev1.NodeAffinity{
				RequiredDuringSchedulingIgnoredDuringExecution: &corev1.NodeSelector{
					NodeSelectorTerms: []corev1.NodeSelectorTerm{{
						MatchExpressions: []corev1.NodeSelectorRequirement{{
							Key:      "custom-affinity-key",
							Operator: corev1.NodeSelectorOpExists,
						}},
					}},
				},
			},
		}
		nodeSelector = map[string]string{
			"not-zero":        "an override of a default nodeSelector key",
			"custom-selector": "value",
		}
		tolerations = []corev1.Toleration{
			{
				Key:      "foo",
				Operator: corev1.TolerationOpEqual,
				Value:    "bar",
			},
		}
	})

	var findUnhandled func(handledFields []string, prefix string, typ reflect.Type) (unhandledFields []string)
	findUnhandled = func(handledFields []string, prefix string, typ reflect.Type) (unhandledFields []string) {
		for typ.Kind() == reflect.Pointer || typ.Kind() == reflect.Slice {
			typ = typ.Elem()
		}
		if typ.Kind() == reflect.Struct {
			numFields := typ.NumField()
		nextField:
			for i := 0; i < numFields; i++ {
				fullName := prefix + typ.Field(i).Name
				isPrefix := false
				for _, handledField := range handledFields {
					if fullName == handledField {
						// The current dotted field name is
						// one that we handle.
						continue nextField
					}
					if strings.HasPrefix(handledField, fullName) {
						isPrefix = true
					}
				}
				if isPrefix {
					// The current dotted field name is a prefix
					// of (at least) one that we handle.
					// Recurse to check its sub-fields.
					unhandledFields = append(unhandledFields, findUnhandled(handledFields, fullName+".", typ.Field(i).Type)...)
				} else {
					// The current dotted field name isn't
					// handled itself, and isn't a prefix
					// either, so it must be unhandled.
					unhandledFields = append(unhandledFields, fullName)
				}
			}
		}
		return
	}

	DescribeTable("check for unhandled fields",
		func(overrides any, expectUnhandled bool, allowedExtraFields ...string) {
			// Wrap getField so we can observe which paths the production
			// code accesses, then run it to discover all the fields that
			// we handle.
			recorded, restore := recordHandledFields()
			defer restore()
			r := &replicatedPodResource{}
			applyReplicatedPodResourceOverrides(r, overrides)
			handledFields := append(recorded(), allowedExtraFields...)

			// Now traverse the structure to find any unhandled fields.
			unhandledFields := findUnhandled(handledFields, "", reflect.TypeOf(overrides))
			if expectUnhandled {
				Expect(unhandledFields).NotTo(BeEmpty())
			} else {
				Expect(unhandledFields).To(BeEmpty())
			}
		},
		Entry("APIServerDeployment", &v1.APIServerDeployment{}, false),
		Entry("CalicoKubeControllersDeployment", &v1.CalicoKubeControllersDeployment{}, false),
		Entry("CalicoWebhooksDeployment", &v1.CalicoWebhooksDeployment{}, false),
		Entry("CalicoNodeDaemonSet", &v1.CalicoNodeDaemonSet{}, false),
		Entry("CalicoNodeWindowsDaemonSet", &v1.CalicoNodeWindowsDaemonSet{}, false),
		Entry("CalicoWindowsUpgradeDaemonSet", &v1.CalicoWindowsUpgradeDaemonSet{}, false),
		Entry("CSINodeDriverDaemonSet", &v1.CSINodeDriverDaemonSet{}, false),
		Entry("DashboardsJob", &v1.DashboardsJob{}, false),
		Entry("DexDeployment", &v1.DexDeployment{}, false),
		Entry("ECKOperatorStatefulSet", &v1.ECKOperatorStatefulSet{}, false),
		// EgressGateway operates as a top-level CR and also as its own customization
		// structure, so it does have fields other than those covered by the override
		// machinery.
		Entry("EgressGateway", &v1.EgressGateway{}, false,
			"TypeMeta",
			"ObjectMeta",
			"Spec.Replicas",
			"Spec.IPPools",
			"Spec.ExternalNetworks",
			"Spec.LogSeverity",
			"Spec.EgressGatewayFailureDetection",
			"Spec.AWS",
			"Status",
		),
		Entry("EKSLogForwarderDeployment", &v1.EKSLogForwarderDeployment{}, false),
		Entry("ElasticsearchMetricsDeployment", &v1.ElasticsearchMetricsDeployment{}, false),
		Entry("ESGatewayDeployment", &v1.ESGatewayDeployment{}, false),
		Entry("FluentBitDaemonSet", &v1.FluentBitDaemonSet{}, false),
		Entry("GatewayCertgenJob", &v1.GatewayCertgenJob{}, false),
		Entry("GatewayControllerDeployment", &v1.GatewayControllerDeployment{}, false),
		Entry("GatewayDeployment", &v1.GatewayDeployment{}, false),
		Entry("GuardianDeployment", &v1.GuardianDeployment{}, false),
		Entry("IntrusionDetectionControllerDeployment", &v1.IntrusionDetectionControllerDeployment{}, false),
		Entry("Kibana", &v1.Kibana{}, false),
		Entry("L7LogCollectorDaemonSet", &v1.L7LogCollectorDaemonSet{}, false),
		Entry("LinseedDeployment", &v1.LinseedDeployment{}, false),
		Entry("ManagerDeployment", &v1.ManagerDeployment{}, false),
		Entry("PacketCaptureAPIDeployment", &v1.PacketCaptureAPIDeployment{}, false),
		Entry("PolicyRecommendationDeployment", &v1.PolicyRecommendationDeployment{}, false),
		Entry("TyphaDeployment", &v1.TyphaDeployment{}, false),

		// This last entry checks that the code above really does identify when a
		// structure has unhandled fields.  To do this we can use any available structure
		// with some field names that don't overlap with those that are handled by our
		// override code.
		Entry("Installation", &v1.Installation{}, true),
	)

	DescribeTable("test ApplyDaemonSetOverrides",
		func(original func() appsv1.DaemonSet, override func() *v1.CalicoNodeDaemonSet, expectations func(set appsv1.DaemonSet)) {
			orig := original()
			template := override()
			ApplyDaemonSetOverrides(&orig, template)
			expectations(orig)
		},

		Entry("empty",
			defaultedDaemonSet,
			func() *v1.CalicoNodeDaemonSet {
				return &v1.CalicoNodeDaemonSet{}
			},
			func(result appsv1.DaemonSet) {
				Expect(result).To(Equal(defaultedDaemonSet()))
			}),

		Entry("empty labels and annotations",
			defaultedDaemonSet,
			func() *v1.CalicoNodeDaemonSet {
				return &v1.CalicoNodeDaemonSet{
					Metadata: &v1.Metadata{
						Labels:      map[string]string{},
						Annotations: nil,
					},
				}
			},
			func(result appsv1.DaemonSet) {
				Expect(result).To(Equal(defaultedDaemonSet()))
			}),

		Entry("empty labels and annotations, empty spec",
			defaultedDaemonSet,
			func() *v1.CalicoNodeDaemonSet {
				return &v1.CalicoNodeDaemonSet{
					Metadata: &v1.Metadata{
						Labels:      map[string]string{},
						Annotations: map[string]string{},
					},
					Spec: &v1.CalicoNodeDaemonSetSpec{},
				}
			},
			func(result appsv1.DaemonSet) {
				Expect(result).To(Equal(defaultedDaemonSet()))
			}),

		Entry("labels and annotations",
			defaultedDaemonSet,
			func() *v1.CalicoNodeDaemonSet {
				return &v1.CalicoNodeDaemonSet{
					Metadata: &v1.Metadata{
						Labels:      map[string]string{"test-label": "label1"},
						Annotations: map[string]string{"test-annot": "annot1"},
					},
					Spec: nil,
				}
			},
			func(result appsv1.DaemonSet) {
				expected := defaultedDaemonSet()
				expected.Labels["test-label"] = "label1"
				expected.Annotations["test-annot"] = "annot1"
				Expect(result).To(Equal(expected))
			}),
		Entry("labels only",
			defaultedDaemonSet,
			func() *v1.CalicoNodeDaemonSet {
				return &v1.CalicoNodeDaemonSet{
					Metadata: &v1.Metadata{
						Labels: map[string]string{"test-label": "label1"},
					},
					Spec: nil,
				}
			},
			func(result appsv1.DaemonSet) {
				expected := defaultedDaemonSet()
				expected.Labels["test-label"] = "label1"
				Expect(result).To(Equal(expected))
			}),
		Entry("annotations only",
			defaultedDaemonSet,
			func() *v1.CalicoNodeDaemonSet {
				return &v1.CalicoNodeDaemonSet{
					Metadata: &v1.Metadata{
						Annotations: map[string]string{"test-annot": "annot1"},
					},
					Spec: nil,
				}
			},
			func(result appsv1.DaemonSet) {
				expected := defaultedDaemonSet()
				expected.Annotations["test-annot"] = "annot1"
				Expect(result).To(Equal(expected))
			}),
		Entry("labels and annotations that are already defined",
			defaultedDaemonSet,
			func() *v1.CalicoNodeDaemonSet {
				return &v1.CalicoNodeDaemonSet{
					Metadata: &v1.Metadata{
						// "not-zero" label and annotation keys exist in the defaulted calico node.
						Labels: map[string]string{
							"test-label": "label1",
							"not-zero":   "not-zero",
						},
						Annotations: map[string]string{
							"not-zero":   "not-zero",
							"test-annot": "annot1",
						},
					},
				}
			},
			func(result appsv1.DaemonSet) {
				expected := defaultedDaemonSet()
				// Only the labels and annotations that don't clobber existing keys are added.
				expected.Labels["test-label"] = "label1"
				expected.Annotations["test-annot"] = "annot1"
				Expect(result).To(Equal(expected))
			}),
		Entry("labels that are already defined",
			defaultedDaemonSet,
			func() *v1.CalicoNodeDaemonSet {
				return &v1.CalicoNodeDaemonSet{
					Metadata: &v1.Metadata{
						// "not-zero" label keys exist in the defaulted calico node.
						Labels: map[string]string{
							"test-label": "label1",
							"not-zero":   "not-zero",
						},
					},
				}
			},
			func(result appsv1.DaemonSet) {
				expected := defaultedDaemonSet()
				// Only the labels that don't clobber existing keys are added.
				expected.Labels["test-label"] = "label1"
				Expect(result).To(Equal(expected))
			}),
		Entry("annotations that are already defined",
			defaultedDaemonSet,
			func() *v1.CalicoNodeDaemonSet {
				return &v1.CalicoNodeDaemonSet{
					Metadata: &v1.Metadata{
						// "not-zero" annotation keys exist in the defaulted calico node.
						Annotations: map[string]string{
							"not-zero":   "not-zero",
							"test-annot": "annot1",
						},
					},
				}
			},
			func(result appsv1.DaemonSet) {
				expected := defaultedDaemonSet()
				// Only the annotations that don't clobber existing keys are added.
				expected.Annotations["test-annot"] = "annot1"
				Expect(result).To(Equal(expected))
			}),
		Entry("DNSPolicy that is defined",
			defaultedDaemonSet,
			func() *v1.CalicoNodeDaemonSet {
				return &v1.CalicoNodeDaemonSet{
					Spec: &v1.CalicoNodeDaemonSetSpec{
						Template: &v1.CalicoNodeDaemonSetPodTemplateSpec{
							Spec: &v1.CalicoNodeDaemonSetPodSpec{
								DNSPolicy: ptr.To(corev1.DNSClusterFirstWithHostNet),
							},
						},
					},
				}
			},
			func(result appsv1.DaemonSet) {
				Expect(result.Spec.Template.Spec.DNSPolicy).To(Equal(corev1.DNSClusterFirstWithHostNet))
			}),

		Entry("minReadySeconds",
			defaultedDaemonSet,
			func() *v1.CalicoNodeDaemonSet {
				return &v1.CalicoNodeDaemonSet{
					Spec: &v1.CalicoNodeDaemonSetSpec{
						MinReadySeconds: &three,
					},
				}
			},
			func(result appsv1.DaemonSet) {
				expected := defaultedDaemonSet()
				expected.Spec.MinReadySeconds = three
				Expect(result).To(Equal(expected))
			}),
		Entry("pod template labels and annotations",
			defaultedDaemonSet,
			func() *v1.CalicoNodeDaemonSet {
				return &v1.CalicoNodeDaemonSet{
					Spec: &v1.CalicoNodeDaemonSetSpec{
						Template: &v1.CalicoNodeDaemonSetPodTemplateSpec{
							Metadata: &v1.Metadata{
								Labels:      map[string]string{"test-pod-label": "label1"},
								Annotations: map[string]string{"test-pod-annot": "annot1"},
							},
						},
					},
				}
			},
			func(result appsv1.DaemonSet) {
				expected := defaultedDaemonSet()
				expected.Spec.Template.Labels["test-pod-label"] = "label1"
				expected.Spec.Template.Annotations["test-pod-annot"] = "annot1"
				Expect(result).To(Equal(expected))
			}),

		Entry("pod template labels only",
			defaultedDaemonSet,
			func() *v1.CalicoNodeDaemonSet {
				return &v1.CalicoNodeDaemonSet{
					Spec: &v1.CalicoNodeDaemonSetSpec{
						Template: &v1.CalicoNodeDaemonSetPodTemplateSpec{
							Metadata: &v1.Metadata{
								Labels: map[string]string{"test-pod-label": "label1"},
							},
						},
					},
				}
			},
			func(result appsv1.DaemonSet) {
				expected := defaultedDaemonSet()
				expected.Spec.Template.Labels["test-pod-label"] = "label1"
				Expect(result).To(Equal(expected))
			}),

		Entry("pod template annotations only",
			defaultedDaemonSet,
			func() *v1.CalicoNodeDaemonSet {
				return &v1.CalicoNodeDaemonSet{
					Spec: &v1.CalicoNodeDaemonSetSpec{
						Template: &v1.CalicoNodeDaemonSetPodTemplateSpec{
							Metadata: &v1.Metadata{
								Annotations: map[string]string{"test-pod-annot": "annot1"},
							},
						},
					},
				}
			},
			func(result appsv1.DaemonSet) {
				expected := defaultedDaemonSet()
				expected.Spec.Template.Annotations["test-pod-annot"] = "annot1"
				Expect(result).To(Equal(expected))
			}),

		Entry("pod labels and annotations that are already defined",
			defaultedDaemonSet,
			func() *v1.CalicoNodeDaemonSet {
				return &v1.CalicoNodeDaemonSet{
					Spec: &v1.CalicoNodeDaemonSetSpec{
						Template: &v1.CalicoNodeDaemonSetPodTemplateSpec{
							Metadata: &v1.Metadata{
								Labels: map[string]string{
									"test-pod-label": "label1",
									"not-zero":       "wont-work",
								},
								Annotations: map[string]string{
									"not-zero":       "wont-work",
									"test-pod-annot": "annot1",
								},
							},
						},
					},
				}
			},
			func(result appsv1.DaemonSet) {
				expected := defaultedDaemonSet()
				expected.Spec.Template.Labels["test-pod-label"] = "label1"
				expected.Spec.Template.Annotations["test-pod-annot"] = "annot1"
				Expect(result).To(Equal(expected))
			}),

		Entry("pod labels that are already defined",
			defaultedDaemonSet,
			func() *v1.CalicoNodeDaemonSet {
				return &v1.CalicoNodeDaemonSet{
					Spec: &v1.CalicoNodeDaemonSetSpec{
						Template: &v1.CalicoNodeDaemonSetPodTemplateSpec{
							Metadata: &v1.Metadata{
								Labels: map[string]string{
									"test-pod-label": "label1",
									"not-zero":       "wont-work",
								},
							},
						},
					},
				}
			},
			func(result appsv1.DaemonSet) {
				expected := defaultedDaemonSet()
				expected.Spec.Template.Labels["test-pod-label"] = "label1"
				Expect(result).To(Equal(expected))
			}),

		Entry("pod annotations that are already defined",
			defaultedDaemonSet,
			func() *v1.CalicoNodeDaemonSet {
				return &v1.CalicoNodeDaemonSet{
					Spec: &v1.CalicoNodeDaemonSetSpec{
						Template: &v1.CalicoNodeDaemonSetPodTemplateSpec{
							Metadata: &v1.Metadata{
								Annotations: map[string]string{
									"not-zero":       "wont-work",
									"test-pod-annot": "annot1",
								},
							},
						},
					},
				}
			},
			func(result appsv1.DaemonSet) {
				expected := defaultedDaemonSet()
				expected.Spec.Template.Annotations["test-pod-annot"] = "annot1"
				Expect(result).To(Equal(expected))
			}),

		Entry("init containers",
			defaultedDaemonSet,
			func() *v1.CalicoNodeDaemonSet {
				return &v1.CalicoNodeDaemonSet{
					Spec: &v1.CalicoNodeDaemonSetSpec{
						Template: &v1.CalicoNodeDaemonSetPodTemplateSpec{
							Spec: &v1.CalicoNodeDaemonSetPodSpec{
								InitContainers: []v1.CalicoNodeDaemonSetInitContainer{
									{
										Name:      "not-zero1",
										Resources: &resources1,
									},
									// Invalid init container. Should be caught by CRD validation.
									{
										Name:      "does-not-exist",
										Resources: &resources3,
									},
									{
										Name:      "not-zero2",
										Resources: &resources2,
									},
								},
							},
						},
					},
				}
			},
			func(result appsv1.DaemonSet) {
				expected := defaultedDaemonSet()
				Expect(expected.Spec.Template.Spec.InitContainers).To(HaveLen(2))

				expected.Spec.Template.Spec.InitContainers[0].Resources = resources1
				expected.Spec.Template.Spec.InitContainers[1].Resources = resources2
				Expect(result.Spec.Template.Spec.InitContainers).To(ContainElements(expected.Spec.Template.Spec.InitContainers))
				Expect(result).To(Equal(expected))
			}),

		Entry("empty init containers",
			defaultedDaemonSet,
			func() *v1.CalicoNodeDaemonSet {
				return &v1.CalicoNodeDaemonSet{
					Spec: &v1.CalicoNodeDaemonSetSpec{
						Template: &v1.CalicoNodeDaemonSetPodTemplateSpec{
							Spec: &v1.CalicoNodeDaemonSetPodSpec{
								InitContainers: []v1.CalicoNodeDaemonSetInitContainer{},
							},
						},
					},
				}
			},
			func(result appsv1.DaemonSet) {
				expected := defaultedDaemonSet()
				Expect(expected.Spec.Template.Spec.InitContainers).To(HaveLen(2))
				Expect(result.Spec.Template.Spec.InitContainers).To(ContainElements(expected.Spec.Template.Spec.InitContainers))
				Expect(result).To(Equal(expected))
			}),

		Entry("containers",
			defaultedDaemonSet,
			func() *v1.CalicoNodeDaemonSet {
				return &v1.CalicoNodeDaemonSet{
					Spec: &v1.CalicoNodeDaemonSetSpec{
						Template: &v1.CalicoNodeDaemonSetPodTemplateSpec{
							Spec: &v1.CalicoNodeDaemonSetPodSpec{
								Containers: []v1.CalicoNodeDaemonSetContainer{
									// Invalid container. Should be caught by CRD validation.
									{
										Name:      "does-not-exist",
										Resources: &resources3,
									},
									{
										Name:      "not-zero1",
										Resources: &resources1,
									},
								},
							},
						},
					},
				}
			},
			func(result appsv1.DaemonSet) {
				expected := defaultedDaemonSet()
				Expect(expected.Spec.Template.Spec.Containers).To(HaveLen(2))
				expected.Spec.Template.Spec.Containers[0].Resources = resources1
				expected.Annotations[CustomOverridesAnnotation] = "resources"
				Expect(result.Spec.Template.Spec.Containers).To(ContainElements(expected.Spec.Template.Spec.Containers))
				Expect(result).To(Equal(expected))
			}),

		Entry("empty containers",
			defaultedDaemonSet,
			func() *v1.CalicoNodeDaemonSet {
				return &v1.CalicoNodeDaemonSet{
					Spec: &v1.CalicoNodeDaemonSetSpec{
						Template: &v1.CalicoNodeDaemonSetPodTemplateSpec{
							Spec: &v1.CalicoNodeDaemonSetPodSpec{
								Containers: []v1.CalicoNodeDaemonSetContainer{},
							},
						},
					},
				}
			},
			func(result appsv1.DaemonSet) {
				expected := defaultedDaemonSet()
				Expect(expected.Spec.Template.Spec.Containers).To(HaveLen(2))
				Expect(result.Spec.Template.Spec.Containers).To(ContainElements(expected.Spec.Template.Spec.Containers))
				Expect(result).To(Equal(expected))
			}),

		Entry("empty tolerations",
			defaultedDaemonSet,
			func() *v1.CalicoNodeDaemonSet {
				return &v1.CalicoNodeDaemonSet{
					Spec: &v1.CalicoNodeDaemonSetSpec{
						Template: &v1.CalicoNodeDaemonSetPodTemplateSpec{
							Spec: &v1.CalicoNodeDaemonSetPodSpec{
								Tolerations: []corev1.Toleration{},
							},
						},
					},
				}
			},
			func(result appsv1.DaemonSet) {
				expected := defaultedDaemonSet()
				expected.Spec.Template.Spec.Tolerations = []corev1.Toleration{}
				Expect(result.Spec.Template.Spec.Tolerations).To(Equal(expected.Spec.Template.Spec.Tolerations))
				Expect(result).To(Equal(expected))
			}),

		Entry("empty nodeSelector",
			defaultedDaemonSet,
			func() *v1.CalicoNodeDaemonSet {
				return &v1.CalicoNodeDaemonSet{
					Spec: &v1.CalicoNodeDaemonSetSpec{
						Template: &v1.CalicoNodeDaemonSetPodTemplateSpec{
							Spec: &v1.CalicoNodeDaemonSetPodSpec{
								NodeSelector: map[string]string{},
							},
						},
					},
				}
			},
			func(result appsv1.DaemonSet) {
				expected := defaultedDaemonSet()
				Expect(result.Spec.Template.Spec.NodeSelector).To(Equal(expected.Spec.Template.Spec.NodeSelector))
				Expect(result).To(Equal(expected))
			}),

		Entry("affinity, nodeSelector, and tolerations",
			defaultedDaemonSet,
			func() *v1.CalicoNodeDaemonSet {
				return &v1.CalicoNodeDaemonSet{
					Spec: &v1.CalicoNodeDaemonSetSpec{
						Template: &v1.CalicoNodeDaemonSetPodTemplateSpec{
							Spec: &v1.CalicoNodeDaemonSetPodSpec{
								Affinity:     &affinity,
								NodeSelector: nodeSelector,
								Tolerations:  tolerations,
							},
						},
					},
				}
			},
			func(result appsv1.DaemonSet) {
				expected := defaultedDaemonSet()
				expected.Spec.Template.Spec.Affinity = &affinity
				// only keys that don't already exist in the nodeSelector are added
				for k, v := range nodeSelector {
					if _, ok := expected.Spec.Template.Spec.NodeSelector[k]; !ok {
						expected.Spec.Template.Spec.NodeSelector[k] = v
					}
				}
				expected.Spec.Template.Spec.Tolerations = tolerations
				Expect(result.Spec.Template.Spec.Affinity).To(Equal(expected.Spec.Template.Spec.Affinity))
				Expect(result.Spec.Template.Spec.NodeSelector).To(Equal(expected.Spec.Template.Spec.NodeSelector))
				Expect(result.Spec.Template.Spec.Tolerations).To(Equal(expected.Spec.Template.Spec.Tolerations))
				Expect(result).To(Equal(expected))
			}),
	)

	DescribeTable("test ApplyDeploymentOverrides",
		func(original func() appsv1.Deployment, override func() *v1.TyphaDeployment, expectations func(set appsv1.Deployment)) {
			orig := original()
			template := override()
			ApplyDeploymentOverrides(&orig, template)
			expectations(orig)
		},

		Entry("empty",
			defaultedDeployment,
			func() *v1.TyphaDeployment {
				return &v1.TyphaDeployment{}
			},
			func(result appsv1.Deployment) {
				Expect(result).To(Equal(defaultedDeployment()))
			}),
		Entry("empty labels and annotations",
			defaultedDeployment,
			func() *v1.TyphaDeployment {
				return &v1.TyphaDeployment{
					Metadata: &v1.Metadata{
						Labels:      map[string]string{},
						Annotations: nil,
					},
				}
			},
			func(result appsv1.Deployment) {
				Expect(result).To(Equal(defaultedDeployment()))
			}),
		Entry("empty labels and annotations, empty spec",
			defaultedDeployment,
			func() *v1.TyphaDeployment {
				return &v1.TyphaDeployment{
					Metadata: &v1.Metadata{
						Labels:      map[string]string{},
						Annotations: map[string]string{},
					},
					Spec: &v1.TyphaDeploymentSpec{},
				}
			},
			func(result appsv1.Deployment) {
				Expect(result).To(Equal(defaultedDeployment()))
			}),
		Entry("labels and annotations",
			defaultedDeployment,
			func() *v1.TyphaDeployment {
				return &v1.TyphaDeployment{
					Metadata: &v1.Metadata{
						Labels:      map[string]string{"test-label": "label1"},
						Annotations: map[string]string{"test-annot": "annot1"},
					},
					Spec: nil,
				}
			},
			func(result appsv1.Deployment) {
				expected := defaultedDeployment()
				expected.Labels["test-label"] = "label1"
				expected.Annotations["test-annot"] = "annot1"
				Expect(result).To(Equal(expected))
			}),
		Entry("labels only",
			defaultedDeployment,
			func() *v1.TyphaDeployment {
				return &v1.TyphaDeployment{
					Metadata: &v1.Metadata{
						Labels: map[string]string{"test-label": "label1"},
					},
					Spec: nil,
				}
			},
			func(result appsv1.Deployment) {
				expected := defaultedDeployment()
				expected.Labels["test-label"] = "label1"
				Expect(result).To(Equal(expected))
			}),
		Entry("annotations only",
			defaultedDeployment,
			func() *v1.TyphaDeployment {
				return &v1.TyphaDeployment{
					Metadata: &v1.Metadata{
						Annotations: map[string]string{"test-annot": "annot1"},
					},
					Spec: nil,
				}
			},
			func(result appsv1.Deployment) {
				expected := defaultedDeployment()
				expected.Annotations["test-annot"] = "annot1"
				Expect(result).To(Equal(expected))
			}),
		Entry("labels and annotations that are already defined",
			defaultedDeployment,
			func() *v1.TyphaDeployment {
				return &v1.TyphaDeployment{
					Metadata: &v1.Metadata{
						// "not-zero" label and annotation keys exist in the defaulted calico node.
						Labels: map[string]string{
							"test-label": "label1",
							"not-zero":   "not-zero",
						},
						Annotations: map[string]string{
							"not-zero":   "not-zero",
							"test-annot": "annot1",
						},
					},
				}
			},
			func(result appsv1.Deployment) {
				expected := defaultedDeployment()
				// Only the labels and annotations that don't clobber existing keys are added.
				expected.Labels["test-label"] = "label1"
				expected.Annotations["test-annot"] = "annot1"
				Expect(result).To(Equal(expected))
			}),
		Entry("labels that are already defined",
			defaultedDeployment,
			func() *v1.TyphaDeployment {
				return &v1.TyphaDeployment{
					Metadata: &v1.Metadata{
						// "not-zero" label keys exist in the defaulted calico node.
						Labels: map[string]string{
							"test-label": "label1",
							"not-zero":   "not-zero",
						},
					},
				}
			},
			func(result appsv1.Deployment) {
				expected := defaultedDeployment()
				// Only the labels that don't clobber existing keys are added.
				expected.Labels["test-label"] = "label1"
				Expect(result).To(Equal(expected))
			}),
		Entry("annotations that are already defined",
			defaultedDeployment,
			func() *v1.TyphaDeployment {
				return &v1.TyphaDeployment{
					Metadata: &v1.Metadata{
						// "not-zero" annotation keys exist in the defaulted calico node.
						Annotations: map[string]string{
							"not-zero":   "not-zero",
							"test-annot": "annot1",
						},
					},
				}
			},
			func(result appsv1.Deployment) {
				expected := defaultedDeployment()
				// Only the annotations that don't clobber existing keys are added.
				expected.Annotations["test-annot"] = "annot1"
				Expect(result).To(Equal(expected))
			}),
		Entry("minReadySeconds",
			defaultedDeployment,
			func() *v1.TyphaDeployment {
				return &v1.TyphaDeployment{
					Spec: &v1.TyphaDeploymentSpec{
						MinReadySeconds: &three,
					},
				}
			},
			func(result appsv1.Deployment) {
				expected := defaultedDeployment()
				expected.Spec.MinReadySeconds = three
				Expect(result).To(Equal(expected))
			}),
		Entry("pod template labels and annotations",
			defaultedDeployment,
			func() *v1.TyphaDeployment {
				return &v1.TyphaDeployment{
					Spec: &v1.TyphaDeploymentSpec{
						Template: &v1.TyphaDeploymentPodTemplateSpec{
							Metadata: &v1.Metadata{
								Labels:      map[string]string{"test-pod-label": "label1"},
								Annotations: map[string]string{"test-pod-annot": "annot1"},
							},
						},
					},
				}
			},
			func(result appsv1.Deployment) {
				expected := defaultedDeployment()
				expected.Spec.Template.Labels["test-pod-label"] = "label1"
				expected.Spec.Template.Annotations["test-pod-annot"] = "annot1"
				Expect(result).To(Equal(expected))
			}),
		Entry("pod template labels only",
			defaultedDeployment,
			func() *v1.TyphaDeployment {
				return &v1.TyphaDeployment{
					Spec: &v1.TyphaDeploymentSpec{
						Template: &v1.TyphaDeploymentPodTemplateSpec{
							Metadata: &v1.Metadata{
								Labels: map[string]string{"test-pod-label": "label1"},
							},
						},
					},
				}
			},
			func(result appsv1.Deployment) {
				expected := defaultedDeployment()
				expected.Spec.Template.Labels["test-pod-label"] = "label1"
				Expect(result).To(Equal(expected))
			}),
		Entry("pod template annotations only",
			defaultedDeployment,
			func() *v1.TyphaDeployment {
				return &v1.TyphaDeployment{
					Spec: &v1.TyphaDeploymentSpec{
						Template: &v1.TyphaDeploymentPodTemplateSpec{
							Metadata: &v1.Metadata{
								Annotations: map[string]string{"test-pod-annot": "annot1"},
							},
						},
					},
				}
			},
			func(result appsv1.Deployment) {
				expected := defaultedDeployment()
				expected.Spec.Template.Annotations["test-pod-annot"] = "annot1"
				Expect(result).To(Equal(expected))
			}),
		Entry("pod labels and annotations that are already defined",
			defaultedDeployment,
			func() *v1.TyphaDeployment {
				return &v1.TyphaDeployment{
					Spec: &v1.TyphaDeploymentSpec{
						Template: &v1.TyphaDeploymentPodTemplateSpec{
							Metadata: &v1.Metadata{
								Labels: map[string]string{
									"test-pod-label": "label1",
									"not-zero":       "wont-work",
								},
								Annotations: map[string]string{
									"not-zero":       "wont-work",
									"test-pod-annot": "annot1",
								},
							},
						},
					},
				}
			},
			func(result appsv1.Deployment) {
				expected := defaultedDeployment()
				expected.Spec.Template.Labels["test-pod-label"] = "label1"
				expected.Spec.Template.Annotations["test-pod-annot"] = "annot1"
				Expect(result).To(Equal(expected))
			}),
		Entry("pod labels that are already defined",
			defaultedDeployment,
			func() *v1.TyphaDeployment {
				return &v1.TyphaDeployment{
					Spec: &v1.TyphaDeploymentSpec{
						Template: &v1.TyphaDeploymentPodTemplateSpec{
							Metadata: &v1.Metadata{
								Labels: map[string]string{
									"test-pod-label": "label1",
									"not-zero":       "wont-work",
								},
							},
						},
					},
				}
			},
			func(result appsv1.Deployment) {
				expected := defaultedDeployment()
				expected.Spec.Template.Labels["test-pod-label"] = "label1"
				Expect(result).To(Equal(expected))
			}),
		Entry("pod annotations that are already defined",
			defaultedDeployment,
			func() *v1.TyphaDeployment {
				return &v1.TyphaDeployment{
					Spec: &v1.TyphaDeploymentSpec{
						Template: &v1.TyphaDeploymentPodTemplateSpec{
							Metadata: &v1.Metadata{
								Annotations: map[string]string{
									"not-zero":       "wont-work",
									"test-pod-annot": "annot1",
								},
							},
						},
					},
				}
			},
			func(result appsv1.Deployment) {
				expected := defaultedDeployment()
				expected.Spec.Template.Annotations["test-pod-annot"] = "annot1"
				Expect(result).To(Equal(expected))
			}),
		Entry("init containers",
			defaultedDeployment,
			func() *v1.TyphaDeployment {
				return &v1.TyphaDeployment{
					Spec: &v1.TyphaDeploymentSpec{
						Template: &v1.TyphaDeploymentPodTemplateSpec{
							Spec: &v1.TyphaDeploymentPodSpec{
								InitContainers: []v1.TyphaDeploymentInitContainer{
									{
										Name:      "not-zero1",
										Resources: &resources1,
									},
									// Invalid init container. Should be caught by CRD validation.
									{
										Name:      "does-not-exist",
										Resources: &resources3,
									},
									{
										Name:      "not-zero2",
										Resources: &resources2,
									},
								},
							},
						},
					},
				}
			},
			func(result appsv1.Deployment) {
				expected := defaultedDeployment()
				Expect(expected.Spec.Template.Spec.InitContainers).To(HaveLen(2))

				expected.Spec.Template.Spec.InitContainers[0].Resources = resources1
				expected.Spec.Template.Spec.InitContainers[1].Resources = resources2
				Expect(result.Spec.Template.Spec.InitContainers).To(ContainElements(expected.Spec.Template.Spec.InitContainers))
				Expect(result).To(Equal(expected))
			}),
		Entry("empty init containers",
			defaultedDeployment,
			func() *v1.TyphaDeployment {
				return &v1.TyphaDeployment{
					Spec: &v1.TyphaDeploymentSpec{
						Template: &v1.TyphaDeploymentPodTemplateSpec{
							Spec: &v1.TyphaDeploymentPodSpec{
								InitContainers: []v1.TyphaDeploymentInitContainer{},
							},
						},
					},
				}
			},
			func(result appsv1.Deployment) {
				expected := defaultedDeployment()
				Expect(expected.Spec.Template.Spec.InitContainers).To(HaveLen(2))
				Expect(result.Spec.Template.Spec.InitContainers).To(ContainElements(expected.Spec.Template.Spec.InitContainers))
				Expect(result).To(Equal(expected))
			}),
		Entry("containers",
			defaultedDeployment,
			func() *v1.TyphaDeployment {
				return &v1.TyphaDeployment{
					Spec: &v1.TyphaDeploymentSpec{
						Template: &v1.TyphaDeploymentPodTemplateSpec{
							Spec: &v1.TyphaDeploymentPodSpec{
								Containers: []v1.TyphaDeploymentContainer{
									// Invalid container. Should be caught by CRD validation.
									{
										Name:      "does-not-exist",
										Resources: &resources3,
									},
									{
										Name:      "not-zero1",
										Resources: &resources1,
									},
								},
							},
						},
					},
				}
			},
			func(result appsv1.Deployment) {
				expected := defaultedDeployment()
				Expect(expected.Spec.Template.Spec.Containers).To(HaveLen(2))
				expected.Spec.Template.Spec.Containers[0].Resources = resources1
				expected.Annotations[CustomOverridesAnnotation] = "resources"
				Expect(result.Spec.Template.Spec.Containers).To(ContainElements(expected.Spec.Template.Spec.Containers))
				Expect(result).To(Equal(expected))
			}),
		Entry("empty containers",
			defaultedDeployment,
			func() *v1.TyphaDeployment {
				return &v1.TyphaDeployment{
					Spec: &v1.TyphaDeploymentSpec{
						Template: &v1.TyphaDeploymentPodTemplateSpec{
							Spec: &v1.TyphaDeploymentPodSpec{
								Containers: []v1.TyphaDeploymentContainer{},
							},
						},
					},
				}
			},
			func(result appsv1.Deployment) {
				expected := defaultedDeployment()
				Expect(expected.Spec.Template.Spec.Containers).To(HaveLen(2))
				Expect(result.Spec.Template.Spec.Containers).To(ContainElements(expected.Spec.Template.Spec.Containers))
				Expect(result).To(Equal(expected))
			}),
		Entry("empty tolerations",
			defaultedDeployment,
			func() *v1.TyphaDeployment {
				return &v1.TyphaDeployment{
					Spec: &v1.TyphaDeploymentSpec{
						Template: &v1.TyphaDeploymentPodTemplateSpec{
							Spec: &v1.TyphaDeploymentPodSpec{
								Tolerations: []corev1.Toleration{},
							},
						},
					},
				}
			},
			func(result appsv1.Deployment) {
				expected := defaultedDeployment()
				expected.Spec.Template.Spec.Tolerations = []corev1.Toleration{}
				Expect(result.Spec.Template.Spec.Tolerations).To(Equal(expected.Spec.Template.Spec.Tolerations))
				Expect(result).To(Equal(expected))
			}),
		Entry("empty nodeSelector",
			defaultedDeployment,
			func() *v1.TyphaDeployment {
				return &v1.TyphaDeployment{
					Spec: &v1.TyphaDeploymentSpec{
						Template: &v1.TyphaDeploymentPodTemplateSpec{
							Spec: &v1.TyphaDeploymentPodSpec{
								NodeSelector: map[string]string{},
							},
						},
					},
				}
			},
			func(result appsv1.Deployment) {
				expected := defaultedDeployment()
				Expect(result.Spec.Template.Spec.NodeSelector).To(Equal(expected.Spec.Template.Spec.NodeSelector))
				Expect(result).To(Equal(expected))
			}),

		Entry("affinity, nodeSelector, and tolerations",
			defaultedDeployment,
			func() *v1.TyphaDeployment {
				return &v1.TyphaDeployment{
					Spec: &v1.TyphaDeploymentSpec{
						Template: &v1.TyphaDeploymentPodTemplateSpec{
							Spec: &v1.TyphaDeploymentPodSpec{
								Affinity:     &affinity,
								NodeSelector: nodeSelector,
								Tolerations:  tolerations,
							},
						},
					},
				}
			},
			func(result appsv1.Deployment) {
				expected := defaultedDeployment()
				expected.Spec.Template.Spec.Affinity = &affinity
				// only keys that don't already exist in the nodeSelector are added
				for k, v := range nodeSelector {
					if _, ok := expected.Spec.Template.Spec.NodeSelector[k]; !ok {
						expected.Spec.Template.Spec.NodeSelector[k] = v
					}
				}
				expected.Spec.Template.Spec.Tolerations = tolerations
				Expect(result.Spec.Template.Spec.Affinity).To(Equal(expected.Spec.Template.Spec.Affinity))
				Expect(result.Spec.Template.Spec.NodeSelector).To(Equal(expected.Spec.Template.Spec.NodeSelector))
				Expect(result.Spec.Template.Spec.Tolerations).To(Equal(expected.Spec.Template.Spec.Tolerations))
				Expect(result).To(Equal(expected))
			}),

		Entry("terminationGracePeriod",
			defaultedDeployment,
			func() *v1.TyphaDeployment {
				return &v1.TyphaDeployment{
					Spec: &v1.TyphaDeploymentSpec{
						Template: &v1.TyphaDeploymentPodTemplateSpec{
							Spec: &v1.TyphaDeploymentPodSpec{
								TerminationGracePeriodSeconds: ptr.To(int64(3)),
							},
						},
					},
				}
			},
			func(result appsv1.Deployment) {
				Expect(*result.Spec.Template.Spec.TerminationGracePeriodSeconds).To(Equal(int64(3)))
			}),

		Entry("strategy",
			defaultedDeployment,
			func() *v1.TyphaDeployment {
				return &v1.TyphaDeployment{
					Spec: &v1.TyphaDeploymentSpec{
						Strategy: &v1.TyphaDeploymentStrategy{
							RollingUpdate: &appsv1.RollingUpdateDeployment{
								MaxUnavailable: ptr.To(intstr.FromString("0")),
								MaxSurge:       ptr.To(intstr.FromString("100%")),
							},
						},
					},
				}
			},
			func(result appsv1.Deployment) {
				Expect(result.Spec.Strategy).To(Equal(appsv1.DeploymentStrategy{
					Type: appsv1.RollingUpdateDeploymentStrategyType,
					RollingUpdate: &appsv1.RollingUpdateDeployment{
						MaxUnavailable: ptr.To(intstr.FromString("0")),
						MaxSurge:       ptr.To(intstr.FromString("100%")),
					},
				}))
			}),
	)

	Describe("resolveContainerName", func() {
		It("should resolve known aliases to current names", func() {
			Expect(resolveContainerName("tigera-manager")).To(Equal("calico-manager"))
			Expect(resolveContainerName("tigera-voltron")).To(Equal("calico-voltron"))
			Expect(resolveContainerName("tigera-ui-apis")).To(Equal("calico-ui-apis"))
			Expect(resolveContainerName("tigera-es-proxy")).To(Equal("calico-ui-apis"))
			Expect(resolveContainerName("tigera-voltron-linseed-tls-key-cert-provisioner")).To(Equal("calico-voltron-linseed-tls-key-cert-provisioner"))
		})

		It("should pass through unknown names unchanged", func() {
			Expect(resolveContainerName("calico-manager")).To(Equal("calico-manager"))
			Expect(resolveContainerName("calico-node")).To(Equal("calico-node"))
			Expect(resolveContainerName("some-other-container")).To(Equal("some-other-container"))
		})
	})

	It("should not have transitive aliases (no value appears as a key)", func() {
		for _, target := range containerNameAliases {
			_, isAlsoKey := containerNameAliases[target]
			Expect(isAlsoKey).To(BeFalse(), "alias target %q is also an alias key, creating a transitive chain", target)
		}
	})

	It("should apply overrides using deprecated container names to containers with current names", func() {
		// Create a deployment with containers using current names.
		d := appsv1.Deployment{}
		d.Spec.Template.Spec.Containers = []corev1.Container{
			{Name: "calico-manager"},
			{Name: "calico-voltron"},
			{Name: "calico-ui-apis"},
		}
		overrideResources := corev1.ResourceRequirements{
			Limits: corev1.ResourceList{
				"cpu": resource.MustParse("2"),
			},
		}

		// Apply overrides using deprecated names.
		overrides := &v1.ManagerDeployment{
			Spec: &v1.ManagerDeploymentSpec{
				Template: &v1.ManagerDeploymentPodTemplateSpec{
					Spec: &v1.ManagerDeploymentPodSpec{
						Containers: []v1.ManagerDeploymentContainer{
							{Name: "tigera-manager", Resources: &overrideResources},
							{Name: "tigera-voltron", Resources: &overrideResources},
							{Name: "tigera-es-proxy", Resources: &overrideResources},
						},
					},
				},
			},
		}
		ApplyDeploymentOverrides(&d, overrides)

		// Verify overrides were applied to containers with current names.
		for _, c := range d.Spec.Template.Spec.Containers {
			Expect(c.Resources).To(Equal(overrideResources), "container %q should have overridden resources", c.Name)
		}
	})

	Describe("custom-overrides annotation", func() {
		It("should set annotation when readiness probe override is applied", func() {
			d := appsv1.Deployment{}
			d.Spec.Template.Spec.Containers = []corev1.Container{
				{
					Name:  "calico-manager",
					Image: "test-image",
					ReadinessProbe: &corev1.Probe{
						ProbeHandler: corev1.ProbeHandler{HTTPGet: &corev1.HTTPGetAction{Path: "/health"}},
					},
				},
			}

			period := int32(30)
			overrides := &v1.ManagerDeployment{
				Spec: &v1.ManagerDeploymentSpec{
					Template: &v1.ManagerDeploymentPodTemplateSpec{
						Spec: &v1.ManagerDeploymentPodSpec{
							Containers: []v1.ManagerDeploymentContainer{
								{
									Name:           "calico-manager",
									ReadinessProbe: &v1.ProbeOverride{PeriodSeconds: &period},
								},
							},
						},
					},
				},
			}

			ApplyDeploymentOverrides(&d, overrides)
			Expect(d.Annotations).To(HaveKeyWithValue(CustomOverridesAnnotation, "readinessProbe"))
		})

		It("should set annotation with multiple override types", func() {
			d := appsv1.Deployment{}
			d.Spec.Template.Spec.Containers = []corev1.Container{
				{
					Name:  "calico-manager",
					Image: "test-image",
					ReadinessProbe: &corev1.Probe{
						ProbeHandler: corev1.ProbeHandler{HTTPGet: &corev1.HTTPGetAction{Path: "/health"}},
					},
					LivenessProbe: &corev1.Probe{
						ProbeHandler: corev1.ProbeHandler{HTTPGet: &corev1.HTTPGetAction{Path: "/health"}},
					},
				},
			}

			period := int32(30)
			overrideResources := corev1.ResourceRequirements{
				Limits: corev1.ResourceList{corev1.ResourceCPU: resource.MustParse("500m")},
			}
			overrides := &v1.ManagerDeployment{
				Spec: &v1.ManagerDeploymentSpec{
					Template: &v1.ManagerDeploymentPodTemplateSpec{
						Spec: &v1.ManagerDeploymentPodSpec{
							Containers: []v1.ManagerDeploymentContainer{
								{
									Name:           "calico-manager",
									ReadinessProbe: &v1.ProbeOverride{PeriodSeconds: &period},
									LivenessProbe:  &v1.ProbeOverride{PeriodSeconds: &period},
									Resources:      &overrideResources,
								},
							},
						},
					},
				},
			}

			ApplyDeploymentOverrides(&d, overrides)
			ann := d.Annotations[CustomOverridesAnnotation]
			Expect(ann).To(ContainSubstring("readinessProbe"))
			Expect(ann).To(ContainSubstring("livenessProbe"))
			Expect(ann).To(ContainSubstring("resources"))
		})

		It("should not set annotation when no probe or resource overrides", func() {
			d := appsv1.Deployment{}
			d.Spec.Template.Spec.Containers = []corev1.Container{
				{Name: "calico-manager", Image: "test-image"},
			}
			overrides := &v1.ManagerDeployment{
				Spec: &v1.ManagerDeploymentSpec{},
			}
			ApplyDeploymentOverrides(&d, overrides)
			Expect(d.Annotations).NotTo(HaveKey(CustomOverridesAnnotation))
		})
	})
})

var _ = Describe("ApplyPodDisruptionBudgetOverrides", func() {
	var pdb *policyv1.PodDisruptionBudget

	BeforeEach(func() {
		pdb = &policyv1.PodDisruptionBudget{
			ObjectMeta: metav1.ObjectMeta{Name: "calico-typha", Namespace: "calico-system"},
			Spec: policyv1.PodDisruptionBudgetSpec{
				MaxUnavailable: ptr.To(intstr.FromInt(1)),
				Selector: &metav1.LabelSelector{
					MatchLabels: map[string]string{"k8s-app": "calico-typha"},
				},
			},
		}
	})

	It("does nothing when overrides is nil", func() {
		ApplyPodDisruptionBudgetOverrides(pdb, nil)
		Expect(pdb.Spec.MaxUnavailable).To(Equal(ptr.To(intstr.FromInt(1))))
		Expect(pdb.Spec.MinAvailable).To(BeNil())
		Expect(pdb.Spec.UnhealthyPodEvictionPolicy).To(BeNil())
	})

	It("does not panic on nil PDB", func() {
		Expect(func() {
			ApplyPodDisruptionBudgetOverrides(nil, &v1.PodDisruptionBudgetOverride{
				Spec: &v1.PodDisruptionBudgetOverrideSpec{
					MinAvailable: ptr.To(intstr.FromInt(2)),
				},
			})
		}).ToNot(Panic())
	})

	It("applies only UnhealthyPodEvictionPolicy and preserves default MaxUnavailable", func() {
		policy := policyv1.AlwaysAllow
		ApplyPodDisruptionBudgetOverrides(pdb, &v1.PodDisruptionBudgetOverride{
			Spec: &v1.PodDisruptionBudgetOverrideSpec{
				UnhealthyPodEvictionPolicy: &policy,
			},
		})
		Expect(pdb.Spec.MaxUnavailable).To(Equal(ptr.To(intstr.FromInt(1))))
		Expect(pdb.Spec.MinAvailable).To(BeNil())
		Expect(*pdb.Spec.UnhealthyPodEvictionPolicy).To(Equal(policyv1.AlwaysAllow))
	})

	It("clears MaxUnavailable when MinAvailable is set", func() {
		ApplyPodDisruptionBudgetOverrides(pdb, &v1.PodDisruptionBudgetOverride{
			Spec: &v1.PodDisruptionBudgetOverrideSpec{
				MinAvailable: ptr.To(intstr.FromInt(2)),
			},
		})
		Expect(pdb.Spec.MinAvailable).To(Equal(ptr.To(intstr.FromInt(2))))
		Expect(pdb.Spec.MaxUnavailable).To(BeNil())
	})

	It("clears MinAvailable when MaxUnavailable is set to a percentage", func() {
		pdb.Spec.MaxUnavailable = nil
		pdb.Spec.MinAvailable = ptr.To(intstr.FromInt(3))
		ApplyPodDisruptionBudgetOverrides(pdb, &v1.PodDisruptionBudgetOverride{
			Spec: &v1.PodDisruptionBudgetOverrideSpec{
				MaxUnavailable: ptr.To(intstr.FromString("50%")),
			},
		})
		Expect(pdb.Spec.MaxUnavailable).To(Equal(ptr.To(intstr.FromString("50%"))))
		Expect(pdb.Spec.MinAvailable).To(BeNil())
	})

	It("applies MinAvailable + UnhealthyPodEvictionPolicy together", func() {
		policy := policyv1.AlwaysAllow
		ApplyPodDisruptionBudgetOverrides(pdb, &v1.PodDisruptionBudgetOverride{
			Spec: &v1.PodDisruptionBudgetOverrideSpec{
				MinAvailable:               ptr.To(intstr.FromInt(2)),
				UnhealthyPodEvictionPolicy: &policy,
			},
		})
		Expect(pdb.Spec.MinAvailable).To(Equal(ptr.To(intstr.FromInt(2))))
		Expect(pdb.Spec.MaxUnavailable).To(BeNil())
		Expect(*pdb.Spec.UnhealthyPodEvictionPolicy).To(Equal(policyv1.AlwaysAllow))
	})

	It("never mutates the selector", func() {
		original := pdb.Spec.Selector.DeepCopy()
		ApplyPodDisruptionBudgetOverrides(pdb, &v1.PodDisruptionBudgetOverride{
			Spec: &v1.PodDisruptionBudgetOverrideSpec{
				MinAvailable: ptr.To(intstr.FromInt(2)),
			},
		})
		Expect(pdb.Spec.Selector).To(Equal(original))
	})

	It("merges metadata labels and annotations onto the PDB", func() {
		pdb.Labels = map[string]string{"existing": "label"}
		pdb.Annotations = map[string]string{"existing": "ann"}
		ApplyPodDisruptionBudgetOverrides(pdb, &v1.PodDisruptionBudgetOverride{
			Metadata: &v1.Metadata{
				Labels:      map[string]string{"new": "label"},
				Annotations: map[string]string{"new": "ann"},
			},
		})
		Expect(pdb.Labels).To(Equal(map[string]string{"existing": "label", "new": "label"}))
		Expect(pdb.Annotations).To(Equal(map[string]string{"existing": "ann", "new": "ann"}))
	})

	It("treats a nil Spec as no spec override", func() {
		ApplyPodDisruptionBudgetOverrides(pdb, &v1.PodDisruptionBudgetOverride{
			Metadata: &v1.Metadata{Labels: map[string]string{"a": "b"}},
		})
		Expect(pdb.Spec.MaxUnavailable).To(Equal(ptr.To(intstr.FromInt(1))))
		Expect(pdb.Spec.MinAvailable).To(BeNil())
		Expect(pdb.Spec.UnhealthyPodEvictionPolicy).To(BeNil())
		Expect(pdb.Labels).To(HaveKeyWithValue("a", "b"))
	})
})

func addContainer(cs []corev1.Container) []corev1.Container {
	// Add another container and rename them to "not-zero1" and "not-zero2".
	containers := make([]corev1.Container, 0, 2)
	var newContainer corev1.Container
	cs[0].DeepCopyInto(&newContainer)
	cs[0].Name = "not-zero1"
	cs[0].Image = "not-zero1"
	newContainer.Name = "not-zero2"
	newContainer.Image = "not-zero2"

	containers = append(containers, cs[0])
	containers = append(containers, newContainer)
	return containers
}

// recordHandledFields swaps the package-level getField with a wrapper that
// records each field path accessed, then returns:
//   - recorded: a closure returning the accumulated paths
//   - restore: a function (typically deferred) that restores the original getField
//
// The wrapper passes raw fieldNames through to the original getField, so any
// per-type path adjustments made there are unchanged. Recording mirrors those
// adjustments via normalizeFieldPath so the recorded paths match the field
// names we actually look up.
//
// NOT safe under parallel test execution: the swap mutates package state.
// All "check for unhandled fields" entries run serially in this Describe.
func recordHandledFields() (recorded func() []string, restore func()) {
	var rec []string
	original := getField
	getField = func(overrides any, fieldNames ...string) reflect.Value {
		rec = append(rec, strings.Join(normalizeFieldPath(overrides, fieldNames), "."))
		return original(overrides, fieldNames...)
	}
	return func() []string { return append([]string(nil), rec...) }, func() { getField = original }
}

// defaultedDaemonSet returns a DaemonSet with its fields populated.
func defaultedDaemonSet() appsv1.DaemonSet {
	var ds appsv1.DaemonSet
	defaulter := test.NewNonZeroStructDefaulter()
	Expect(defaulter.SetDefault(&ds)).ToNot(HaveOccurred())

	ds.Spec.Template.Spec.DNSPolicy = corev1.DNSClusterFirst
	ds.Spec.Template.Spec.Containers = addContainer(ds.Spec.Template.Spec.Containers)
	ds.Spec.Template.Spec.InitContainers = addContainer(ds.Spec.Template.Spec.InitContainers)
	return ds
}

// defaultedDeployment returns a Deployment with its fields populated.
func defaultedDeployment() appsv1.Deployment {
	var ds appsv1.Deployment
	defaulter := test.NewNonZeroStructDefaulter()
	Expect(defaulter.SetDefault(&ds)).ToNot(HaveOccurred())

	ds.Spec.Template.Spec.Containers = addContainer(ds.Spec.Template.Spec.Containers)
	ds.Spec.Template.Spec.InitContainers = addContainer(ds.Spec.Template.Spec.InitContainers)
	return ds
}
