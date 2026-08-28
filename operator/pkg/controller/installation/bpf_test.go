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

package installation

import (
	"strconv"

	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	"github.com/tigera/operator/pkg/common"

	"github.com/tigera/operator/pkg/render"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

var _ = Describe("BPF functional tests", func() {
	Context("Annotations validation tests", func() {
		var fc *v3.FelixConfiguration
		var textTrue, textFalse string
		var enabled, notEnabled bool

		textTrue = strconv.FormatBool(true)
		textFalse = strconv.FormatBool(false)

		enabled = true
		notEnabled = false

		BeforeEach(func() {
			fc = &v3.FelixConfiguration{
				ObjectMeta: metav1.ObjectMeta{
					Name:        "default",
					Annotations: map[string]string{"foo": "bar"},
				},
				Spec: v3.FelixConfigurationSpec{},
			}
		})

		It("should return error if the value is not a boolean", func() {
			fc.Annotations[render.BPFOperatorAnnotation] = "NotBoolean"
			err := bpfValidateAnnotations(fc)
			Expect(err).Should(HaveOccurred())
		})

		It("should return error if the annotation is nil and the spec field is not", func() {
			fc.Annotations = nil
			fc.Spec.BPFEnabled = &enabled
			err := bpfValidateAnnotations(fc)
			Expect(err).Should(HaveOccurred())
		})

		It("should return error if the annotation is not nil and the spec field is", func() {
			fc.Annotations[render.BPFOperatorAnnotation] = textFalse
			err := bpfValidateAnnotations(fc)
			Expect(err).Should(HaveOccurred())
		})

		It("should return error if the annotation is true and the spec field is false", func() {
			fc.Annotations[render.BPFOperatorAnnotation] = textTrue
			fc.Spec.BPFEnabled = &notEnabled
			err := bpfValidateAnnotations(fc)
			Expect(err).Should(HaveOccurred())
		})

		It("should return error if the annotation is false and the spec field is true", func() {
			fc.Annotations[render.BPFOperatorAnnotation] = textFalse
			fc.Spec.BPFEnabled = &enabled
			err := bpfValidateAnnotations(fc)
			Expect(err).Should(HaveOccurred())
		})

		It("should return valid if both annotation and the spec field are nil", func() {
			fc.Annotations = nil
			err := bpfValidateAnnotations(fc)
			Expect(err).ShouldNot(HaveOccurred())
		})

		It("should return valid if the annotation is false and the spec field is false", func() {
			fc.Annotations[render.BPFOperatorAnnotation] = textFalse
			fc.Spec.BPFEnabled = &notEnabled
			err := bpfValidateAnnotations(fc)
			Expect(err).ShouldNot(HaveOccurred())
		})

		It("should return valid if the annotation is true and the spec field is true", func() {
			fc.Annotations[render.BPFOperatorAnnotation] = textTrue
			fc.Spec.BPFEnabled = &enabled
			err := bpfValidateAnnotations(fc)
			Expect(err).ShouldNot(HaveOccurred())
		})
	})

	Context("Daemonset rollout completion tests", func() {
		var ds *appsv1.DaemonSet
		var bpfVolume corev1.Volume
		BeforeEach(func() {
			ds = &appsv1.DaemonSet{
				ObjectMeta: metav1.ObjectMeta{Name: common.NodeDaemonSetName, Namespace: common.CalicoNamespace},
				Spec: appsv1.DaemonSetSpec{
					Template: corev1.PodTemplateSpec{
						ObjectMeta: metav1.ObjectMeta{},
						Spec: corev1.PodSpec{
							Containers: []corev1.Container{{Name: render.CalicoNodeObjectName, Image: render.CalicoNodeObjectName}},
							Volumes: []corev1.Volume{
								{Name: "other-volume", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/other/volume"}}},
							},
						},
					},
				},
			}

			bpfVolume = corev1.Volume{Name: render.BPFVolumeName}
		})

		It("should return false if volume is not found", func() {
			completed := isRolloutCompleteWithBPFVolumes(ds)
			Expect(completed).To(BeFalse())
		})

		It("should return false if CurrentNumberScheduled is not matching UpdatedNumberScheduled", func() {
			ds.Spec.Template.Spec.Volumes = append(ds.Spec.Template.Spec.Volumes, bpfVolume)

			ds.Status.CurrentNumberScheduled = 4
			ds.Status.UpdatedNumberScheduled = 2
			ds.Status.NumberAvailable = 4
			completed := isRolloutCompleteWithBPFVolumes(ds)
			Expect(completed).To(BeFalse())
		})

		It("should return false if CurrentNumberScheduled is not matching NumberAvailable", func() {
			ds.Spec.Template.Spec.Volumes = append(ds.Spec.Template.Spec.Volumes, bpfVolume)

			ds.Status.CurrentNumberScheduled = 4
			ds.Status.UpdatedNumberScheduled = 4
			ds.Status.NumberAvailable = 2
			completed := isRolloutCompleteWithBPFVolumes(ds)
			Expect(completed).To(BeFalse())
		})

		It("should return true if CurrentNumberScheduled is matching NumberAvailable and CurrentNumberScheduled", func() {
			ds.Spec.Template.Spec.Volumes = append(ds.Spec.Template.Spec.Volumes, bpfVolume)

			ds.Status.CurrentNumberScheduled = 4
			ds.Status.UpdatedNumberScheduled = 4
			ds.Status.NumberAvailable = 4
			completed := isRolloutCompleteWithBPFVolumes(ds)
			Expect(completed).To(BeTrue())
		})
	})

	Context("BPFEnabled on daemonset variable tests", func() {
		var ds *appsv1.DaemonSet

		BeforeEach(func() {
			ds = &appsv1.DaemonSet{
				ObjectMeta: metav1.ObjectMeta{Name: common.NodeDaemonSetName, Namespace: common.CalicoNamespace},
				Spec: appsv1.DaemonSetSpec{
					Template: corev1.PodTemplateSpec{
						ObjectMeta: metav1.ObjectMeta{},
						Spec: corev1.PodSpec{
							Containers: []corev1.Container{{Name: render.CalicoNodeObjectName, Image: render.CalicoNodeObjectName}},
							Volumes: []corev1.Volume{
								{Name: "other-volume", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/other/volume"}}},
							},
						},
					},
				},
			}
		})

		It("should return false if BPFEnabled ENV is nil", func() {
			result, err := bpfEnabledOnDaemonsetWithEnvVar(ds)
			Expect(err).ShouldNot(HaveOccurred())
			Expect(result).To(BeFalse())
		})

		It("should return true if BPFEnabled ENV is set to true", func() {
			ds.Spec.Template.Spec.Containers[0].Env = []corev1.EnvVar{
				{Name: "FELIX_BPFENABLED", Value: "true", ValueFrom: nil},
			}
			result, err := bpfEnabledOnDaemonsetWithEnvVar(ds)
			Expect(err).ShouldNot(HaveOccurred())
			Expect(result).To(BeTrue())
		})

		It("should return false if BPFEnabled ENV is set to false", func() {
			ds.Spec.Template.Spec.Containers[0].Env = []corev1.EnvVar{
				{Name: "FELIX_BPFENABLED", Value: "false", ValueFrom: nil},
			}
			result, err := bpfEnabledOnDaemonsetWithEnvVar(ds)
			Expect(err).ShouldNot(HaveOccurred())
			Expect(result).To(BeFalse())
		})

		It("should return error if BPFEnabled ENV is set to an invalid string", func() {
			ds.Spec.Template.Spec.Containers[0].Env = []corev1.EnvVar{
				{Name: "FELIX_BPFENABLED", Value: "invalid", ValueFrom: nil},
			}
			_, err := bpfEnabledOnDaemonsetWithEnvVar(ds)
			Expect(err).Should(HaveOccurred())
		})
	})

	Context("BPFEnabled on FelixConfiguration tests", func() {
		var fc *v3.FelixConfiguration
		var enabled, notEnabled bool

		enabled = true
		notEnabled = false

		BeforeEach(func() {
			fc = &v3.FelixConfiguration{
				ObjectMeta: metav1.ObjectMeta{
					Name: "default",
				},
				Spec: v3.FelixConfigurationSpec{},
			}
		})

		It("should return false if BPFEnabled field is nil", func() {
			result := bpfEnabledOnFelixConfig(fc)
			Expect(result).To(BeFalse())
		})

		It("should return false if BPFEnabled field is false", func() {
			fc.Spec.BPFEnabled = &notEnabled
			result := bpfEnabledOnFelixConfig(fc)
			Expect(result).To(BeFalse())
		})

		It("should return false if BPFEnabled field is true", func() {
			fc.Spec.BPFEnabled = &enabled
			result := bpfEnabledOnFelixConfig(fc)
			Expect(result).To(BeTrue())
		})
	})

	Context("setBPFEnabledOnFelixConfiguration tests", func() {
		var fc *v3.FelixConfiguration

		BeforeEach(func() {
			fc = &v3.FelixConfiguration{
				ObjectMeta: metav1.ObjectMeta{
					Name: "default",
				},
				Spec: v3.FelixConfigurationSpec{},
			}
		})

		It("should return error if annotation validation failed", func() {
			fc.Annotations = make(map[string]string)
			fc.Annotations[render.BPFOperatorAnnotation] = "NotBoolean"
			err := bpfValidateAnnotations(fc)
			Expect(err).Should(HaveOccurred())
			err = setBPFEnabledOnFelixConfiguration(fc, true)
			Expect(err).Should(HaveOccurred())
		})

		It("should set correct annotation", func() {
			err := setBPFEnabledOnFelixConfiguration(fc, true)
			Expect(err).ShouldNot(HaveOccurred())

			annotations := fc.Annotations[render.BPFOperatorAnnotation]
			Expect(annotations).To(Equal("true"))
			Expect(*fc.Spec.BPFEnabled).To(Equal(true))

			err = setBPFEnabledOnFelixConfiguration(fc, false)
			Expect(err).ShouldNot(HaveOccurred())

			annotations = fc.Annotations[render.BPFOperatorAnnotation]
			Expect(annotations).To(Equal("false"))
			Expect(*fc.Spec.BPFEnabled).To(Equal(false))
		})
	})

	Context("disableBPFKubeProxyHealthz tests", func() {
		It("should set BPFKubeProxyHealthzPort to 0", func() {
			fc := &v3.FelixConfiguration{
				ObjectMeta: metav1.ObjectMeta{Name: "default"},
				Spec:       v3.FelixConfigurationSpec{},
			}
			disableBPFKubeProxyHealthz(fc)
			Expect(fc.Spec.BPFKubeProxyHealthzPort).ShouldNot(BeNil())
			Expect(*fc.Spec.BPFKubeProxyHealthzPort).To(Equal(0))
		})

		It("should overwrite an existing value", func() {
			existing := 12345
			fc := &v3.FelixConfiguration{
				ObjectMeta: metav1.ObjectMeta{Name: "default"},
				Spec:       v3.FelixConfigurationSpec{BPFKubeProxyHealthzPort: &existing},
			}
			disableBPFKubeProxyHealthz(fc)
			Expect(fc.Spec.BPFKubeProxyHealthzPort).ShouldNot(BeNil())
			Expect(*fc.Spec.BPFKubeProxyHealthzPort).To(Equal(0))
		})
	})
})
