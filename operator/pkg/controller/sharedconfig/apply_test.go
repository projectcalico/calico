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

package sharedconfig_test

import (
	"context"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/projectcalico/calico/operator/pkg/apis"
	"github.com/projectcalico/calico/operator/pkg/controller/sharedconfig"
	ctrlrfake "github.com/projectcalico/calico/operator/pkg/ctrlruntime/client/fake"
	"github.com/projectcalico/calico/operator/pkg/render"
)

// declare returns a declaration of healthPort and vxlanPort, with a policy per field.
func declare(healthPolicy, vxlanPolicy sharedconfig.ConflictPolicy) sharedconfig.DeclareFelixConfiguration {
	return func(_ *v3.FelixConfiguration) (*sharedconfig.FelixConfigurationDeclaration, error) {
		return &sharedconfig.FelixConfigurationDeclaration{
			Manager: "installation",
			Owned: &v3.FelixConfiguration{
				Spec: v3.FelixConfigurationSpec{
					HealthPort: ptr.To(9099),
					VXLANPort:  ptr.To(4789),
				},
			},
			Policies: map[string]sharedconfig.ConflictPolicy{
				"spec.healthPort": healthPolicy,
				"spec.vxlanPort":  vxlanPolicy,
			},
		}, nil
	}
}

// declarePolicySync governs spec.policySyncPathPrefix, declaring a value only when prefix is set.
func declarePolicySync(prefix string) sharedconfig.DeclareFelixConfiguration {
	return func(_ *v3.FelixConfiguration) (*sharedconfig.FelixConfigurationDeclaration, error) {
		return &sharedconfig.FelixConfigurationDeclaration{
			Manager:  "policy-sync",
			Owned:    &v3.FelixConfiguration{Spec: v3.FelixConfigurationSpec{PolicySyncPathPrefix: prefix}},
			Policies: map[string]sharedconfig.ConflictPolicy{"spec.policySyncPathPrefix": sharedconfig.ConflictDefer},
		}, nil
	}
}

var _ = Describe("Applying declared FelixConfiguration fields", func() {
	var c client.Client
	var ctx context.Context

	getFelixConfig := func() *v3.FelixConfiguration {
		fc := &v3.FelixConfiguration{}
		Expect(c.Get(ctx, types.NamespacedName{Name: "default"}, fc)).NotTo(HaveOccurred())
		return fc
	}

	Context("projectcalico.org/v3, where the API server tracks ownership", func() {
		var w sharedconfig.Writer

		// applyAs writes healthPort as another field manager, taking the field if it has to.
		applyAs := func(manager string, healthPort int64) {
			other := &unstructured.Unstructured{Object: map[string]any{
				"apiVersion": "projectcalico.org/v3",
				"kind":       "FelixConfiguration",
				"metadata":   map[string]any{"name": "default"},
				"spec":       map[string]any{"healthPort": healthPort},
			}}
			Expect(c.Apply(ctx, client.ApplyConfigurationFromUnstructured(other), client.FieldOwner(manager), client.ForceOwnership)).NotTo(HaveOccurred())
		}

		BeforeEach(func() {
			scheme := runtime.NewScheme()
			Expect(apis.AddToScheme(scheme, true)).NotTo(HaveOccurred())
			c = ctrlrfake.DefaultFakeClientBuilder(scheme).WithReturnManagedFields().Build()
			ctx = context.Background()
			w = sharedconfig.NewWriter(c, true)
		})

		It("should create the FelixConfiguration owning only the declared fields", func() {
			_, err := w.ApplyFelixConfiguration(ctx, declare(sharedconfig.ConflictDefer, sharedconfig.ConflictDefer))
			Expect(err).NotTo(HaveOccurred())

			fc := getFelixConfig()
			Expect(fc.Spec.HealthPort).To(Equal(ptr.To(9099)))
			Expect(fc.Spec.VXLANPort).To(Equal(ptr.To(4789)))
			Expect(fc.ManagedFields).To(HaveLen(1))
			Expect(fc.ManagedFields[0].Manager).To(Equal("tigera-operator/installation"))
			Expect(fc.ManagedFields[0].Operation).To(Equal(metav1.ManagedFieldsOperationApply))
		})

		It("should keep the same values when it applies the same declaration twice", func() {
			_, err := w.ApplyFelixConfiguration(ctx, declare(sharedconfig.ConflictDefer, sharedconfig.ConflictDefer))
			Expect(err).NotTo(HaveOccurred())

			fc, err := w.ApplyFelixConfiguration(ctx, declare(sharedconfig.ConflictDefer, sharedconfig.ConflictDefer))
			Expect(err).NotTo(HaveOccurred())
			Expect(fc.Spec.HealthPort).To(Equal(ptr.To(9099)))
			Expect(fc.Spec.VXLANPort).To(Equal(ptr.To(4789)))
			Expect(getFelixConfig().ManagedFields).To(HaveLen(1))
		})

		It("should leave a deferred field with the other owner and still write the rest", func() {
			applyAs("kubectl", 9100)

			fc, err := w.ApplyFelixConfiguration(ctx, declare(sharedconfig.ConflictDefer, sharedconfig.ConflictDefer))
			Expect(err).NotTo(HaveOccurred())
			Expect(fc.Spec.HealthPort).To(Equal(ptr.To(9100)))
			Expect(fc.Spec.VXLANPort).To(Equal(ptr.To(4789)))

			Expect(getFelixConfig().Spec.HealthPort).To(Equal(ptr.To(9100)))
		})

		It("should take an overridden field back", func() {
			applyAs("kubectl", 9100)

			fc, err := w.ApplyFelixConfiguration(ctx, declare(sharedconfig.ConflictOverride, sharedconfig.ConflictDefer))
			Expect(err).NotTo(HaveOccurred())
			Expect(fc.Spec.HealthPort).To(Equal(ptr.To(9099)))
			Expect(getFelixConfig().Spec.HealthPort).To(Equal(ptr.To(9099)))
		})

		It("should report a conflict on a field it refuses to take", func() {
			applyAs("kubectl", 9100)

			_, err := w.ApplyFelixConfiguration(ctx, declare(sharedconfig.ConflictError, sharedconfig.ConflictDefer))
			Expect(err).To(BeAssignableToTypeOf(&sharedconfig.ConflictingFieldsError{}))
			Expect(err.(*sharedconfig.ConflictingFieldsError).Paths).To(ConsistOf("spec.healthPort"))
			Expect(getFelixConfig().Spec.HealthPort).To(Equal(ptr.To(9100)))
		})

		It("should take a field that already holds the declared value, without arbitrating", func() {
			applyAs("kubectl", 9099)

			fc, err := w.ApplyFelixConfiguration(ctx, declare(sharedconfig.ConflictError, sharedconfig.ConflictDefer))
			Expect(err).NotTo(HaveOccurred())
			Expect(fc.Spec.HealthPort).To(Equal(ptr.To(9099)))
			Expect(getFelixConfig().ManagedFields).To(ContainElement(SatisfyAll(
				HaveField("Manager", "tigera-operator/installation"),
				HaveField("Operation", metav1.ManagedFieldsOperationApply),
			)))
		})

		It("should delete a field it stops declaring, so the declared set has to stay stable", func() {
			_, err := w.ApplyFelixConfiguration(ctx, declare(sharedconfig.ConflictDefer, sharedconfig.ConflictDefer))
			Expect(err).NotTo(HaveOccurred())

			_, err = w.ApplyFelixConfiguration(ctx, func(_ *v3.FelixConfiguration) (*sharedconfig.FelixConfigurationDeclaration, error) {
				return &sharedconfig.FelixConfigurationDeclaration{
					Manager:  "installation",
					Owned:    &v3.FelixConfiguration{Spec: v3.FelixConfigurationSpec{HealthPort: ptr.To(9099)}},
					Policies: map[string]sharedconfig.ConflictPolicy{"spec.healthPort": sharedconfig.ConflictDefer},
				}, nil
			})
			Expect(err).NotTo(HaveOccurred())
			Expect(getFelixConfig().Spec.VXLANPort).To(BeNil())
		})

		Context("a cluster the operator wrote before it applied", func() {
			declareBPF := func(policy sharedconfig.ConflictPolicy) sharedconfig.DeclareFelixConfiguration {
				return func(_ *v3.FelixConfiguration) (*sharedconfig.FelixConfigurationDeclaration, error) {
					return &sharedconfig.FelixConfigurationDeclaration{
						Manager:  "installation-bpf",
						Owned:    &v3.FelixConfiguration{Spec: v3.FelixConfigurationSpec{BPFEnabled: ptr.To(false)}},
						Policies: map[string]sharedconfig.ConflictPolicy{"spec.bpfEnabled": policy},
					}, nil
				}
			}

			// createAsManager writes the way a plain update does, under a manager with no apply
			// of its own.
			createAsManager := func(manager string, annotations map[string]string, spec v3.FelixConfigurationSpec) {
				Expect(c.Create(ctx, &v3.FelixConfiguration{
					ObjectMeta: metav1.ObjectMeta{Name: "default", Annotations: annotations},
					Spec:       spec,
				}, client.FieldOwner(manager))).NotTo(HaveOccurred())
			}

			createByUpdate := func(annotations map[string]string, spec v3.FelixConfigurationSpec) {
				createAsManager("someone-else", annotations, spec)
			}

			It("should take over a field it recorded as its own", func() {
				createByUpdate(map[string]string{render.BPFOperatorAnnotation: "true"},
					v3.FelixConfigurationSpec{BPFEnabled: ptr.To(true)})

				_, err := w.ApplyFelixConfiguration(ctx, declareBPF(sharedconfig.ConflictError))
				Expect(err).NotTo(HaveOccurred())

				fc := getFelixConfig()
				Expect(fc.Spec.BPFEnabled).To(Equal(ptr.To(false)))
				Expect(fc.ManagedFields).To(ContainElement(SatisfyAll(
					HaveField("Manager", "tigera-operator/installation-bpf"),
					HaveField("Operation", metav1.ManagedFieldsOperationApply),
				)))
			})

			It("should refuse a field it has no record of writing", func() {
				createByUpdate(nil, v3.FelixConfigurationSpec{BPFEnabled: ptr.To(true)})

				_, err := w.ApplyFelixConfiguration(ctx, declareBPF(sharedconfig.ConflictError))
				Expect(err).To(BeAssignableToTypeOf(&sharedconfig.ConflictingFieldsError{}))
				Expect(getFelixConfig().Spec.BPFEnabled).To(Equal(ptr.To(true)))
			})

			It("should stop trusting its old record once ownership has moved", func() {
				createByUpdate(map[string]string{render.BPFOperatorAnnotation: "true"},
					v3.FelixConfigurationSpec{BPFEnabled: ptr.To(true)})
				_, err := w.ApplyFelixConfiguration(ctx, declareBPF(sharedconfig.ConflictError))
				Expect(err).NotTo(HaveOccurred())

				// The stale annotation still reads "true", matching the value the user applies.
				other := &unstructured.Unstructured{Object: map[string]any{
					"apiVersion": "projectcalico.org/v3",
					"kind":       "FelixConfiguration",
					"metadata":   map[string]any{"name": "default"},
					"spec":       map[string]any{"bpfEnabled": true},
				}}
				Expect(c.Apply(ctx, client.ApplyConfigurationFromUnstructured(other), client.FieldOwner("kubectl"), client.ForceOwnership)).NotTo(HaveOccurred())

				_, err = w.ApplyFelixConfiguration(ctx, declareBPF(sharedconfig.ConflictError))
				Expect(err).To(BeAssignableToTypeOf(&sharedconfig.ConflictingFieldsError{}))
				Expect(getFelixConfig().Spec.BPFEnabled).To(Equal(ptr.To(true)))
			})

			It("should take over a field its own legacy manager still owns", func() {
				createAsManager("operator", nil, v3.FelixConfigurationSpec{HealthPort: ptr.To(9098)})

				fc, err := w.ApplyFelixConfiguration(ctx, declare(sharedconfig.ConflictDefer, sharedconfig.ConflictDefer))
				Expect(err).NotTo(HaveOccurred())
				Expect(fc.Spec.HealthPort).To(Equal(ptr.To(9099)))

				// Taking the field over moves it out of the legacy manager's field set.
				for _, entry := range getFelixConfig().ManagedFields {
					if entry.Manager == "operator" {
						Expect(entry.FieldsV1.GetRawString()).NotTo(ContainSubstring("healthPort"))
					}
				}
			})

			It("should defer on a field it never recorded, leaving the value alone", func() {
				createByUpdate(nil, v3.FelixConfigurationSpec{HealthPort: ptr.To(9100)})

				fc, err := w.ApplyFelixConfiguration(ctx, declare(sharedconfig.ConflictDefer, sharedconfig.ConflictDefer))
				Expect(err).NotTo(HaveOccurred())
				Expect(fc.Spec.HealthPort).To(Equal(ptr.To(9100)))
				Expect(fc.Spec.VXLANPort).To(Equal(ptr.To(4789)))
			})

			It("should clear a field its legacy manager holds that the declaration dropped", func() {
				createAsManager("operator", nil, v3.FelixConfigurationSpec{PolicySyncPathPrefix: "/var/run/nodeagent"})

				_, err := w.ApplyFelixConfiguration(ctx, declarePolicySync(""))
				Expect(err).NotTo(HaveOccurred())
				Expect(getFelixConfig().Spec.PolicySyncPathPrefix).To(BeEmpty())
			})

			It("should leave a dropped field alone when someone else wrote it", func() {
				createByUpdate(nil, v3.FelixConfigurationSpec{PolicySyncPathPrefix: "/var/run/customer"})

				_, err := w.ApplyFelixConfiguration(ctx, declarePolicySync(""))
				Expect(err).NotTo(HaveOccurred())
				Expect(getFelixConfig().Spec.PolicySyncPathPrefix).To(Equal("/var/run/customer"))
			})

			It("should stop using its record once it has applied the field itself", func() {
				createByUpdate(map[string]string{render.BPFOperatorAnnotation: "true"},
					v3.FelixConfigurationSpec{BPFEnabled: ptr.To(true)})
				_, err := w.ApplyFelixConfiguration(ctx, declareBPF(sharedconfig.ConflictError))
				Expect(err).NotTo(HaveOccurred())
				Expect(getFelixConfig().Spec.BPFEnabled).To(Equal(ptr.To(false)))

				// A user turns it back on by hand, to the value the stale annotation still names.
				fc := getFelixConfig()
				fc.Spec.BPFEnabled = ptr.To(true)
				Expect(c.Update(ctx, fc, client.FieldOwner("kubectl"))).NotTo(HaveOccurred())

				_, err = w.ApplyFelixConfiguration(ctx, declareBPF(sharedconfig.ConflictError))
				Expect(err).To(BeAssignableToTypeOf(&sharedconfig.ConflictingFieldsError{}))
				Expect(getFelixConfig().Spec.BPFEnabled).To(Equal(ptr.To(true)))
			})
		})
	})

	Context("crd.projectcalico.org/v1, where the operator tracks what it wrote", func() {
		var w sharedconfig.Writer

		BeforeEach(func() {
			scheme := runtime.NewScheme()
			Expect(apis.AddToScheme(scheme, false)).NotTo(HaveOccurred())
			c = ctrlrfake.DefaultFakeClientBuilder(scheme).Build()
			ctx = context.Background()
			w = sharedconfig.NewWriter(c, false)
		})

		It("should create the FelixConfiguration and record the values it wrote", func() {
			_, err := w.ApplyFelixConfiguration(ctx, declare(sharedconfig.ConflictDefer, sharedconfig.ConflictDefer))
			Expect(err).NotTo(HaveOccurred())

			fc := getFelixConfig()
			Expect(fc.Spec.HealthPort).To(Equal(ptr.To(9099)))
			Expect(fc.Spec.VXLANPort).To(Equal(ptr.To(4789)))
			Expect(fc.Annotations).To(HaveKeyWithValue("operator.tigera.io/owned-fields",
				`{"spec.healthPort":9099,"spec.vxlanPort":4789}`))
		})

		It("should not write again when the declaration has not changed", func() {
			_, err := w.ApplyFelixConfiguration(ctx, declare(sharedconfig.ConflictDefer, sharedconfig.ConflictDefer))
			Expect(err).NotTo(HaveOccurred())
			before := getFelixConfig().ResourceVersion

			_, err = w.ApplyFelixConfiguration(ctx, declare(sharedconfig.ConflictDefer, sharedconfig.ConflictDefer))
			Expect(err).NotTo(HaveOccurred())
			Expect(getFelixConfig().ResourceVersion).To(Equal(before))
		})

		It("should leave a deferred field alone and drop it from the record", func() {
			_, err := w.ApplyFelixConfiguration(ctx, declare(sharedconfig.ConflictDefer, sharedconfig.ConflictDefer))
			Expect(err).NotTo(HaveOccurred())

			fc := getFelixConfig()
			fc.Spec.HealthPort = ptr.To(9100)
			Expect(c.Update(ctx, fc)).NotTo(HaveOccurred())

			_, err = w.ApplyFelixConfiguration(ctx, declare(sharedconfig.ConflictDefer, sharedconfig.ConflictDefer))
			Expect(err).NotTo(HaveOccurred())

			fc = getFelixConfig()
			Expect(fc.Spec.HealthPort).To(Equal(ptr.To(9100)))
			Expect(fc.Annotations).To(HaveKeyWithValue("operator.tigera.io/owned-fields", `{"spec.vxlanPort":4789}`))
		})

		It("should take an overridden field back", func() {
			_, err := w.ApplyFelixConfiguration(ctx, declare(sharedconfig.ConflictOverride, sharedconfig.ConflictDefer))
			Expect(err).NotTo(HaveOccurred())

			fc := getFelixConfig()
			fc.Spec.HealthPort = ptr.To(9100)
			Expect(c.Update(ctx, fc)).NotTo(HaveOccurred())

			_, err = w.ApplyFelixConfiguration(ctx, declare(sharedconfig.ConflictOverride, sharedconfig.ConflictDefer))
			Expect(err).NotTo(HaveOccurred())
			Expect(getFelixConfig().Spec.HealthPort).To(Equal(ptr.To(9099)))
		})

		It("should report a conflict on a field it refuses to take", func() {
			_, err := w.ApplyFelixConfiguration(ctx, declare(sharedconfig.ConflictError, sharedconfig.ConflictDefer))
			Expect(err).NotTo(HaveOccurred())

			fc := getFelixConfig()
			fc.Spec.HealthPort = ptr.To(9100)
			Expect(c.Update(ctx, fc)).NotTo(HaveOccurred())

			_, err = w.ApplyFelixConfiguration(ctx, declare(sharedconfig.ConflictError, sharedconfig.ConflictDefer))
			Expect(err).To(BeAssignableToTypeOf(&sharedconfig.ConflictingFieldsError{}))
			Expect(getFelixConfig().Spec.HealthPort).To(Equal(ptr.To(9100)))
		})

		It("should treat a value it has no record of as someone else's", func() {
			Expect(c.Create(ctx, &v3.FelixConfiguration{
				ObjectMeta: metav1.ObjectMeta{Name: "default"},
				Spec:       v3.FelixConfigurationSpec{HealthPort: ptr.To(9100)},
			})).NotTo(HaveOccurred())

			_, err := w.ApplyFelixConfiguration(ctx, declare(sharedconfig.ConflictError, sharedconfig.ConflictDefer))
			Expect(err).To(BeAssignableToTypeOf(&sharedconfig.ConflictingFieldsError{}))
		})

		Context("a cluster the operator wrote before it recorded its writes", func() {
			BeforeEach(func() {
				scheme := runtime.NewScheme()
				Expect(apis.AddToScheme(scheme, false)).NotTo(HaveOccurred())
				c = ctrlrfake.DefaultFakeClientBuilder(scheme).WithReturnManagedFields().Build()
				ctx = context.Background()
				w = sharedconfig.NewWriter(c, false)
			})

			createAsManager := func(manager string, spec v3.FelixConfigurationSpec) {
				Expect(c.Create(ctx, &v3.FelixConfiguration{
					ObjectMeta: metav1.ObjectMeta{Name: "default"},
					Spec:       spec,
				}, client.FieldOwner(manager))).NotTo(HaveOccurred())
			}

			It("should take over a field its own legacy manager holds", func() {
				createAsManager("operator", v3.FelixConfigurationSpec{HealthPort: ptr.To(9100)})

				fc, err := w.ApplyFelixConfiguration(ctx, declare(sharedconfig.ConflictError, sharedconfig.ConflictDefer))
				Expect(err).NotTo(HaveOccurred())
				Expect(fc.Spec.HealthPort).To(Equal(ptr.To(9099)))
			})

			It("should clear a field its legacy manager holds that the declaration dropped", func() {
				createAsManager("operator", v3.FelixConfigurationSpec{PolicySyncPathPrefix: "/var/run/nodeagent"})

				_, err := w.ApplyFelixConfiguration(ctx, declarePolicySync(""))
				Expect(err).NotTo(HaveOccurred())
				Expect(getFelixConfig().Spec.PolicySyncPathPrefix).To(BeEmpty())
			})

			It("should leave a dropped field alone when someone else wrote it", func() {
				createAsManager("someone-else", v3.FelixConfigurationSpec{PolicySyncPathPrefix: "/var/run/customer"})

				_, err := w.ApplyFelixConfiguration(ctx, declarePolicySync(""))
				Expect(err).NotTo(HaveOccurred())
				Expect(getFelixConfig().Spec.PolicySyncPathPrefix).To(Equal("/var/run/customer"))
			})
		})

		Context("bpfEnabled, which older operators recorded in their own annotation", func() {
			declareBPF := func(policy sharedconfig.ConflictPolicy) sharedconfig.DeclareFelixConfiguration {
				return func(_ *v3.FelixConfiguration) (*sharedconfig.FelixConfigurationDeclaration, error) {
					return &sharedconfig.FelixConfigurationDeclaration{
						Manager:  "installation",
						Owned:    &v3.FelixConfiguration{Spec: v3.FelixConfigurationSpec{BPFEnabled: ptr.To(true)}},
						Policies: map[string]sharedconfig.ConflictPolicy{"spec.bpfEnabled": policy},
					}, nil
				}
			}

			It("should accept the legacy annotation as its own record", func() {
				Expect(c.Create(ctx, &v3.FelixConfiguration{
					ObjectMeta: metav1.ObjectMeta{
						Name:        "default",
						Annotations: map[string]string{render.BPFOperatorAnnotation: "true"},
					},
					Spec: v3.FelixConfigurationSpec{BPFEnabled: ptr.To(true)},
				})).NotTo(HaveOccurred())

				_, err := w.ApplyFelixConfiguration(ctx, declareBPF(sharedconfig.ConflictError))
				Expect(err).NotTo(HaveOccurred())
				Expect(getFelixConfig().Spec.BPFEnabled).To(Equal(ptr.To(true)))
			})

			It("should take over a value someone else set, when it wanted that value anyway", func() {
				Expect(c.Create(ctx, &v3.FelixConfiguration{
					ObjectMeta: metav1.ObjectMeta{
						Name:        "default",
						Annotations: map[string]string{render.BPFOperatorAnnotation: "false"},
					},
					Spec: v3.FelixConfigurationSpec{BPFEnabled: ptr.To(true)},
				})).NotTo(HaveOccurred())

				_, err := w.ApplyFelixConfiguration(ctx, declareBPF(sharedconfig.ConflictError))
				Expect(err).NotTo(HaveOccurred())
				fc := getFelixConfig()
				Expect(fc.Spec.BPFEnabled).To(Equal(ptr.To(true)))
				Expect(fc.Annotations).To(HaveKeyWithValue(render.BPFOperatorAnnotation, "true"))
			})

			It("should refuse to change a value someone else set", func() {
				Expect(c.Create(ctx, &v3.FelixConfiguration{
					ObjectMeta: metav1.ObjectMeta{Name: "default"},
					Spec:       v3.FelixConfigurationSpec{BPFEnabled: ptr.To(false)},
				})).NotTo(HaveOccurred())

				_, err := w.ApplyFelixConfiguration(ctx, declareBPF(sharedconfig.ConflictError))
				Expect(err).To(MatchError(ContainSubstring("spec.bpfEnabled")))
				Expect(getFelixConfig().Spec.BPFEnabled).To(Equal(ptr.To(false)))
			})

			It("should keep the legacy annotation in step with what it writes", func() {
				_, err := w.ApplyFelixConfiguration(ctx, declareBPF(sharedconfig.ConflictDefer))
				Expect(err).NotTo(HaveOccurred())
				Expect(getFelixConfig().Annotations).To(HaveKeyWithValue(render.BPFOperatorAnnotation, "true"))
			})
		})
	})
})
