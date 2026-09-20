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

package managedfields_test

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
	"github.com/projectcalico/calico/operator/pkg/controller/managedfields"
	ctrlrfake "github.com/projectcalico/calico/operator/pkg/ctrlruntime/client/fake"
	"github.com/projectcalico/calico/operator/pkg/render"
)

// declare returns a declaration of healthPort and vxlanPort, with a policy per field.
func declare(healthPolicy, vxlanPolicy managedfields.ConflictPolicy) managedfields.Declare[*v3.FelixConfiguration] {
	return func(_ *v3.FelixConfiguration) (*managedfields.Declaration[*v3.FelixConfiguration], error) {
		return &managedfields.Declaration[*v3.FelixConfiguration]{
			Manager: "installation",
			Owned: &v3.FelixConfiguration{
				Spec: v3.FelixConfigurationSpec{
					HealthPort: ptr.To(9099),
					VXLANPort:  ptr.To(4789),
				},
			},
			Policies: map[string]managedfields.ConflictPolicy{
				"spec.healthPort": healthPolicy,
				"spec.vxlanPort":  vxlanPolicy,
			},
		}, nil
	}
}

// declarePolicySync governs spec.policySyncPathPrefix, declaring a value only when prefix is set.
func declarePolicySync(prefix string) managedfields.Declare[*v3.FelixConfiguration] {
	return func(_ *v3.FelixConfiguration) (*managedfields.Declaration[*v3.FelixConfiguration], error) {
		return &managedfields.Declaration[*v3.FelixConfiguration]{
			Manager:  "policy-sync",
			Owned:    &v3.FelixConfiguration{Spec: v3.FelixConfigurationSpec{PolicySyncPathPrefix: prefix}},
			Policies: map[string]managedfields.ConflictPolicy{"spec.policySyncPathPrefix": managedfields.ConflictDefer},
		}, nil
	}
}

// declareRouteTableRange governs spec.routeTableRange, a struct field the API server records
// field by field, declaring a value only when one is given.
func declareRouteTableRange(r *v3.RouteTableRange) managedfields.Declare[*v3.FelixConfiguration] {
	return func(_ *v3.FelixConfiguration) (*managedfields.Declaration[*v3.FelixConfiguration], error) {
		return &managedfields.Declaration[*v3.FelixConfiguration]{
			Manager:  "installation",
			Owned:    &v3.FelixConfiguration{Spec: v3.FelixConfigurationSpec{RouteTableRange: r}},
			Policies: map[string]managedfields.ConflictPolicy{"spec.routeTableRange": managedfields.ConflictDefer},
		}, nil
	}
}

// declareRefusedPlusOne governs a field the operator will not arbitrate (spec.bpfEnabled) and
// one it merely defaults, so a test can check the second still lands when the first is refused.
func declareRefusedPlusOne() managedfields.Declare[*v3.FelixConfiguration] {
	return func(_ *v3.FelixConfiguration) (*managedfields.Declaration[*v3.FelixConfiguration], error) {
		return &managedfields.Declaration[*v3.FelixConfiguration]{
			Manager: "installation-bpf",
			Owned: &v3.FelixConfiguration{
				Spec: v3.FelixConfigurationSpec{
					BPFEnabled: ptr.To(false),
					HealthPort: ptr.To(9099),
				},
			},
			Policies: map[string]managedfields.ConflictPolicy{
				"spec.bpfEnabled": managedfields.ConflictError,
				"spec.healthPort": managedfields.ConflictDefer,
			},
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
		var w *managedfields.FieldManager

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
			w = managedfields.New(c, true)
		})

		It("should create the FelixConfiguration owning only the declared fields", func() {
			_, err := declare(managedfields.ConflictDefer, managedfields.ConflictDefer).Apply(ctx, w)
			Expect(err).NotTo(HaveOccurred())

			fc := getFelixConfig()
			Expect(fc.Spec.HealthPort).To(Equal(ptr.To(9099)))
			Expect(fc.Spec.VXLANPort).To(Equal(ptr.To(4789)))
			Expect(fc.ManagedFields).To(HaveLen(1))
			Expect(fc.ManagedFields[0].Manager).To(Equal("tigera-operator/installation"))
			Expect(fc.ManagedFields[0].Operation).To(Equal(metav1.ManagedFieldsOperationApply))
		})

		It("should keep the same values when it applies the same declaration twice", func() {
			_, err := declare(managedfields.ConflictDefer, managedfields.ConflictDefer).Apply(ctx, w)
			Expect(err).NotTo(HaveOccurred())

			fc, err := declare(managedfields.ConflictDefer, managedfields.ConflictDefer).Apply(ctx, w)
			Expect(err).NotTo(HaveOccurred())
			Expect(fc.Spec.HealthPort).To(Equal(ptr.To(9099)))
			Expect(fc.Spec.VXLANPort).To(Equal(ptr.To(4789)))
			Expect(getFelixConfig().ManagedFields).To(HaveLen(1))
		})

		It("should leave a deferred field with the other owner and still write the rest", func() {
			applyAs("kubectl", 9100)

			fc, err := declare(managedfields.ConflictDefer, managedfields.ConflictDefer).Apply(ctx, w)
			Expect(err).NotTo(HaveOccurred())
			Expect(fc.Spec.HealthPort).To(Equal(ptr.To(9100)))
			Expect(fc.Spec.VXLANPort).To(Equal(ptr.To(4789)))

			Expect(getFelixConfig().Spec.HealthPort).To(Equal(ptr.To(9100)))
		})

		It("should take an overridden field back", func() {
			applyAs("kubectl", 9100)

			fc, err := declare(managedfields.ConflictOverride, managedfields.ConflictDefer).Apply(ctx, w)
			Expect(err).NotTo(HaveOccurred())
			Expect(fc.Spec.HealthPort).To(Equal(ptr.To(9099)))
			Expect(getFelixConfig().Spec.HealthPort).To(Equal(ptr.To(9099)))
		})

		It("should report a conflict on a field it refuses to take", func() {
			applyAs("kubectl", 9100)

			_, err := declare(managedfields.ConflictError, managedfields.ConflictDefer).Apply(ctx, w)
			Expect(err).To(BeAssignableToTypeOf(&managedfields.ConflictingFieldsError{}))
			Expect(err.(*managedfields.ConflictingFieldsError).Paths).To(ConsistOf("spec.healthPort"))
			Expect(getFelixConfig().Spec.HealthPort).To(Equal(ptr.To(9100)))
		})

		It("should take a field that already holds the declared value, without arbitrating", func() {
			applyAs("kubectl", 9099)

			fc, err := declare(managedfields.ConflictError, managedfields.ConflictDefer).Apply(ctx, w)
			Expect(err).NotTo(HaveOccurred())
			Expect(fc.Spec.HealthPort).To(Equal(ptr.To(9099)))
			Expect(getFelixConfig().ManagedFields).To(ContainElement(SatisfyAll(
				HaveField("Manager", "tigera-operator/installation"),
				HaveField("Operation", metav1.ManagedFieldsOperationApply),
			)))
		})

		It("should delete a field it stops declaring, so the declared set has to stay stable", func() {
			_, err := declare(managedfields.ConflictDefer, managedfields.ConflictDefer).Apply(ctx, w)
			Expect(err).NotTo(HaveOccurred())

			_, err = managedfields.Declare[*v3.FelixConfiguration](func(_ *v3.FelixConfiguration) (*managedfields.Declaration[*v3.FelixConfiguration], error) {
				return &managedfields.Declaration[*v3.FelixConfiguration]{
					Manager:  "installation",
					Owned:    &v3.FelixConfiguration{Spec: v3.FelixConfigurationSpec{HealthPort: ptr.To(9099)}},
					Policies: map[string]managedfields.ConflictPolicy{"spec.healthPort": managedfields.ConflictDefer},
				}, nil
			}).Apply(ctx, w)
			Expect(err).NotTo(HaveOccurred())
			Expect(getFelixConfig().Spec.VXLANPort).To(BeNil())
		})

		Context("a cluster the operator wrote before it applied", func() {
			declareBPF := func(policy managedfields.ConflictPolicy) managedfields.Declare[*v3.FelixConfiguration] {
				return func(_ *v3.FelixConfiguration) (*managedfields.Declaration[*v3.FelixConfiguration], error) {
					return &managedfields.Declaration[*v3.FelixConfiguration]{
						Manager:  "installation-bpf",
						Owned:    &v3.FelixConfiguration{Spec: v3.FelixConfigurationSpec{BPFEnabled: ptr.To(false)}},
						Policies: map[string]managedfields.ConflictPolicy{"spec.bpfEnabled": policy},
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

				_, err := declareBPF(managedfields.ConflictError).Apply(ctx, w)
				Expect(err).NotTo(HaveOccurred())

				fc := getFelixConfig()
				Expect(fc.Spec.BPFEnabled).To(Equal(ptr.To(false)))
				Expect(fc.ManagedFields).To(ContainElement(SatisfyAll(
					HaveField("Manager", "tigera-operator/installation-bpf"),
					HaveField("Operation", metav1.ManagedFieldsOperationApply),
				)))
			})

			It("should write the rest of the declaration when one field is refused", func() {
				createByUpdate(nil, v3.FelixConfigurationSpec{BPFEnabled: ptr.To(true)})

				fc, err := declareRefusedPlusOne().Apply(ctx, w)
				Expect(err).To(BeAssignableToTypeOf(&managedfields.ConflictingFieldsError{}))
				Expect(fc).NotTo(BeNil())

				// The refused field keeps the other writer's value; the rest still lands.
				stored := getFelixConfig()
				Expect(stored.Spec.BPFEnabled).To(Equal(ptr.To(true)))
				Expect(stored.Spec.HealthPort).To(Equal(ptr.To(9099)))
			})

			It("should refuse a field it has no record of writing", func() {
				createByUpdate(nil, v3.FelixConfigurationSpec{BPFEnabled: ptr.To(true)})

				_, err := declareBPF(managedfields.ConflictError).Apply(ctx, w)
				Expect(err).To(BeAssignableToTypeOf(&managedfields.ConflictingFieldsError{}))
				Expect(getFelixConfig().Spec.BPFEnabled).To(Equal(ptr.To(true)))
			})

			It("should stop trusting its old record once ownership has moved", func() {
				createByUpdate(map[string]string{render.BPFOperatorAnnotation: "true"},
					v3.FelixConfigurationSpec{BPFEnabled: ptr.To(true)})
				_, err := declareBPF(managedfields.ConflictError).Apply(ctx, w)
				Expect(err).NotTo(HaveOccurred())

				// The stale annotation still reads "true", matching the value the user applies.
				other := &unstructured.Unstructured{Object: map[string]any{
					"apiVersion": "projectcalico.org/v3",
					"kind":       "FelixConfiguration",
					"metadata":   map[string]any{"name": "default"},
					"spec":       map[string]any{"bpfEnabled": true},
				}}
				Expect(c.Apply(ctx, client.ApplyConfigurationFromUnstructured(other), client.FieldOwner("kubectl"), client.ForceOwnership)).NotTo(HaveOccurred())

				_, err = declareBPF(managedfields.ConflictError).Apply(ctx, w)
				Expect(err).To(BeAssignableToTypeOf(&managedfields.ConflictingFieldsError{}))
				Expect(getFelixConfig().Spec.BPFEnabled).To(Equal(ptr.To(true)))
			})

			It("should take over a field another manager applied when its record says it wrote the value", func() {
				// A server-side apply owns the field, so no update manager holds it and the
				// operator's record is the only evidence of who wrote the value.
				other := &unstructured.Unstructured{Object: map[string]any{
					"apiVersion": "projectcalico.org/v3",
					"kind":       "FelixConfiguration",
					"metadata":   map[string]any{"name": "default"},
					"spec":       map[string]any{"bpfEnabled": true},
				}}
				Expect(c.Apply(ctx, client.ApplyConfigurationFromUnstructured(other), client.FieldOwner("kubectl"))).NotTo(HaveOccurred())

				fc := getFelixConfig()
				fc.Annotations = map[string]string{render.BPFOperatorAnnotation: "true"}
				Expect(c.Update(ctx, fc, client.FieldOwner("operator"))).NotTo(HaveOccurred())

				_, err := declareBPF(managedfields.ConflictError).Apply(ctx, w)
				Expect(err).NotTo(HaveOccurred())
				Expect(getFelixConfig().Spec.BPFEnabled).To(Equal(ptr.To(false)))
			})

			It("should take over a field its own legacy manager still owns", func() {
				createAsManager("operator", nil, v3.FelixConfigurationSpec{HealthPort: ptr.To(9098)})

				fc, err := declare(managedfields.ConflictDefer, managedfields.ConflictDefer).Apply(ctx, w)
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

				fc, err := declare(managedfields.ConflictDefer, managedfields.ConflictDefer).Apply(ctx, w)
				Expect(err).NotTo(HaveOccurred())
				Expect(fc.Spec.HealthPort).To(Equal(ptr.To(9100)))
				Expect(fc.Spec.VXLANPort).To(Equal(ptr.To(4789)))
			})

			It("should take over a struct field its own legacy manager still owns", func() {
				createAsManager("operator", nil, v3.FelixConfigurationSpec{RouteTableRange: &v3.RouteTableRange{Min: 1, Max: 50}})

				fc, err := declareRouteTableRange(&v3.RouteTableRange{Min: 65, Max: 99}).Apply(ctx, w)
				Expect(err).NotTo(HaveOccurred())
				Expect(fc.Spec.RouteTableRange).To(Equal(&v3.RouteTableRange{Min: 65, Max: 99}))
			})

			It("should clear a struct field its legacy manager holds that the declaration dropped", func() {
				createAsManager("operator", nil, v3.FelixConfigurationSpec{RouteTableRange: &v3.RouteTableRange{Min: 1, Max: 50}})

				_, err := declareRouteTableRange(nil).Apply(ctx, w)
				Expect(err).NotTo(HaveOccurred())
				Expect(getFelixConfig().Spec.RouteTableRange).To(BeNil())
			})

			It("should clear a field its legacy manager holds that the declaration dropped", func() {
				createAsManager("operator", nil, v3.FelixConfigurationSpec{PolicySyncPathPrefix: "/var/run/nodeagent"})

				_, err := declarePolicySync("").Apply(ctx, w)
				Expect(err).NotTo(HaveOccurred())
				Expect(getFelixConfig().Spec.PolicySyncPathPrefix).To(BeEmpty())
			})

			It("should leave a dropped field alone when someone else wrote it", func() {
				createByUpdate(nil, v3.FelixConfigurationSpec{PolicySyncPathPrefix: "/var/run/customer"})

				_, err := declarePolicySync("").Apply(ctx, w)
				Expect(err).NotTo(HaveOccurred())
				Expect(getFelixConfig().Spec.PolicySyncPathPrefix).To(Equal("/var/run/customer"))
			})

			It("should stop using its record once it has applied the field itself", func() {
				createByUpdate(map[string]string{render.BPFOperatorAnnotation: "true"},
					v3.FelixConfigurationSpec{BPFEnabled: ptr.To(true)})
				_, err := declareBPF(managedfields.ConflictError).Apply(ctx, w)
				Expect(err).NotTo(HaveOccurred())
				Expect(getFelixConfig().Spec.BPFEnabled).To(Equal(ptr.To(false)))

				// A user turns it back on by hand, to the value the stale annotation still names.
				fc := getFelixConfig()
				fc.Spec.BPFEnabled = ptr.To(true)
				Expect(c.Update(ctx, fc, client.FieldOwner("kubectl"))).NotTo(HaveOccurred())

				_, err = declareBPF(managedfields.ConflictError).Apply(ctx, w)
				Expect(err).To(BeAssignableToTypeOf(&managedfields.ConflictingFieldsError{}))
				Expect(getFelixConfig().Spec.BPFEnabled).To(Equal(ptr.To(true)))
			})
		})
	})

	Context("crd.projectcalico.org/v1, where the operator tracks what it wrote", func() {
		var w *managedfields.FieldManager

		BeforeEach(func() {
			scheme := runtime.NewScheme()
			Expect(apis.AddToScheme(scheme, false)).NotTo(HaveOccurred())
			c = ctrlrfake.DefaultFakeClientBuilder(scheme).Build()
			ctx = context.Background()
			w = managedfields.New(c, false)
		})

		It("should create the FelixConfiguration and record the values it wrote", func() {
			_, err := declare(managedfields.ConflictDefer, managedfields.ConflictDefer).Apply(ctx, w)
			Expect(err).NotTo(HaveOccurred())

			fc := getFelixConfig()
			Expect(fc.Spec.HealthPort).To(Equal(ptr.To(9099)))
			Expect(fc.Spec.VXLANPort).To(Equal(ptr.To(4789)))
			Expect(fc.Annotations).To(HaveKeyWithValue("operator.tigera.io/owned-fields",
				`{"spec.healthPort":9099,"spec.vxlanPort":4789}`))
		})

		It("should not write again when the declaration has not changed", func() {
			_, err := declare(managedfields.ConflictDefer, managedfields.ConflictDefer).Apply(ctx, w)
			Expect(err).NotTo(HaveOccurred())
			before := getFelixConfig().ResourceVersion

			_, err = declare(managedfields.ConflictDefer, managedfields.ConflictDefer).Apply(ctx, w)
			Expect(err).NotTo(HaveOccurred())
			Expect(getFelixConfig().ResourceVersion).To(Equal(before))
		})

		It("should leave a deferred field alone and drop it from the record", func() {
			_, err := declare(managedfields.ConflictDefer, managedfields.ConflictDefer).Apply(ctx, w)
			Expect(err).NotTo(HaveOccurred())

			fc := getFelixConfig()
			fc.Spec.HealthPort = ptr.To(9100)
			Expect(c.Update(ctx, fc)).NotTo(HaveOccurred())

			_, err = declare(managedfields.ConflictDefer, managedfields.ConflictDefer).Apply(ctx, w)
			Expect(err).NotTo(HaveOccurred())

			fc = getFelixConfig()
			Expect(fc.Spec.HealthPort).To(Equal(ptr.To(9100)))
			Expect(fc.Annotations).To(HaveKeyWithValue("operator.tigera.io/owned-fields", `{"spec.vxlanPort":4789}`))
		})

		It("should take an overridden field back", func() {
			_, err := declare(managedfields.ConflictOverride, managedfields.ConflictDefer).Apply(ctx, w)
			Expect(err).NotTo(HaveOccurred())

			fc := getFelixConfig()
			fc.Spec.HealthPort = ptr.To(9100)
			Expect(c.Update(ctx, fc)).NotTo(HaveOccurred())

			_, err = declare(managedfields.ConflictOverride, managedfields.ConflictDefer).Apply(ctx, w)
			Expect(err).NotTo(HaveOccurred())
			Expect(getFelixConfig().Spec.HealthPort).To(Equal(ptr.To(9099)))
		})

		It("should report a conflict on a field it refuses to take", func() {
			_, err := declare(managedfields.ConflictError, managedfields.ConflictDefer).Apply(ctx, w)
			Expect(err).NotTo(HaveOccurred())

			fc := getFelixConfig()
			fc.Spec.HealthPort = ptr.To(9100)
			Expect(c.Update(ctx, fc)).NotTo(HaveOccurred())

			_, err = declare(managedfields.ConflictError, managedfields.ConflictDefer).Apply(ctx, w)
			Expect(err).To(BeAssignableToTypeOf(&managedfields.ConflictingFieldsError{}))
			Expect(getFelixConfig().Spec.HealthPort).To(Equal(ptr.To(9100)))
		})

		It("should keep a deferred field a user set at the declared value out of its record", func() {
			Expect(c.Create(ctx, &v3.FelixConfiguration{
				ObjectMeta: metav1.ObjectMeta{Name: "default"},
				Spec:       v3.FelixConfigurationSpec{HealthPort: ptr.To(9099)},
			})).NotTo(HaveOccurred())

			_, err := declare(managedfields.ConflictDefer, managedfields.ConflictDefer).Apply(ctx, w)
			Expect(err).NotTo(HaveOccurred())

			_, err = managedfields.Declare[*v3.FelixConfiguration](func(_ *v3.FelixConfiguration) (*managedfields.Declaration[*v3.FelixConfiguration], error) {
				return &managedfields.Declaration[*v3.FelixConfiguration]{
					Manager: "installation",
					Owned:   &v3.FelixConfiguration{Spec: v3.FelixConfigurationSpec{VXLANPort: ptr.To(4789)}},
					Policies: map[string]managedfields.ConflictPolicy{
						"spec.healthPort": managedfields.ConflictDefer,
						"spec.vxlanPort":  managedfields.ConflictDefer,
					},
				}, nil
			}).Apply(ctx, w)
			Expect(err).NotTo(HaveOccurred())
			Expect(getFelixConfig().Spec.HealthPort).To(Equal(ptr.To(9099)))
		})

		It("should treat a value it has no record of as someone else's", func() {
			Expect(c.Create(ctx, &v3.FelixConfiguration{
				ObjectMeta: metav1.ObjectMeta{Name: "default"},
				Spec:       v3.FelixConfigurationSpec{HealthPort: ptr.To(9100)},
			})).NotTo(HaveOccurred())

			_, err := declare(managedfields.ConflictError, managedfields.ConflictDefer).Apply(ctx, w)
			Expect(err).To(BeAssignableToTypeOf(&managedfields.ConflictingFieldsError{}))
		})

		Context("a cluster the operator wrote before it recorded its writes", func() {
			BeforeEach(func() {
				scheme := runtime.NewScheme()
				Expect(apis.AddToScheme(scheme, false)).NotTo(HaveOccurred())
				c = ctrlrfake.DefaultFakeClientBuilder(scheme).WithReturnManagedFields().Build()
				ctx = context.Background()
				w = managedfields.New(c, false)
			})

			createAsManager := func(manager string, spec v3.FelixConfigurationSpec) {
				Expect(c.Create(ctx, &v3.FelixConfiguration{
					ObjectMeta: metav1.ObjectMeta{Name: "default"},
					Spec:       spec,
				}, client.FieldOwner(manager))).NotTo(HaveOccurred())
			}

			It("should take over a field its own legacy manager holds", func() {
				createAsManager("operator", v3.FelixConfigurationSpec{HealthPort: ptr.To(9100)})

				fc, err := declare(managedfields.ConflictError, managedfields.ConflictDefer).Apply(ctx, w)
				Expect(err).NotTo(HaveOccurred())
				Expect(fc.Spec.HealthPort).To(Equal(ptr.To(9099)))
			})

			It("should clear a field its legacy manager holds that the declaration dropped", func() {
				createAsManager("operator", v3.FelixConfigurationSpec{PolicySyncPathPrefix: "/var/run/nodeagent"})

				_, err := declarePolicySync("").Apply(ctx, w)
				Expect(err).NotTo(HaveOccurred())
				Expect(getFelixConfig().Spec.PolicySyncPathPrefix).To(BeEmpty())
			})

			It("should leave a dropped field alone when someone else wrote it", func() {
				createAsManager("someone-else", v3.FelixConfigurationSpec{PolicySyncPathPrefix: "/var/run/customer"})

				_, err := declarePolicySync("").Apply(ctx, w)
				Expect(err).NotTo(HaveOccurred())
				Expect(getFelixConfig().Spec.PolicySyncPathPrefix).To(Equal("/var/run/customer"))
			})
		})

		Context("bpfEnabled, which older operators recorded in their own annotation", func() {
			declareBPF := func(policy managedfields.ConflictPolicy) managedfields.Declare[*v3.FelixConfiguration] {
				return func(_ *v3.FelixConfiguration) (*managedfields.Declaration[*v3.FelixConfiguration], error) {
					return &managedfields.Declaration[*v3.FelixConfiguration]{
						Manager:  "installation",
						Owned:    &v3.FelixConfiguration{Spec: v3.FelixConfigurationSpec{BPFEnabled: ptr.To(true)}},
						Policies: map[string]managedfields.ConflictPolicy{"spec.bpfEnabled": policy},
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

				_, err := declareBPF(managedfields.ConflictError).Apply(ctx, w)
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

				_, err := declareBPF(managedfields.ConflictError).Apply(ctx, w)
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

				_, err := declareBPF(managedfields.ConflictError).Apply(ctx, w)
				Expect(err).To(MatchError(ContainSubstring("spec.bpfEnabled")))
				Expect(getFelixConfig().Spec.BPFEnabled).To(Equal(ptr.To(false)))
			})

			It("should keep the legacy annotation in step with what it writes", func() {
				_, err := declareBPF(managedfields.ConflictDefer).Apply(ctx, w)
				Expect(err).NotTo(HaveOccurred())
				Expect(getFelixConfig().Annotations).To(HaveKeyWithValue(render.BPFOperatorAnnotation, "true"))
			})
		})
	})
})
