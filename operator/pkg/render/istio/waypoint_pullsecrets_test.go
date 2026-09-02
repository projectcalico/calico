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

package istio_test

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/projectcalico/calico/operator/pkg/common"
	"github.com/projectcalico/calico/operator/pkg/render/istio"
)

var _ = Describe("Waypoint pull secret render", func() {
	const ns = "user-ns"

	pullSecret := func(name string) *corev1.Secret {
		return &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      name,
				Namespace: common.OperatorNamespace(),
			},
			Type: corev1.SecretTypeDockerConfigJson,
			Data: map[string][]byte{".dockerconfigjson": []byte(`{"auths":{}}`)},
		}
	}

	Context("WaypointPullSecretObjects", func() {
		It("returns the RoleBinding ahead of the secret copies", func() {
			// The RoleBinding is the grant that lets the operator write the copies, so it
			// has to be applied before them.
			objs := istio.WaypointPullSecretObjects(ns, []*corev1.Secret{pullSecret("a"), pullSecret("b")})

			Expect(objs).To(HaveLen(3))
			Expect(objs[0]).To(BeAssignableToTypeOf(&rbacv1.RoleBinding{}))
			Expect(objs[0].GetName()).To(Equal("tigera-operator-secrets"))
			Expect(objs[1]).To(BeAssignableToTypeOf(&corev1.Secret{}))
			Expect(objs[2]).To(BeAssignableToTypeOf(&corev1.Secret{}))
		})

		It("puts every object in the requested namespace", func() {
			objs := istio.WaypointPullSecretObjects(ns, []*corev1.Secret{pullSecret("a")})

			for _, o := range objs {
				Expect(o.GetNamespace()).To(Equal(ns), "%T %s in wrong namespace", o, o.GetName())
			}
		})

		It("marks every object for merged ownership", func() {
			// These land in user namespaces other features write to as well, so the owner
			// reference the component handler adds has to merge rather than replace. Without
			// the label an owner another feature added is dropped, and its objects are
			// garbage collected when the CR owning them here goes away.
			objs := istio.WaypointPullSecretObjects(ns, []*corev1.Secret{pullSecret("a")})

			Expect(objs).To(HaveLen(2))
			for _, o := range objs {
				Expect(o.GetLabels()).To(HaveKeyWithValue(common.MultipleOwnersLabel, "true"),
					"%T %s is missing the label", o, o.GetName())
			}
		})

		It("copies the pull secret contents and keeps the source name", func() {
			// The copy has to be usable as an imagePullSecret, and the waypoint pod spec
			// refers to it by the name the Installation gave it.
			objs := istio.WaypointPullSecretObjects(ns, []*corev1.Secret{pullSecret("my-pull-secret")})

			Expect(objs).To(HaveLen(2))
			copied, ok := objs[1].(*corev1.Secret)
			Expect(ok).To(BeTrue())
			Expect(copied.Name).To(Equal("my-pull-secret"))
			Expect(copied.Type).To(Equal(corev1.SecretTypeDockerConfigJson))
			Expect(copied.Data).To(HaveKeyWithValue(".dockerconfigjson", []byte(`{"auths":{}}`)))
		})

		It("returns only the RoleBinding when there are no pull secrets", func() {
			objs := istio.WaypointPullSecretObjects(ns, nil)

			Expect(objs).To(HaveLen(1))
			Expect(objs[0]).To(BeAssignableToTypeOf(&rbacv1.RoleBinding{}))
		})
	})
})
