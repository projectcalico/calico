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

package istio

import (
	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/projectcalico/calico/operator/pkg/common"
	"github.com/projectcalico/calico/operator/pkg/render"
	"github.com/projectcalico/calico/operator/pkg/render/common/secret"
)

// WaypointPullSecretObjects returns the objects a namespace containing waypoint Gateways needs
// so its waypoint pods can pull images from a private registry:
//
//   - A tigera-operator-secrets RoleBinding granting the operator permission to manage secrets
//     in the namespace.
//   - A copy of each Installation pull secret.
//
// The RoleBinding is ordered first: it is the grant that lets the operator write the copies
// that follow it.
//
// Every object carries MultipleOwnersLabel, which makes the component handler merge the owner
// reference it adds into the owners already on the object instead of replacing them. These land
// in user namespaces that other features write to as well — an egress gateway in the same
// namespace renders the same RoleBinding — and replacing its owner reference would have that
// feature's objects garbage collected when the CR owning them here is deleted. Stamping the
// label here keeps the invariant with the objects, so anything added to the set inherits it.
//
// Which namespaces get these is a question about live cluster state and stays with the caller.
func WaypointPullSecretObjects(namespace string, pullSecrets []*corev1.Secret) []client.Object {
	objs := []client.Object{render.CreateOperatorSecretsRoleBinding(namespace)}
	objs = append(objs, secret.ToRuntimeObjects(secret.CopyToNamespace(namespace, pullSecrets...)...)...)

	for _, obj := range objs {
		labels := common.MapExistsOrInitialize(obj.GetLabels())
		labels[common.MultipleOwnersLabel] = "true"
		obj.SetLabels(labels)
	}

	return objs
}
