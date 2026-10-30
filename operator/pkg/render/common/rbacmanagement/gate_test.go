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

package rbacmanagement_test

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"

	"github.com/projectcalico/calico/operator/pkg/render/common/rbacmanagement"
)

// The gate is hand-edited by an admin, and only the exact value "true" switches
// the feature on. Anything else leaves the feature, and all of its access, off.
// The spellings ui-apis rejects are pinned here too, since a value that enables
// one side and not the other renders RBAC for a feature that will not serve.
var _ = DescribeTable("Enabled",
	func(cm *corev1.ConfigMap, expected bool) {
		Expect(rbacmanagement.Enabled(cm)).To(Equal(expected))
	},
	Entry("nil ConfigMap (never created, or deleted)", nil, false),
	Entry("missing key", &corev1.ConfigMap{Data: map[string]string{}}, false),
	Entry("explicitly disabled", &corev1.ConfigMap{Data: map[string]string{rbacmanagement.ConfigMapKey: "false"}}, false),
	Entry("enabled", &corev1.ConfigMap{Data: map[string]string{rbacmanagement.ConfigMapKey: "true"}}, true),
	Entry("capitalised stays off, as in ui-apis", &corev1.ConfigMap{Data: map[string]string{rbacmanagement.ConfigMapKey: "True"}}, false),
	Entry("1 stays off, as in ui-apis", &corev1.ConfigMap{Data: map[string]string{rbacmanagement.ConfigMapKey: "1"}}, false),
	Entry("unparsable value stays off", &corev1.ConfigMap{Data: map[string]string{rbacmanagement.ConfigMapKey: "yes please"}}, false),
	Entry("empty value stays off", &corev1.ConfigMap{Data: map[string]string{rbacmanagement.ConfigMapKey: ""}}, false),
)
