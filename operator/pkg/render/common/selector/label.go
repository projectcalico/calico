// Copyright (c) 2025-2026 Tigera, Inc. All rights reserved.

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

package selector

import metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

const (
	OpenShiftDNSDaemonsetLabel = "dns.operator.openshift.io/daemonset-dns"
	K8sNameLabel               = "app.kubernetes.io/name"
	CalicoNameLabel            = "kubernetes.io/metadata.name"
)

func PodLabelSelector(name string) *metav1.LabelSelector {
	return &metav1.LabelSelector{
		MatchLabels: map[string]string{
			K8sNameLabel: name,
		},
	}
}
