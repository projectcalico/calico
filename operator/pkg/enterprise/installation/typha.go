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

package installation

import (
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/projectcalico/calico/operator/pkg/common"
	"github.com/projectcalico/calico/operator/pkg/extensions"
	"github.com/projectcalico/calico/operator/pkg/render"
)

func modifyTypha(ri render.Inputs, cfg *render.TyphaConfiguration, objs, del []client.Object) ([]client.Object, []client.Object) {
	role := extensions.MustFindObject[*rbacv1.ClusterRole](objs, render.TyphaClusterRoleName)
	role.Rules = append(role.Rules, rbacv1.PolicyRule{
		APIGroups: []string{"projectcalico.org", "crd.projectcalico.org"},
		Resources: []string{
			"bfdconfigurations",
			"deeppacketinspections",
			"egressgatewaypolicies",
			"externalnetworks",
			"licensekeys",
			"networks",
			"packetcaptures",
			"remoteclusterconfigurations",
		},
		Verbs: []string{"get", "list", "watch"},
	})

	if data := installationData(ri).nonClusterHost; data.enabled {
		objs = addNonClusterHostTypha(cfg, data, objs)
	}

	// Both Typha deployments need the interface mode, or the non-cluster-host one
	// disagrees with the cluster one.
	net := ri.Installation.CalicoNetwork
	if net != nil && net.MultiInterfaceMode != nil {
		for _, name := range []string{common.TyphaDeploymentName, common.TyphaDeploymentName + render.TyphaNonClusterHostSuffix} {
			// The non-cluster-host deployment only renders when that feature is enabled.
			dep, ok := extensions.FindObject[*appsv1.Deployment](objs, name)
			if !ok {
				continue
			}

			c := render.MustContainer(&dep.Spec.Template.Spec, render.TyphaContainerName)
			c.Env = append(c.Env, corev1.EnvVar{Name: "MULTI_INTERFACE_MODE", Value: net.MultiInterfaceMode.Value()})
		}
	}

	return objs, del
}
