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
	"reflect"
	"strconv"

	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"

	"github.com/projectcalico/calico/operator/pkg/common"
	"github.com/projectcalico/calico/operator/pkg/controller/utils"
	"github.com/projectcalico/calico/operator/pkg/render"
)

// isRolloutCompleteWithBPFVolumes checks if the calico-node DaemonSet
// rollout process is completed with BPF volume mount been created.
// If the Installation resource has been patched to dataplane: BPF then the
// calico-node daemonset will be re-created with BPF infrastructure such as
// the "bpffs" volumne mount etc. which will cause the DS to do a rolling update.
// Therefore, one way to check that the daemonset rolling update is complete is
// to compare the DS status current scheduled pods equals the updated number and
// the current scheduled pods also equals the number available.  When all these
// checks are reconciled then FelixConfig can be patched as bpfEnabled: true.
func isRolloutCompleteWithBPFVolumes(ds *appsv1.DaemonSet) bool {
	if ds.Status.ObservedGeneration != ds.Generation {
		// To avoid race condition: the k8s DaemonSet controller hasn't observed the
		// latest Spec update yet, so the Status might still be outdated.
		return false
	}

	for _, volume := range ds.Spec.Template.Spec.Volumes {
		if volume.Name == render.BPFVolumeName {
			// return ds.Status.CurrentNumberScheduled == ds.Status.UpdatedNumberScheduled && ds.Status.CurrentNumberScheduled == ds.Status.NumberAvailable
			if ds.Status.CurrentNumberScheduled == ds.Status.UpdatedNumberScheduled && ds.Status.CurrentNumberScheduled == ds.Status.NumberAvailable {
				return true
			} else {
				return false
			}
		}
	}
	return false
}

func bpfEnabledOnDaemonsetWithEnvVar(ds *appsv1.DaemonSet) (bool, error) {
	bpfEnabledStatus := false
	var err error

	if ds != nil &&
		!reflect.DeepEqual(ds.Spec, appsv1.DaemonSetSpec{}) &&
		!reflect.DeepEqual(ds.Spec.Template, corev1.PodTemplateSpec{}) &&
		!reflect.DeepEqual(ds.Spec.Template.Spec, corev1.PodSpec{}) {
		bpfEnabledEnvVar := utils.GetPodEnvVar(ds.Spec.Template.Spec, common.NodeDaemonSetName, "FELIX_BPFENABLED")
		if bpfEnabledEnvVar != nil {
			bpfEnabledStatus, err = strconv.ParseBool(*bpfEnabledEnvVar)
		}
	}

	return bpfEnabledStatus, err
}

func bpfEnabledOnFelixConfig(fc *v3.FelixConfiguration) bool {
	return fc.Spec.BPFEnabled != nil && *fc.Spec.BPFEnabled
}
