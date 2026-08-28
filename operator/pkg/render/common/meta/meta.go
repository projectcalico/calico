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

package meta

import (
	"crypto/sha1"
	"fmt"
	"time"

	operatorv1 "github.com/tigera/operator/api/v1"
	corev1 "k8s.io/api/core/v1"
)

// This type helps ensure that we only use defined os types
type OSType string

const (
	DefaultCertificateDuration = 825 * 24 * time.Hour

	OSTypeAny     OSType = "any"
	OSTypeLinux   OSType = "linux"
	OSTypeWindows OSType = "windows"

	// TigeraOperatorCAIssuerPrefix The name prefix used for the CA issuer, which is used
	// for self-signed certificates issued for operator-managed certificates.
	// NOTE: Do not change this field since we use this value to identify
	// certificates managed by this operator.
	TigeraOperatorCAIssuerPrefix = "tigera-operator-signer"
)

var (
	// TolerateControlPlane allows pod to be scheduled on master nodes
	TolerateControlPlane = []corev1.Toleration{
		{
			Key:    "node-role.kubernetes.io/master",
			Effect: corev1.TaintEffectNoSchedule,
		},
		{
			Key:    "node-role.kubernetes.io/control-plane",
			Effect: corev1.TaintEffectNoSchedule,
		},
	}

	// TolerateCriticalAddonsOnly allows pods to be rescheduled while the node is in "critical add-ons only" mode.
	TolerateCriticalAddonsOnly = corev1.Toleration{
		Key:      "CriticalAddonsOnly",
		Operator: corev1.TolerationOpExists,
	}

	TolerateCriticalAddonsAndControlPlane = append(TolerateControlPlane, TolerateCriticalAddonsOnly)

	// TolerateGKEARM64NoSchedule allows pods to be scheduled on GKE Arm64 nodes.
	// See https://cloud.google.com/kubernetes-engine/docs/how-to/prepare-arm-workloads-for-deployment#multi-arch-schedule-any-arch
	TolerateGKEARM64NoSchedule = corev1.Toleration{
		Key:      "kubernetes.io/arch",
		Operator: corev1.TolerationOpEqual,
		Value:    "arm64",
		Effect:   corev1.TaintEffectNoSchedule,
	}

	// TolerateBootstrap is the toleration set used by host-networked Deployments
	// that must be schedulable during cluster bootstrap (before the CNI is up and
	// before the cloud provider has initialized the node), but which should
	// otherwise respect node cordoning. Unlike TolerateAll, this set deliberately
	// omits a blanket NoSchedule toleration so that the Kubernetes-added
	// node.kubernetes.io/unschedulable taint applied by `kubectl cordon` takes
	// effect.
	TolerateBootstrap = []corev1.Toleration{
		TolerateCriticalAddonsOnly,
		{
			Key:      "node-role.kubernetes.io/master",
			Operator: corev1.TolerationOpExists,
			Effect:   corev1.TaintEffectNoSchedule,
		},
		{
			Key:      "node-role.kubernetes.io/control-plane",
			Operator: corev1.TolerationOpExists,
			Effect:   corev1.TaintEffectNoSchedule,
		},
		{
			Key:      "node.kubernetes.io/not-ready",
			Operator: corev1.TolerationOpExists,
			Effect:   corev1.TaintEffectNoSchedule,
		},
		{
			Key:      "node.kubernetes.io/network-unavailable",
			Operator: corev1.TolerationOpExists,
			Effect:   corev1.TaintEffectNoSchedule,
		},
		{
			Key:      "node.cloudprovider.kubernetes.io/uninitialized",
			Operator: corev1.TolerationOpExists,
			Effect:   corev1.TaintEffectNoSchedule,
		},
	}

	// TolerateAll returns tolerations to tolerate all taints. When used, it is not necessary
	// to include the user's custom tolerations because we already tolerate everything.
	TolerateAll = []corev1.Toleration{
		TolerateCriticalAddonsOnly,
		{
			Effect:   corev1.TaintEffectNoSchedule,
			Operator: corev1.TolerationOpExists,
		},
		{
			Effect:   corev1.TaintEffectNoExecute,
			Operator: corev1.TolerationOpExists,
		},
	}
)

func DefaultOperatorCASignerName() string {
	return fmt.Sprintf("%s@%d", TigeraOperatorCAIssuerPrefix, time.Now().Unix())
}

// AnnotationHash is to generate a hash that can be included in a Deployment
// or DaemonSet to trigger a restart/rolling update when a ConfigMap or Secret
// is updated.
func AnnotationHash(i interface{}) string {
	h := sha1.New()
	_, _ = fmt.Fprintf(h, "%q", i)
	return fmt.Sprintf("%x", h.Sum(nil))
}

// SecretsAnnotationHash generates a hash based off of the data in each secrets Data field that can be used by
// Deployments or DaemonSets to trigger a restart/rolling update based on changes to one of more secrets data.
func SecretsAnnotationHash(secrets ...*corev1.Secret) string {
	var annoteArr []map[string][]byte
	for _, secret := range secrets {
		if secret == nil {
			continue
		}
		annoteArr = append(annoteArr, secret.Data)
	}

	return AnnotationHash(annoteArr)
}

// GetResourceRequirements retrieves the component ResourcesRequirements from the installation. If it doesn't exist, it
// returns an empty ResourceRequirements struct.
func GetResourceRequirements(i *operatorv1.InstallationSpec, name operatorv1.ComponentName) corev1.ResourceRequirements {
	if i.ComponentResources != nil {
		for _, cr := range i.ComponentResources {
			if cr.ComponentName == name && cr.ResourceRequirements != nil {
				return *cr.ResourceRequirements
			}
		}
	}
	return corev1.ResourceRequirements{}
}
