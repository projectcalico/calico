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

package convert

import (
	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func emptyNodeSpec() *appsv1.DaemonSet {
	return &appsv1.DaemonSet{
		ObjectMeta: v1.ObjectMeta{
			Name:      "calico-node",
			Namespace: "kube-system",
		},
		Spec: appsv1.DaemonSetSpec{
			Template: corev1.PodTemplateSpec{
				Spec: corev1.PodSpec{
					Tolerations: []corev1.Toleration{
						{
							Effect:   corev1.TaintEffectNoSchedule,
							Operator: corev1.TolerationOpExists,
						},
						{
							Key:      "CriticalAddonsOnly",
							Operator: corev1.TolerationOpExists,
						},
						{
							Effect:   corev1.TaintEffectNoExecute,
							Operator: corev1.TolerationOpExists,
						},
					},
					InitContainers: []corev1.Container{{
						Name: "install-cni",
						Env: []corev1.EnvVar{{
							Name:  "CNI_NETWORK_CONFIG",
							Value: `{"type": "calico", "name": "k8s-pod-network", "ipam": {"type": "calico-ipam"}}`,
						}},
					}},
					Containers: []corev1.Container{{
						Name: "calico-node",
					}},
					Volumes: []corev1.Volume{
						{
							Name: "lib-modules",
							VolumeSource: corev1.VolumeSource{
								HostPath: &corev1.HostPathVolumeSource{
									Path: "/lib/modules",
								},
							},
						},
						{
							Name: "var-run-calico",
							VolumeSource: corev1.VolumeSource{
								HostPath: &corev1.HostPathVolumeSource{
									Path: "/var/run/calico",
								},
							},
						},
						{
							Name: "var-lib-calico",
							VolumeSource: corev1.VolumeSource{
								HostPath: &corev1.HostPathVolumeSource{
									Path: "/var/lib/calico",
								},
							},
						},
						{
							Name: "xtables-lock",
							VolumeSource: corev1.VolumeSource{
								HostPath: &corev1.HostPathVolumeSource{
									Path: "/run/xtables.lock",
								},
							},
						},
						{
							Name: "cni-bin-dir",
							VolumeSource: corev1.VolumeSource{
								HostPath: &corev1.HostPathVolumeSource{
									Path: "/opt/cni/bin",
								},
							},
						},
						{
							Name: "cni-net-dir",
							VolumeSource: corev1.VolumeSource{
								HostPath: &corev1.HostPathVolumeSource{
									Path: "/etc/cni/net.d",
								},
							},
						},
					},
				},
			},
		},
	}
}

func emptyKubeControllerSpec() *appsv1.Deployment {
	return &appsv1.Deployment{
		ObjectMeta: v1.ObjectMeta{
			Name:      "calico-kube-controllers",
			Namespace: "kube-system",
		},
		Spec: appsv1.DeploymentSpec{
			Template: corev1.PodTemplateSpec{
				Spec: corev1.PodSpec{
					Tolerations: []corev1.Toleration{
						{
							Key:      "CriticalAddonsOnly",
							Operator: corev1.TolerationOpExists,
						},
						{
							Effect: corev1.TaintEffectNoSchedule,
							Key:    "node-role.kubernetes.io/master",
						},
					},
					Containers: []corev1.Container{{
						Name: "calico-kube-controllers",
					}},
				},
			},
		},
	}
}

func emptyTyphaDeployment() *appsv1.Deployment {
	return &appsv1.Deployment{
		ObjectMeta: v1.ObjectMeta{
			Name:      "calico-typha",
			Namespace: "kube-system",
		},
		Spec: appsv1.DeploymentSpec{
			Template: corev1.PodTemplateSpec{
				Spec: corev1.PodSpec{
					Tolerations: []corev1.Toleration{{
						Key:      "CriticalAddonsOnly",
						Operator: corev1.TolerationOpExists,
					}},
					Containers: []corev1.Container{{
						Name: "calico-typha",
					}},
				},
			},
		},
	}
}

// emptyComponents is a convenience function for initializing a
// components object which meets basic validation requirements.
func emptyComponents() components {
	return components{
		node: CheckedDaemonSet{
			*emptyNodeSpec(),
			make(map[string]checkedFields),
		},
		kubeControllers: emptyKubeControllerSpec(),
		typha:           emptyTyphaDeployment(),
	}
}

func emptyFelixConfig() *v3.FelixConfiguration {
	return &v3.FelixConfiguration{
		ObjectMeta: v1.ObjectMeta{
			Name: "default",
		},
	}
}
