// Copyright (c) 2020-2026 Tigera, Inc. All rights reserved.
//
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
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/intstr"

	"github.com/tigera/operator/pkg/render/common/securitycontext"
)

func calicoDefaultConfig() []runtime.Object {
	fileOrCreate := corev1.HostPathFileOrCreate
	directoryOrCreate := corev1.HostPathDirectoryOrCreate
	isPrivileged := true
	var terminationGracePeriod int64 = 0
	maxUnav := intstr.FromInt(1)
	updateStrat := appsv1.RollingUpdateDaemonSet{MaxUnavailable: &maxUnav}
	var _1 int32 = 1
	return []runtime.Object{
		&corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "calico-config",
				Namespace: "kube-system",
			},
			Data: map[string]string{
				"typha_service_name": "none",
				"calico_backend":     "bird",
				"veth_mtu":           "1440",
				"cni_network_config": `{
  "name": "k8s-pod-network",
  "cniVersion": "0.3.1",
  "plugins": [
    {
      "type": "calico",
      "log_level": "info",
      "datastore_type": "kubernetes",
      "nodename": "__KUBERNETES_NODE_NAME__",
      "mtu": __CNI_MTU__,
      "ipam": {
          "type": "calico-ipam"
      },
      "policy": {
          "type": "k8s"
      },
      "kubernetes": {
          "kubeconfig": "__KUBECONFIG_FILEPATH__"
      }
    },
    {
      "type": "portmap",
      "snat": true,
      "capabilities": {"portMappings": true}
    }
  ]
}`,
			},
		},
		&appsv1.DaemonSet{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "calico-node",
				Namespace: "kube-system",
				Labels: map[string]string{
					"k8s-app": "calico-node",
				},
			},
			Spec: appsv1.DaemonSetSpec{
				Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"k8s-app": "calico-node"}},
				UpdateStrategy: appsv1.DaemonSetUpdateStrategy{
					Type:          appsv1.RollingUpdateDaemonSetStrategyType,
					RollingUpdate: &updateStrat,
				},
				Template: corev1.PodTemplateSpec{
					ObjectMeta: metav1.ObjectMeta{
						Labels: map[string]string{
							"k8s-app": "calico-node",
						},
					},
					Spec: corev1.PodSpec{
						NodeSelector: map[string]string{"kubernetes.io/os": "linux"},
						HostNetwork:  true,
						Tolerations: []corev1.Toleration{
							{Operator: corev1.TolerationOpExists, Effect: corev1.TaintEffectNoSchedule},
							{Operator: corev1.TolerationOpExists, Key: "CriticalAddonsOnly"},
							{Operator: corev1.TolerationOpExists, Effect: corev1.TaintEffectNoExecute},
						},
						ServiceAccountName:            "calico-node",
						TerminationGracePeriodSeconds: &terminationGracePeriod,
						PriorityClassName:             "system-node-critical",
						InitContainers: []corev1.Container{{
							Name:    "upgrade-ipam",
							Image:   "calico/cni:v3.15.1",
							Command: []string{"/opt/cni/bin/calico-ipam", "-upgrade"},
							Env: []corev1.EnvVar{
								{Name: "KUBERNETES_NODE_NAME",
									ValueFrom: &corev1.EnvVarSource{
										FieldRef: &corev1.ObjectFieldSelector{FieldPath: "spec.nodeName"},
									},
								},
								{Name: "CALICO_NETWORKING_BACKEND",
									ValueFrom: &corev1.EnvVarSource{
										ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
											LocalObjectReference: corev1.LocalObjectReference{Name: "calico-config"},
											Key:                  "calico_backend",
										},
									},
								},
							},
							VolumeMounts: []corev1.VolumeMount{
								{MountPath: "/var/lib/cni/networks", Name: "host-local-net-dir"},
								{MountPath: "/host/opt/cni/bin", Name: "cni-bin-dir"},
							},
							SecurityContext: securitycontext.NewRootContext(isPrivileged),
						}, {
							Name:    "install-cni",
							Image:   "calico/cni:v3.15.1",
							Command: []string{"/install-cni.sh"},
							Env: []corev1.EnvVar{
								{Name: "CNI_CONF_NAME", Value: "10-calico.conflist"},
								{Name: "CNI_NETWORK_CONFIG",
									ValueFrom: &corev1.EnvVarSource{
										ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
											LocalObjectReference: corev1.LocalObjectReference{Name: "calico-config"},
											Key:                  "cni_network_config",
										},
									},
								},
								{Name: "KUBERNETES_NODE_NAME",
									ValueFrom: &corev1.EnvVarSource{
										FieldRef: &corev1.ObjectFieldSelector{FieldPath: "spec.nodeName"},
									},
								},
								{Name: "CNI_MTU",
									ValueFrom: &corev1.EnvVarSource{
										ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
											LocalObjectReference: corev1.LocalObjectReference{Name: "calico-config"},
											Key:                  "veth_mtu",
										},
									},
								},
								{Name: "SLEEP", Value: "false"},
							},
							VolumeMounts: []corev1.VolumeMount{
								{MountPath: "/host/opt/cni/bin", Name: "cni-bin-dir"},
								{MountPath: "/host/etc/cni/net.d", Name: "cni-net-dir"},
							},
							SecurityContext: securitycontext.NewRootContext(isPrivileged),
						}, {
							Name:  "flexvol-driver",
							Image: "calico/pod2daemon-flexvol:v3.15.1",
							VolumeMounts: []corev1.VolumeMount{
								{MountPath: "/host/driver", Name: "flexvol-driver-host"},
							},
							SecurityContext: securitycontext.NewRootContext(isPrivileged),
						}},
						Containers: []corev1.Container{{
							Name:  "calico-node",
							Image: "calico/node:v3.15.1",
							Env: []corev1.EnvVar{
								{Name: "DATASTORE_TYPE", Value: "kubernetes"},
								{Name: "WAIT_FOR_DATASTORE", Value: "true"},
								{
									Name: "NODENAME",
									ValueFrom: &corev1.EnvVarSource{
										FieldRef: &corev1.ObjectFieldSelector{FieldPath: "spec.nodeName"},
									},
								},
								{Name: "CALICO_NETWORKING_BACKEND",
									ValueFrom: &corev1.EnvVarSource{
										ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
											LocalObjectReference: corev1.LocalObjectReference{Name: "calico-config"},
											Key:                  "calico_backend",
										},
									},
								},
								{Name: "CLUSTER_TYPE", Value: "k8s,bgp"},
								{Name: "IP", Value: "autodetect"},
								{Name: "CALICO_IPV4POOL_IPIP", Value: "Always"},
								{Name: "CALICO_IPV4POOL_VXLAN", Value: "Never"},
								{Name: "FELIX_IPINIPMTU",
									ValueFrom: &corev1.EnvVarSource{
										ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
											LocalObjectReference: corev1.LocalObjectReference{Name: "calico-config"},
											Key:                  "veth_mtu",
										},
									},
								},
								{Name: "FELIX_VXLANMTU",
									ValueFrom: &corev1.EnvVarSource{
										ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
											LocalObjectReference: corev1.LocalObjectReference{Name: "calico-config"},
											Key:                  "veth_mtu",
										},
									},
								},
								{Name: "FELIX_VXLANMTUV6",
									ValueFrom: &corev1.EnvVarSource{
										ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
											LocalObjectReference: corev1.LocalObjectReference{Name: "calico-config"},
											Key:                  "veth_mtu",
										},
									},
								},
								{Name: "FELIX_WIREGUARDMTU",
									ValueFrom: &corev1.EnvVarSource{
										ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
											LocalObjectReference: corev1.LocalObjectReference{Name: "calico-config"},
											Key:                  "veth_mtu",
										},
									},
								},
								{Name: "FELIX_WIREGUARDMTUV6",
									ValueFrom: &corev1.EnvVarSource{
										ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
											LocalObjectReference: corev1.LocalObjectReference{Name: "calico-config"},
											Key:                  "veth_mtu",
										},
									},
								},
								{Name: "CALICO_DISABLE_FILE_LOGGING", Value: "false"},
								{Name: "FELIX_DEFAULTENDPOINTTOHOSTACTION", Value: "ACCEPT"},
								{Name: "FELIX_IPV6SUPPORT", Value: "false"},
								{Name: "FELIX_LOGSEVERITYSCREEN", Value: "info"},
								{Name: "FELIX_HEALTHENABLED", Value: "true"},
							},
							SecurityContext: securitycontext.NewRootContext(isPrivileged),
							Resources: corev1.ResourceRequirements{
								Requests: corev1.ResourceList{
									corev1.ResourceCPU: resource.MustParse("250m"),
								},
							},
							LivenessProbe: &corev1.Probe{
								ProbeHandler: corev1.ProbeHandler{Exec: &corev1.ExecAction{
									Command: []string{"/bin/calico-node", "-felix-live", "-bird-live"}}},
								PeriodSeconds:       10,
								InitialDelaySeconds: 10,
								FailureThreshold:    6,
							},
							ReadinessProbe: &corev1.Probe{
								ProbeHandler: corev1.ProbeHandler{Exec: &corev1.ExecAction{
									Command: []string{"/bin/calico-node", "-felix-ready", "-bird-ready"}}},
								PeriodSeconds: 10,
							},
							VolumeMounts: []corev1.VolumeMount{
								{MountPath: "/lib/modules", Name: "lib-modules", ReadOnly: true},
								{MountPath: "/run/xtables.lock", Name: "xtables-lock", ReadOnly: false},
								{MountPath: "/var/run/calico", Name: "var-run-calico", ReadOnly: false},
								{MountPath: "/var/lib/calico", Name: "var-lib-calico", ReadOnly: false},
								{MountPath: "/var/run/nodeagent", Name: "policysync"},
							},
						}},
						Volumes: []corev1.Volume{
							{Name: "lib-modules", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/lib/modules"}}},
							{Name: "var-run-calico", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/var/run/calico"}}},
							{Name: "var-lib-calico", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/var/lib/calico"}}},
							{Name: "xtables-lock", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/run/xtables.lock", Type: &fileOrCreate}}},
							{Name: "cni-bin-dir", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/opt/cni/bin"}}},
							{Name: "cni-net-dir", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/etc/cni/net.d"}}},
							{Name: "host-local-net-dir", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/var/lib/cni/networks"}}},
							{Name: "policysync", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/var/run/nodeagent", Type: &directoryOrCreate}}},
							{Name: "flexvol-driver-host", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/usr/libexec/kubernetes/kubelet-plugins/volume/exec/nodeagent~uds", Type: &directoryOrCreate}}},
						},
					},
				},
			},
		},
		&appsv1.Deployment{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "calico-kube-controllers",
				Namespace: "kube-system",
				Labels: map[string]string{
					"k8s-app": "calico-kube-controllers",
				},
			},
			Spec: appsv1.DeploymentSpec{
				Replicas: &_1,
				Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"k8s-app": "calico-kube-controllers"}},
				Strategy: appsv1.DeploymentStrategy{
					Type: appsv1.RecreateDeploymentStrategyType,
				},
				Template: corev1.PodTemplateSpec{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "calico-kube-controllers",
						Namespace: "kube-system",
						Labels: map[string]string{
							"k8s-app": "calico-kue-controllers",
						},
					},
					Spec: corev1.PodSpec{
						NodeSelector: map[string]string{"kubernetes.io/os": "linux"},
						Tolerations: []corev1.Toleration{
							{Operator: corev1.TolerationOpExists, Key: "CriticalAddonsOnly"},
							{Key: "node-role.kubernetes.io/master", Effect: corev1.TaintEffectNoSchedule},
						},
						ServiceAccountName: "calico-kube-controllers",
						PriorityClassName:  "system-node-critical",
						Containers: []corev1.Container{{
							Name:  "calico-kube-controllers",
							Image: "calico/kube-controllers:v3.15.1",
							Env: []corev1.EnvVar{
								{Name: "ENABLED_CONTROLLERS", Value: "node"},
								{Name: "DATASTORE_TYPE", Value: "kubernetes"},
							},
							ReadinessProbe: &corev1.Probe{
								ProbeHandler: corev1.ProbeHandler{Exec: &corev1.ExecAction{
									Command: []string{"/usr/bin/check-status", "-r"}}},
							},
						}},
					},
				},
			},
		},
	}
}
