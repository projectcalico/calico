// Copyright (c) 2022-2024 Tigera, Inc. All rights reserved.

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
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/intstr"

	"github.com/tigera/operator/pkg/render/common/securitycontext"
)

func awsCNIPolicyOnlyConfig() []runtime.Object {
	fileOrCreate := corev1.HostPathFileOrCreate
	isPrivileged := true
	var terminationGracePeriod int64 = 0
	maxUnav := intstr.FromInt(1)
	updateStrat := appsv1.RollingUpdateDaemonSet{MaxUnavailable: &maxUnav}
	_intStr9098 := intstr.FromInt(9098)
	var _65534 int64 = 65534
	var _2 int32 = 2
	return []runtime.Object{
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
						PriorityClassName:             "system-node-critical",
						NodeSelector:                  map[string]string{"beta.kubernetes.io/os": "linux"},
						HostNetwork:                   true,
						ServiceAccountName:            "calico-node",
						TerminationGracePeriodSeconds: &terminationGracePeriod,
						Containers: []corev1.Container{{
							Name:  "calico-node",
							Image: "quay.io/calico/node:v3.13.4",
							Env: []corev1.EnvVar{
								{Name: "DATASTORE_TYPE", Value: "kubernetes"},
								{Name: "FELIX_INTERFACEPREFIX", Value: "eni"},
								{Name: "FELIX_LOGSEVERITYSCREEN", Value: "info"},
								{Name: "CALICO_NETWORKING_BACKEND", Value: "none"},
								{Name: "CLUSTER_TYPE", Value: "k8s,ecs"},
								{Name: "CALICO_DISABLE_FILE_LOGGING", Value: "false"},
								{Name: "FELIX_TYPHAK8SSERVICENAME", Value: "calico-typha"},
								{Name: "FELIX_DEFAULTENDPOINTTOHOSTACTION", Value: "ACCEPT"},
								{Name: "FELIX_IPTABLESMANGLEALLOWACTION", Value: "Return"},
								{Name: "FELIX_IPV6SUPPORT", Value: "false"},
								{Name: "WAIT_FOR_DATASTORE", Value: "true"},
								{Name: "FELIX_LOGSEVERITYSYS", Value: "none"},
								{Name: "FELIX_PROMETHEUSMETRICSENABLED", Value: "true"},
								{Name: "NO_DEFAULT_POOLS", Value: "true"},
								{
									Name: "NODENAME",
									ValueFrom: &corev1.EnvVarSource{
										FieldRef: &corev1.ObjectFieldSelector{FieldPath: "spec.nodeName"},
									},
								},
								{Name: "IP", Value: ""},
								{Name: "FELIX_HEALTHENABLED", Value: "true"},
							},
							SecurityContext: securitycontext.NewRootContext(isPrivileged),
							LivenessProbe: &corev1.Probe{
								ProbeHandler:        corev1.ProbeHandler{Exec: &corev1.ExecAction{Command: []string{"/bin/calico-node", "-felix-live"}}},
								PeriodSeconds:       10,
								InitialDelaySeconds: 10,
								FailureThreshold:    6,
							},
							ReadinessProbe: &corev1.Probe{
								ProbeHandler:  corev1.ProbeHandler{Exec: &corev1.ExecAction{Command: []string{"/bin/calico-node", "-felix-ready"}}},
								PeriodSeconds: 10,
							},
							VolumeMounts: []corev1.VolumeMount{
								{MountPath: "/lib/modules", Name: "lib-modules", ReadOnly: true},
								{MountPath: "/run/xtables.lock", Name: "xtables-lock"},
								{MountPath: "/var/run/calico", Name: "var-run-calico"},
								{MountPath: "/var/lib/calico", Name: "var-lib-calico"},
							},
						}},
						Tolerations: []corev1.Toleration{
							{Operator: corev1.TolerationOpExists, Effect: corev1.TaintEffectNoSchedule},
							{Operator: corev1.TolerationOpExists, Key: "CriticalAddonsOnly"},
							{Operator: corev1.TolerationOpExists, Effect: corev1.TaintEffectNoExecute},
						},
						Volumes: []corev1.Volume{
							{Name: "lib-modules", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/lib/modules"}}},
							{Name: "var-run-calico", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/var/run/calico"}}},
							{Name: "var-lib-calico", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/var/lib/calico"}}},
							{Name: "xtables-lock", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/run/xtables.lock", Type: &fileOrCreate}}},
						},
					},
				},
			},
		},
		&appsv1.Deployment{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "calico-typha",
				Namespace: "kube-system",
				Labels: map[string]string{
					"k8s-app": "calico-typha",
				},
			},
			Spec: appsv1.DeploymentSpec{
				Replicas: &_2,
				Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"k8s-app": "calico-typha"}},
				Template: corev1.PodTemplateSpec{
					ObjectMeta: metav1.ObjectMeta{
						Labels: map[string]string{
							"k8s-app": "calico-typha",
						},
						Annotations: map[string]string{
							"cluster-autoscaler.kubernetes.io/safe-to-evict": "true",
						},
					},
					Spec: corev1.PodSpec{
						PriorityClassName: "system-cluster-critical",
						NodeSelector:      map[string]string{"beta.kubernetes.io/os": "linux"},
						Tolerations: []corev1.Toleration{
							{Operator: corev1.TolerationOpExists, Key: "CriticalAddonsOnly"},
						},
						HostNetwork:        true,
						ServiceAccountName: "calico-node",
						SecurityContext:    &corev1.PodSecurityContext{FSGroup: &_65534},
						Containers: []corev1.Container{{
							Name:  "calico-typha",
							Image: "quay.io/calico/typha:v3.13.4",
							Ports: []corev1.ContainerPort{
								{Name: "calico-typha", Protocol: corev1.ProtocolTCP, ContainerPort: 5473},
							},
							Env: []corev1.EnvVar{
								{Name: "FELIX_INTERFACEPREFIX", Value: "eni"},
								{Name: "TYPHA_LOGFILEPATH", Value: "none"},
								{Name: "TYPHA_LOGSEVERITYSYS", Value: "none"},
								{Name: "TYPHA_LOGSEVERITYSCREEN", Value: "info"},
								{Name: "TYPHA_PROMETHEUSMETRICSENABLED", Value: "true"},
								{Name: "TYPHA_CONNECTIONREBALANCINGMODE", Value: "kubernetes"},
								{Name: "TYPHA_PROMETHEUSMETRICSPORT", Value: "9093"},
								{Name: "TYPHA_DATASTORETYPE", Value: "kubernetes"},
								{Name: "TYPHA_MAXCONNECTIONSLOWERLIMIT", Value: "1"},
								{Name: "TYPHA_HEALTHENABLED", Value: "true"},
								{Name: "FELIX_IPTABLESMANGLEALLOWACTION", Value: "Return"},
							},
							LivenessProbe: &corev1.Probe{
								ProbeHandler: corev1.ProbeHandler{
									HTTPGet: &corev1.HTTPGetAction{
										Host: "localhost",
										Path: "/liveness",
										Port: _intStr9098,
									},
								},
								PeriodSeconds:       30,
								InitialDelaySeconds: 30,
							},
							SecurityContext: securitycontext.NewNonRootContext(),
							ReadinessProbe: &corev1.Probe{
								ProbeHandler: corev1.ProbeHandler{
									HTTPGet: &corev1.HTTPGetAction{
										Host: "localhost",
										Path: "/readiness",
										Port: _intStr9098,
									},
								},
								PeriodSeconds: 10,
							},
						}},
					},
				},
			},
		},
	}
}
