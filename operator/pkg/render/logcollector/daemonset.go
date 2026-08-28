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

package logcollector

import (
	"fmt"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"

	"github.com/tigera/operator/pkg/render"
	rcomponents "github.com/tigera/operator/pkg/render/common/components"
	rmeta "github.com/tigera/operator/pkg/render/common/meta"
	"github.com/tigera/operator/pkg/render/common/secret"
	"github.com/tigera/operator/pkg/render/common/securitycontext"
)

// uptimeProbeHandler asserts only that the fluent-bit process is alive:
// /api/v1/uptime answers 200 whenever the monitoring server is up. The
// startup and liveness probes use it because /api/v1/health flips unhealthy
// on sustained delivery errors, and a liveness-triggered restart would drop
// any in-memory buffered chunks — an output outage must not crashloop the
// collector.
func (c *fluentBitComponent) uptimeProbeHandler() corev1.ProbeHandler {
	return corev1.ProbeHandler{
		HTTPGet: &corev1.HTTPGetAction{
			Path: "/api/v1/uptime",
			Port: intstr.FromInt(FluentBitMetricsPort),
		},
	}
}

// healthProbeHandler is error-aware (the config enables health_check, which
// reports unhealthy on sustained delivery errors). Only the readiness probe
// uses it, so an erroring instance is taken out of Ready without being
// restarted.
func (c *fluentBitComponent) healthProbeHandler() corev1.ProbeHandler {
	return corev1.ProbeHandler{
		HTTPGet: &corev1.HTTPGetAction{
			Path: "/api/v1/health",
			Port: intstr.FromInt(FluentBitMetricsPort),
		},
	}
}

func (c *fluentBitComponent) securityContext(privileged bool) *corev1.SecurityContext {
	if c.osType == rmeta.OSTypeWindows {
		return nil
	}
	return securitycontext.NewRootContext(privileged)
}

func (c *fluentBitComponent) daemonset() *appsv1.DaemonSet {
	// Give fluent-bit time to flush on the way down: the engine flushes
	// in-flight chunks for up to its 5s shutdown grace on SIGTERM (and
	// filesystem-buffered chunks survive a kill either way), so an immediate
	// SIGKILL (grace 0) would guarantee losing whatever is only in memory on
	// every roll.
	var terminationGracePeriod int64 = 30
	// The rationale for this setting is that while there is no need for fluent-bit to be available, we want to avoid
	// potentially negative consequences of an immediate roll-out on huge clusters.
	maxUnavailable := intstr.FromInt(10)

	annots := c.cfg.TrustedBundle.HashAnnotations()
	if c.cfg.FluentBitKeyPair != nil {
		annots[c.cfg.FluentBitKeyPair.HashAnnotationKey()] = c.cfg.FluentBitKeyPair.HashAnnotationValue()
	}
	if c.cfg.S3Credential != nil {
		annots[s3CredentialHashAnnotation] = rmeta.AnnotationHash(c.cfg.S3Credential)
	}
	if c.cfg.SplkCredential != nil {
		annots[splunkCredentialHashAnnotation] = rmeta.AnnotationHash(c.cfg.SplkCredential)
	}
	// Most LogCollector spec changes only alter the rendered ConfigMap (and the
	// config is subPath-mounted, which kubelet never live-updates), so hash the
	// rendered config into the pod template to force a rollout on change. This
	// also covers user filters, which are inlined into the config.
	annots[configHashAnnotation] = rmeta.AnnotationHash(c.renderFluentBitConf())

	// The pos-migrator init container seeds fluent-bit's tail-offset DBs from
	// the legacy fluentd .pos files at cutover and pre-creates the tailed log
	// directories. Windows fluentd kept tail positions under the same mounted
	// log dir, so the migration applies there too — the Windows image ships
	// the cross-compiled migrator, with env overrides pointing it at the
	// c:-prefixed mounts.
	migratorCommand := "/usr/bin/pos-migrator"
	migratorEnv := []corev1.EnvVar{
		{Name: "LOG_DIRS", Value: c.logDirsCSV()},
	}
	if c.osType == rmeta.OSTypeWindows {
		migratorCommand = c.path("/fluent-bit/pos-migrator.exe")
		migratorEnv = append([]corev1.EnvVar{
			{Name: "POS_DIR", Value: c.path("/var/log/calico")},
			{Name: "DB_DIR", Value: c.path("/var/log/calico/calico-fluent-bit")},
		}, migratorEnv...)
	}
	initContainers := []corev1.Container{{
		Name:    "pos-migrator",
		Image:   c.image,
		Command: []string{migratorCommand},
		Env:     migratorEnv,
		// Writes to the same host path volume as the fluent-bit container, so
		// it needs the same privileged access on OpenShift (SELinux otherwise
		// denies mkdir on the host path).
		SecurityContext: c.securityContext(c.cfg.Installation.KubernetesProvider.IsOpenShift()),
		VolumeMounts: []corev1.VolumeMount{
			{MountPath: c.path("/var/log/calico"), Name: "var-log-calico"},
		},
	}}
	if c.cfg.FluentBitKeyPair != nil && c.cfg.FluentBitKeyPair.UseCertificateManagement() {
		initContainers = append(initContainers, c.cfg.FluentBitKeyPair.InitContainer(LogCollectorNamespace, c.container().SecurityContext))
	}

	podTemplate := &corev1.PodTemplateSpec{
		ObjectMeta: metav1.ObjectMeta{
			Annotations: annots,
		},
		Spec: corev1.PodSpec{
			NodeSelector:                  map[string]string{},
			Tolerations:                   rmeta.TolerateAll,
			ImagePullSecrets:              secret.GetReferenceList(c.cfg.PullSecrets),
			TerminationGracePeriodSeconds: &terminationGracePeriod,
			InitContainers:                initContainers,
			Containers:                    []corev1.Container{c.container()},
			Volumes:                       c.volumes(),
			ServiceAccountName:            c.fluentBitNodeName(),
		},
	}

	ds := &appsv1.DaemonSet{
		TypeMeta: metav1.TypeMeta{Kind: "DaemonSet", APIVersion: "apps/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      c.fluentBitNodeName(),
			Namespace: LogCollectorNamespace,
		},
		Spec: appsv1.DaemonSetSpec{
			Template: *podTemplate,
			UpdateStrategy: appsv1.DaemonSetUpdateStrategy{
				RollingUpdate: &appsv1.RollingUpdateDaemonSet{
					MaxUnavailable: &maxUnavailable,
				},
			},
		},
	}
	if c.cfg.LogCollector != nil {
		overrides := c.cfg.LogCollector.Spec.CalicoFluentBitDaemonSet
		if overrides == nil {
			// Deprecated alias: fluentdDaemonSet is honored for one release when
			// the new field is unset, per the API contract. Container entries
			// stored under the legacy fluentd-era names are matched against the
			// renamed containers via the shared containerNameAliases mechanism
			// in pkg/render/common/components.
			overrides = c.cfg.LogCollector.Spec.FluentdDaemonSet //nolint:staticcheck // deliberate use of the deprecated alias field
		}
		if overrides != nil {
			rcomponents.ApplyDaemonSetOverrides(ds, overrides)
		}
	}
	render.SetNodeCriticalPod(&(ds.Spec.Template))
	return ds
}

func (c *fluentBitComponent) container() corev1.Container {
	envs := c.envvars()
	volumeMounts := []corev1.VolumeMount{
		{MountPath: c.path("/var/log/calico"), Name: "var-log-calico"},
	}
	if c.osType == rmeta.OSTypeWindows {
		// Windows containers cannot mount a single file (no subPath file
		// mounts), so mount the whole ConfigMap as a directory. The Windows
		// image keeps its own files under C:\fluent-bit, so c:\etc\fluent-bit
		// shadows nothing.
		volumeMounts = append(volumeMounts,
			corev1.VolumeMount{MountPath: c.path("/etc/fluent-bit/conf"), Name: "fluent-bit-conf", ReadOnly: true})
	} else {
		// Mount only the rendered config as a single file (SubPath) so it does
		// not shadow the image's /etc/fluent-bit directory, which ships
		// plugins.conf, record_transformer.lua and the in_eks plugin.
		volumeMounts = append(volumeMounts,
			corev1.VolumeMount{MountPath: "/etc/fluent-bit/fluent-bit.yaml", Name: "fluent-bit-conf", SubPath: "fluent-bit.yaml", ReadOnly: true})
	}

	volumeMounts = append(volumeMounts, c.cfg.TrustedBundle.VolumeMounts(c.SupportedOSType())...)

	if c.cfg.FluentBitKeyPair != nil {
		volumeMounts = append(volumeMounts, c.cfg.FluentBitKeyPair.VolumeMount(c.SupportedOSType()))
	}

	if c.cfg.ManagedCluster {
		volumeMounts = append(volumeMounts,
			corev1.VolumeMount{
				Name:      LinseedTokenVolumeName,
				MountPath: c.path(LinseedVolumeMountPath),
			})
	}

	return corev1.Container{
		Name:    "calico-fluent-bit",
		Image:   c.image,
		Command: []string{c.binPath()},
		Args:    []string{"-c", c.configPath()},
		Env:     envs,
		// On OpenShift Fluent Bit needs privileged access to access logs on host path volume
		SecurityContext: c.securityContext(c.cfg.Installation.KubernetesProvider.IsOpenShift()),
		VolumeMounts:    volumeMounts,
		StartupProbe:    c.startup(),
		LivenessProbe:   c.liveness(),
		ReadinessProbe:  c.readiness(),
		Ports: []corev1.ContainerPort{{
			Name:          "metrics-port",
			ContainerPort: FluentBitMetricsPort,
		}},
	}
}

func (c *fluentBitComponent) metricsService() *corev1.Service {
	return &corev1.Service{
		TypeMeta: metav1.TypeMeta{Kind: "Service", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      c.fluentBitMetricsServiceName(),
			Namespace: LogCollectorNamespace,
			Labels:    map[string]string{"k8s-app": c.fluentBitNodeName()},
		},
		Spec: corev1.ServiceSpec{
			Selector: map[string]string{"k8s-app": c.fluentBitNodeName()},
			// Important: "None" tells Kubernetes that we want a headless service with
			// no kube-proxy load balancer.  If we omit this then kube-proxy will render
			// a huge set of iptables rules for this service since there's an instance
			// on every node.
			ClusterIP: "None",
			Ports: []corev1.ServicePort{
				{
					Name:       FluentBitMetricsPortName,
					Port:       int32(FluentBitMetricsPort),
					TargetPort: intstr.FromInt(FluentBitMetricsPort),
					Protocol:   corev1.ProtocolTCP,
				},
			},
		},
	}
}

func (c *fluentBitComponent) envvars() []corev1.EnvVar {
	envs := []corev1.EnvVar{
		{Name: "NODENAME", ValueFrom: &corev1.EnvVarSource{FieldRef: &corev1.ObjectFieldSelector{FieldPath: "spec.nodeName"}}},
	}
	// Additional stores are Linux-only (the Windows pipeline ships to Linseed
	// only, matching the fluentd Windows variant), so their credentials are too.
	if c.cfg.LogCollector.Spec.AdditionalStores != nil && c.osType == rmeta.OSTypeLinux {
		if s3 := c.cfg.LogCollector.Spec.AdditionalStores.S3; s3 != nil {
			// The standard AWS credential env vars, which fluent-bit's native s3
			// output reads via the AWS credential chain (the legacy AWS_KEY_ID /
			// AWS_SECRET_KEY names were fluentd-config-only and are read by
			// nothing in fluent-bit).
			envs = append(envs,
				corev1.EnvVar{
					Name: "AWS_ACCESS_KEY_ID",
					ValueFrom: &corev1.EnvVarSource{
						SecretKeyRef: &corev1.SecretKeySelector{
							LocalObjectReference: corev1.LocalObjectReference{Name: S3FluentBitSecretName},
							Key:                  S3KeyIdName,
						},
					},
				},
				corev1.EnvVar{
					Name: "AWS_SECRET_ACCESS_KEY",
					ValueFrom: &corev1.EnvVarSource{
						SecretKeyRef: &corev1.SecretKeySelector{
							LocalObjectReference: corev1.LocalObjectReference{Name: S3FluentBitSecretName},
							Key:                  S3KeySecretName,
						},
					},
				},
			)
		}
		if splunk := c.cfg.LogCollector.Spec.AdditionalStores.Splunk; splunk != nil {
			envs = append(envs,
				corev1.EnvVar{
					Name: "SPLUNK_HEC_TOKEN",
					ValueFrom: &corev1.EnvVarSource{
						SecretKeyRef: &corev1.SecretKeySelector{
							LocalObjectReference: corev1.LocalObjectReference{Name: SplunkFluentBitTokenSecretName},
							Key:                  SplunkFluentBitSecretTokenKey,
						},
					},
				},
			)
		}
	}
	return envs
}

// The startup probe uses the same action as the liveness probe, but with
// a higher failure threshold and double the timeout to account for slow
// networks.
func (c *fluentBitComponent) startup() *corev1.Probe {
	return &corev1.Probe{
		ProbeHandler:     c.uptimeProbeHandler(),
		TimeoutSeconds:   c.probeTimeout,
		PeriodSeconds:    c.probePeriod,
		FailureThreshold: 10,
	}
}

func (c *fluentBitComponent) liveness() *corev1.Probe {
	return &corev1.Probe{
		ProbeHandler:   c.uptimeProbeHandler(),
		TimeoutSeconds: c.probeTimeout,
		PeriodSeconds:  c.probePeriod,
	}
}

func (c *fluentBitComponent) readiness() *corev1.Probe {
	return &corev1.Probe{
		ProbeHandler:   c.healthProbeHandler(),
		TimeoutSeconds: c.probeTimeout,
		PeriodSeconds:  c.probePeriod,
	}
}

func (c *fluentBitComponent) volumes() []corev1.Volume {
	dirOrCreate := corev1.HostPathDirectoryOrCreate

	volumes := []corev1.Volume{
		{
			Name: "var-log-calico",
			VolumeSource: corev1.VolumeSource{
				HostPath: &corev1.HostPathVolumeSource{
					Path: c.volumeHostPath(),
					Type: &dirOrCreate,
				},
			},
		},
		{
			Name: "fluent-bit-conf",
			VolumeSource: corev1.VolumeSource{
				ConfigMap: &corev1.ConfigMapVolumeSource{
					LocalObjectReference: corev1.LocalObjectReference{
						Name: c.fluentBitConfConfigMapName(),
					},
				},
			},
		},
	}
	if c.cfg.FluentBitKeyPair != nil {
		volumes = append(volumes, c.cfg.FluentBitKeyPair.Volume())
	}
	if c.cfg.ManagedCluster {
		volumes = append(volumes,
			corev1.Volume{
				Name: LinseedTokenVolumeName,
				VolumeSource: corev1.VolumeSource{
					Secret: &corev1.SecretVolumeSource{
						// Per-OS: the token controller provisions a secret per
						// ServiceAccount (calico-fluent-bit /
						// calico-fluent-bit-windows).
						SecretName: fmt.Sprintf(LinseedTokenSecret, c.fluentBitNodeName()),
						Items:      []corev1.KeyToPath{{Key: LinseedTokenKey, Path: LinseedTokenSubPath}},
					},
				},
			})
	}
	volumes = append(volumes, render.TrustedBundleVolume(c.cfg.TrustedBundle))

	return volumes
}
