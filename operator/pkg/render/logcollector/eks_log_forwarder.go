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
	"encoding/json"
	"fmt"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/projectcalico/calico/operator/pkg/render"
	rcomponents "github.com/projectcalico/calico/operator/pkg/render/common/components"
	relasticsearch "github.com/projectcalico/calico/operator/pkg/render/common/elasticsearch"
	rmeta "github.com/projectcalico/calico/operator/pkg/render/common/meta"
	"github.com/projectcalico/calico/operator/pkg/render/common/secret"
)

func (c *fluentBitComponent) eksLogForwarderServiceAccount() *corev1.ServiceAccount {
	return &corev1.ServiceAccount{
		TypeMeta:   metav1.TypeMeta{Kind: "ServiceAccount", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{Name: EKSLogForwarderName, Namespace: LogCollectorNamespace},
	}
}

func (c *fluentBitComponent) eksLogForwarderSecret() *corev1.Secret {
	return &corev1.Secret{
		TypeMeta: metav1.TypeMeta{Kind: "Secret", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      EksLogForwarderSecret,
			Namespace: LogCollectorNamespace,
		},
		Data: map[string][]byte{
			EksLogForwarderAwsId:  c.cfg.EKSConfig.AwsId,
			EksLogForwarderAwsKey: c.cfg.EKSConfig.AwsKey,
		},
	}
}

// renderEKSFluentBitConf renders the fluent-bit config for the eks-log-forwarder
// Deployment: a single in_eks input (the Go plugin polls CloudWatch, applies
// the EKS audit shaping itself, and resumes from the last Linseed-ingested
// timestamp on every process start) feeding the built-in http output that
// ships to Linseed. The in_eks plugin reads its CloudWatch/Linseed settings
// from the Deployment's env vars rather than plugin properties.
func (c *fluentBitComponent) renderEKSFluentBitConf() string {
	cfg := fluentBitConfig{
		Service: map[string]interface{}{
			"flush":        5,
			"log_level":    "info",
			"http_server":  true,
			"http_port":    FluentBitMetricsPort,
			"health_check": true,
			// Load the custom in_eks Go plugin shipped in the image. Without
			// this the `in_eks` input is an unknown plugin.
			"plugins_file": c.pluginsFilePath(),
		},
	}
	cfg.Pipeline.Inputs = append(cfg.Pipeline.Inputs, map[string]interface{}{
		"name": "in_eks",
		"tag":  "audit.kube",
	})
	cfg.Pipeline.Outputs = append(cfg.Pipeline.Outputs, c.linseedHTTPOutput(
		"audit.kube",
		c.cfg.EKSLogForwarderKeyPair.VolumeMountCertificateFilePath(),
		c.cfg.EKSLogForwarderKeyPair.VolumeMountKeyFilePath(),
		// No filesystem storage on this Deployment, so no backlog cap applies.
		""))

	out, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return fmt.Sprintf("# error rendering config: %v\n", err)
	}
	return string(out) + "\n"
}

func (c *fluentBitComponent) eksConfigMap() *corev1.ConfigMap {
	return &corev1.ConfigMap{
		TypeMeta:   metav1.TypeMeta{Kind: "ConfigMap", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{Name: EKSLogForwarderConfConfigMapName, Namespace: LogCollectorNamespace},
		Data:       map[string]string{"fluent-bit.yaml": c.renderEKSFluentBitConf()},
	}
}

func (c *fluentBitComponent) eksLogForwarderDeployment() *appsv1.Deployment {
	annots := map[string]string{
		eksCloudwatchLogCredentialHashAnnotation: rmeta.AnnotationHash(c.cfg.EKSConfig),
		configHashAnnotation:                     rmeta.AnnotationHash(c.renderEKSFluentBitConf()),
	}

	envVars := []corev1.EnvVar{
		{Name: "LOG_LEVEL", Value: "info"},
		// CloudWatch config, credentials — consumed by the in_eks input plugin
		// (fluent-bit/plugins/in_eks/pkg/config) and the AWS SDK credential chain.
		{Name: "EKS_CLOUDWATCH_LOG_GROUP", Value: c.cfg.EKSConfig.GroupName},
		{Name: "AWS_REGION", Value: c.cfg.EKSConfig.AwsRegion},
		{Name: "AWS_ACCESS_KEY_ID", ValueFrom: secret.GetEnvVarSource(EksLogForwarderSecret, EksLogForwarderAwsId, false)},
		{Name: "AWS_SECRET_ACCESS_KEY", ValueFrom: secret.GetEnvVarSource(EksLogForwarderSecret, EksLogForwarderAwsKey, false)},
		// Linseed connection for the plugin's resume-point query (it asks
		// Linseed for the last ingested audit timestamp on startup).
		// Determine the namespace in which Linseed is running. For managed and standalone clusters, this is always the elasticsearch
		// namespace. For multi-tenant management clusters, this may vary.
		{Name: "LINSEED_ENDPOINT", Value: relasticsearch.LinseedEndpoint(c.SupportedOSType(), c.cfg.ClusterDomain, render.LinseedNamespace(c.cfg.Tenant), c.cfg.ManagedCluster, true)},
		{Name: "LINSEED_CA_PATH", Value: c.trustedBundlePath()},
		{Name: "TLS_CRT_PATH", Value: c.cfg.EKSLogForwarderKeyPair.VolumeMountCertificateFilePath()},
		{Name: "TLS_KEY_PATH", Value: c.cfg.EKSLogForwarderKeyPair.VolumeMountKeyFilePath()},
		{Name: "LINSEED_TOKEN", Value: c.path(render.GetLinseedTokenPath(c.cfg.ManagedCluster))},
	}
	// The logcollector controller defaults these before render
	// (getEksCloudwatchLogConfig: prefix kube-apiserver-audit-, interval
	// 60), so in practice both env vars are always set. The guards are
	// defense in depth for other callers: rendering an empty prefix or a
	// zero interval would override the plugin's own defaults with a broken
	// setting (an empty prefix matches every stream in the group).
	if c.cfg.EKSConfig.StreamPrefix != "" {
		envVars = append(envVars, corev1.EnvVar{Name: "EKS_CLOUDWATCH_LOG_STREAM_PREFIX", Value: c.cfg.EKSConfig.StreamPrefix})
	}
	if c.cfg.EKSConfig.FetchInterval > 0 {
		envVars = append(envVars, corev1.EnvVar{Name: "EKS_CLOUDWATCH_POLL_INTERVAL", Value: fmt.Sprintf("%ds", c.cfg.EKSConfig.FetchInterval)})
	}
	if c.cfg.Tenant != nil && c.cfg.ExternalElastic {
		envVars = append(envVars, corev1.EnvVar{Name: "TENANT_ID", Value: c.cfg.Tenant.Spec.ID})
	}

	var eksLogForwarderReplicas int32 = 1

	tolerations := c.cfg.Installation.ControlPlaneTolerations
	if c.cfg.Installation.KubernetesProvider.IsGKE() {
		tolerations = append(tolerations, rmeta.TolerateGKEARM64NoSchedule)
	}

	d := &appsv1.Deployment{
		TypeMeta: metav1.TypeMeta{Kind: "Deployment", APIVersion: "apps/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      EKSLogForwarderName,
			Namespace: LogCollectorNamespace,
			Labels: map[string]string{
				"k8s-app": EKSLogForwarderName,
			},
		},
		Spec: appsv1.DeploymentSpec{
			Replicas: &eksLogForwarderReplicas,
			Strategy: appsv1.DeploymentStrategy{
				Type: appsv1.RecreateDeploymentStrategyType,
			},
			Selector: &metav1.LabelSelector{
				MatchLabels: map[string]string{
					"k8s-app": EKSLogForwarderName,
				},
			},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Name:      EKSLogForwarderName,
					Namespace: LogCollectorNamespace,
					Labels: map[string]string{
						"k8s-app": EKSLogForwarderName,
					},
					Annotations: annots,
				},
				Spec: corev1.PodSpec{
					Tolerations:        tolerations,
					ServiceAccountName: EKSLogForwarderName,
					ImagePullSecrets:   secret.GetReferenceList(c.cfg.PullSecrets),
					Containers: []corev1.Container{{
						Name:            EKSLogForwarderName,
						Image:           c.image,
						Command:         []string{c.binPath()},
						Args:            []string{"-c", c.configPath()},
						Env:             envVars,
						SecurityContext: c.securityContext(false),
						VolumeMounts:    c.eksLogForwarderVolumeMounts(),
						StartupProbe:    c.startup(),
						LivenessProbe:   c.liveness(),
						ReadinessProbe:  c.readiness(),
					}},
					Volumes: c.eksLogForwarderVolumes(),
				},
			},
		},
	}

	if c.cfg.LogCollector != nil {
		if overrides := c.cfg.LogCollector.Spec.EKSLogForwarderDeployment; overrides != nil {
			rcomponents.ApplyDeploymentOverrides(d, overrides)
		}
	}

	return d
}

func (c *fluentBitComponent) eksLogForwarderVolumeMounts() []corev1.VolumeMount {
	volumeMounts := []corev1.VolumeMount{
		// Mount only the rendered config file (SubPath) so it does not shadow
		// the image's /etc/fluent-bit directory (plugins.conf etc.).
		{
			Name:      "fluent-bit-conf",
			MountPath: c.configPath(),
			SubPath:   "fluent-bit.yaml",
			ReadOnly:  true,
		},
	}
	volumeMounts = append(volumeMounts, c.cfg.TrustedBundle.VolumeMounts(c.SupportedOSType())...)
	if c.cfg.EKSLogForwarderKeyPair != nil {
		volumeMounts = append(volumeMounts, c.cfg.EKSLogForwarderKeyPair.VolumeMount(c.SupportedOSType()))
	}

	if c.cfg.ManagedCluster {
		volumeMounts = append(volumeMounts,
			corev1.VolumeMount{
				Name:      LinseedTokenVolumeName,
				MountPath: c.path(LinseedVolumeMountPath),
			})
	}
	return volumeMounts
}

func (c *fluentBitComponent) eksLogForwarderVolumes() []corev1.Volume {
	volumes := []corev1.Volume{
		render.TrustedBundleVolume(c.cfg.TrustedBundle),
		{
			Name: "fluent-bit-conf",
			VolumeSource: corev1.VolumeSource{
				ConfigMap: &corev1.ConfigMapVolumeSource{
					LocalObjectReference: corev1.LocalObjectReference{
						Name: EKSLogForwarderConfConfigMapName,
					},
				},
			},
		},
	}
	if c.cfg.EKSLogForwarderKeyPair != nil {
		volumes = append(volumes, c.cfg.EKSLogForwarderKeyPair.Volume())
	}

	if c.cfg.ManagedCluster {
		volumes = append(volumes,
			corev1.Volume{
				Name: LinseedTokenVolumeName,
				VolumeSource: corev1.VolumeSource{
					Secret: &corev1.SecretVolumeSource{
						SecretName: fmt.Sprintf(LinseedTokenSecret, EKSLogForwarderName),
						Items:      []corev1.KeyToPath{{Key: LinseedTokenKey, Path: LinseedTokenSubPath}},
					},
				},
			})
	}
	return volumes
}

func (c *fluentBitComponent) eksLogForwarderClusterRoleBinding() *rbacv1.ClusterRoleBinding {
	return &rbacv1.ClusterRoleBinding{
		TypeMeta: metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name: EKSLogForwarderName,
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "ClusterRole",
			Name:     EKSLogForwarderName,
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      "ServiceAccount",
				Name:      EKSLogForwarderName,
				Namespace: LogCollectorNamespace,
			},
		},
	}
}

// eksLogForwarderLinseedRules grants the narrower Linseed access an EKS log
// forwarder needs: it reads audit logs to find where it left off, and writes
// only kube audit logs.
func eksLogForwarderLinseedRules() []rbacv1.PolicyRule {
	return []rbacv1.PolicyRule{
		{
			APIGroups: []string{"linseed.tigera.io"},
			Resources: []string{"auditlogs"},
			Verbs:     []string{"get"},
		},
		{
			APIGroups: []string{"linseed.tigera.io"},
			Resources: []string{"kube_auditlogs"},
			Verbs:     []string{"create"},
		},
	}
}

func (c *fluentBitComponent) eksLogForwarderClusterRole() *rbacv1.ClusterRole {
	rules := eksLogForwarderLinseedRules()

	return &rbacv1.ClusterRole{
		TypeMeta: metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name: EKSLogForwarderName,
		},
		Rules: rules,
	}
}
