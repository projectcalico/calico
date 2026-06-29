// Copyright (c) 2022-2026 Tigera, Inc. All rights reserved.

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package render

import (
	"os"
	"slices"
	"sort"
	"strconv"

	corev1 "k8s.io/api/core/v1"

	tigerakvc "github.com/tigera/operator/pkg/render/common/authentication/tigera/key_validator_config"
)

// ManagerCloudResources contains all the resources needed for the cloud manager.
type ManagerCloudResources struct {
	VoltronMetricsEnabled    bool
	VoltronInternalHttpsPort uint16
	VoltronExtraEnv          map[string]string

	ManagerImage    string
	ManagerExtraEnv map[string]string
}

func (c *managerComponent) decorateCloudVoltronContainer(container corev1.Container) corev1.Container {
	if !c.cfg.Cloud {
		return container
	}

	container.Env = append(container.Env,
		corev1.EnvVar{Name: "VOLTRON_K8S_CLIENT_QPS", Value: "20"},
		corev1.EnvVar{Name: "VOLTRON_K8S_CLIENT_BURST", Value: "20"},
		corev1.EnvVar{Name: "VOLTRON_INTERNAL_PORT", Value: strconv.FormatUint(uint64(c.cfg.CloudResources.VoltronInternalHttpsPort), 10)},
		corev1.EnvVar{Name: "VOLTRON_METRICS_ENABLED", Value: strconv.FormatBool(c.cfg.CloudResources.VoltronMetricsEnabled)},
		corev1.EnvVar{Name: "VOLTRON_HTTP_ACCESS_LOGGING_ENABLED", Value: "true"},
		corev1.EnvVar{Name: "VOLTRON_CHECK_MANAGED_CLUSTER_AUTHORIZATION_BEFORE_PROXY", Value: "true"},
		corev1.EnvVar{Name: "VOLTRON_CHECK_MANAGED_CLUSTER_AUTHORIZATION_CACHE_TTL", Value: "10s"},
		corev1.EnvVar{Name: "VOLTRON_OIDC_TOKEN_REVIEW_CACHE_TTL", Value: "10s"},
	)

	// move extra env vars into Voltron, but sort them alphabetically first,
	// otherwise, since map iteration is random, they'll be added to the env vars in a random order,
	// which will cause another reconciliation event when Voltron is updated.
	sortedKeysIterate(c.cfg.CloudResources.VoltronExtraEnv, func(key, val string) {
		if i := slices.IndexFunc(container.Env, func(env corev1.EnvVar) bool { return env.Name == key }); i != -1 {
			container.Env[i].Value = val
		} else {
			container.Env = append(container.Env, corev1.EnvVar{Name: key, Value: val})
		}
	})
	return container
}

func (c *managerComponent) decorateCloudDeploymentSpec(templateSpec corev1.PodTemplateSpec) corev1.PodTemplateSpec {
	if !c.cfg.Cloud {
		return templateSpec
	}

	if c.cfg.CloudResources.VoltronMetricsEnabled {
		templateSpec.Annotations["prometheus.io.scrape"] = "true"
		templateSpec.Annotations["prometheus.io.scheme"] = "https"
		templateSpec.Annotations["prometheus.io.port"] = strconv.FormatUint(uint64(c.cfg.CloudResources.VoltronInternalHttpsPort), 10)
	}

	return templateSpec
}

// Do this as a separate function to try to make updates in the future easier.
func (c *managerComponent) setManagerCloudEnvs(envs []corev1.EnvVar) []corev1.EnvVar {
	if !c.cfg.Cloud {
		return envs
	}

	envs = append(envs,
		corev1.EnvVar{Name: "ENABLE_MANAGED_CLUSTERS_ONLY", Value: "true"},
		corev1.EnvVar{Name: "LICENSE_EDITION", Value: "cloudEdition"},
	)

	// move extra env vars into Manager, but sort them alphabetically first,
	// otherwise, since map iteration is random, they'll be added to the env vars in a random order,
	// which will cause another reconciliation event when Manager is updated.
	sortedKeysIterate(c.cfg.CloudResources.ManagerExtraEnv, func(key, val string) {
		envs = append(envs, corev1.EnvVar{Name: key, Value: val})
	})

	return envs
}

// decorateCloudOAuth2EnvVars applies cloud-only OIDC workarounds to the manager OAuth2 env vars.
// These are no-ops for non-cloud installs.
//
// TODO: remove these once manager correctly reads well-known-config from the root of the local
// domain instead of from the root of auth0.
func (c *managerComponent) decorateCloudOAuth2EnvVars(envs []corev1.EnvVar) []corev1.EnvVar {
	if !c.cfg.Cloud {
		return envs
	}

	setEnv := func(name, value string) {
		if i := slices.IndexFunc(envs, func(env corev1.EnvVar) bool { return env.Name == name }); i != -1 {
			envs[i].Value = value
		} else {
			envs = append(envs, corev1.EnvVar{Name: name, Value: value})
		}
	}

	// Cloud requires the OIDC audience to be set to the client ID.
	setEnv("CNX_WEB_OIDC_AUDIENCE", c.cfg.KeyValidatorConfig.ClientID())

	// For the tigera key validator, cloud sets the authority to the issuer rather than an empty string.
	if _, ok := c.cfg.KeyValidatorConfig.(*tigerakvc.KeyValidatorConfig); ok {
		setEnv("CNX_WEB_OIDC_AUTHORITY", c.cfg.KeyValidatorConfig.Issuer())
	}

	return envs
}

func (c *managerComponent) resolveCloudImages() {
	if !c.cfg.Cloud {
		return
	}

	// support legacy override if specified
	if managerImage := os.Getenv("MANAGER_IMAGE"); managerImage != "" {
		c.managerImage = managerImage
	}

	// override manager image if specified
	if c.cfg.CloudResources.ManagerImage != "" {
		c.managerImage = c.cfg.CloudResources.ManagerImage
	}
}

// sortedKeysIterate Sort map keys and call f with the sorted key and its value
func sortedKeysIterate(m map[string]string, f func(key, val string)) {
	var keys []string
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	for _, key := range keys {
		f(key, m[key])
	}
}
