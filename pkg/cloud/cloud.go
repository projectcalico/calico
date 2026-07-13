// Copyright (c) 2026 Tigera, Inc. All rights reserved.

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

package cloud

import (
	"context"
	"fmt"
	"os"
	"strconv"

	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/render"
	"github.com/tigera/operator/pkg/render/common/cloudconfig"
	"github.com/tigera/operator/pkg/render/logstorage"
	kerrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/utils/ptr"
	ctrl "sigs.k8s.io/controller-runtime"
)

var setupLog = ctrl.Log.WithName("cloud_setup")

const (
	configMapName = "cloud-operator-config"

	// EnableCloudEnvVar can enable cloud mode for a non-cloud build. The shipped Calico Cloud
	// operator image has cloud mode baked in at build time (see IsCloudBuild) and cannot be turned
	// off; this env var is only a fallback for enabling cloud mode in a regular build, e.g. for
	// local development or testing.
	EnableCloudEnvVar = "CALICO_CLOUD"
)

// buildVariant is injected at build time via -ldflags "-X .../pkg/cloud.buildVariant=cloud" when
// building the Calico Cloud operator image. It is empty for the regular Calico/Calico Enterprise
// image. Baking it into the binary means cloud mode is immutable: it cannot be disabled by editing
// the operator Deployment's environment.
var buildVariant string

// IsCloudBuild reports whether this binary was built as the Calico Cloud variant. When true, cloud
// mode is baked in and cannot be disabled at runtime.
func IsCloudBuild() bool {
	return buildVariant == "cloud"
}

// Options holds the cloud-specific configuration parsed at operator startup. When Cloud is false the
// operator is running as a regular (non-cloud) Calico Enterprise install and the remaining fields are
// not meaningful.
type Options struct {
	// Cloud indicates that this operator is running as a Calico Cloud install. It is true when the
	// cloud-operator-config ConfigMap is present or the relevant cloud env vars are set.
	Cloud bool
	// ElasticExternal is parsed from cloud-operator-config for cloud's own startup verify (see verify).
	// It is NOT the operator's external-ES gate: controllers read that from ControllerOptions.ElasticExternal,
	// which main.go sources solely from operator-bootstrap-config via discovery.UseExternalElastic. Cloud
	// provisions ELASTIC_EXTERNAL into both configmaps so the two stay consistent.
	ElasticExternal bool
	ESMigration     bool
}

// Load determines whether the operator is running in cloud mode and, if so, parses the cloud options.
//
// Cloud mode is enabled when this is a cloud build (IsCloudBuild, baked into the cloud image) or,
// for a regular build, when the CALICO_CLOUD env var is truthy (dev/testing fallback). When neither
// applies the operator is a regular Calico/Calico Enterprise install and Load returns
// Options{Cloud: false} with no error, leaving enterprise behavior unchanged. Only once cloud mode
// is enabled does Load read the cloud-operator-config ConfigMap (and env) for cloud config values.
func Load(ctx context.Context, cs kubernetes.Interface) (Options, error) {
	cloudEnabled := IsCloudBuild()
	if !cloudEnabled {
		envEnabled, err := parseEnableCloud()
		if err != nil {
			return Options{}, err
		}
		cloudEnabled = envEnabled
	}
	if !cloudEnabled {
		setupLog.Info("cloud mode not enabled; running in non-cloud mode")
		return Options{Cloud: false}, nil
	}

	var cmData map[string]string
	cloudConfig, err := cs.CoreV1().ConfigMaps(common.OperatorNamespace()).Get(ctx, configMapName, metav1.GetOptions{})
	if err != nil {
		if !kerrors.IsNotFound(err) {
			return Options{}, fmt.Errorf("failed to read configmap '%s': %v", configMapName, err)
		}
		setupLog.Info("missing configmap. reading config from env.", "name", configMapName)
	} else {
		cmData = cloudConfig.Data
	}

	elasticExternal, err := parseBoolFromEnvOrConfigMap("ELASTIC_EXTERNAL", cmData)
	if err != nil {
		return Options{}, fmt.Errorf("error in parsing ELASTIC_EXTERNAL: %v", err)
	}

	esMigration, err := parseBoolFromEnvOrConfigMap("ELASTIC_MIGRATION", cmData)
	if err != nil {
		setupLog.Info("error in parsing ELASTIC_MIGRATION: %v. Defaulting to false", err)
		esMigration = false
	}

	opts := Options{
		Cloud:           true,
		ElasticExternal: elasticExternal,
		ESMigration:     esMigration,
	}

	if err := verify(ctx, cs, opts); err != nil {
		return Options{}, err
	}

	if err = watch(cs, cmData); err != nil {
		return Options{}, err
	}

	return opts, nil
}

// parseEnableCloud reads the CALICO_CLOUD gate env var. Unset or empty means non-cloud (false). A
// set-but-unparseable value is an error so misconfiguration fails loudly rather than silently
// disabling cloud.
func parseEnableCloud() (bool, error) {
	strVal := os.Getenv(EnableCloudEnvVar)
	if strVal == "" {
		return false, nil
	}
	val, err := strconv.ParseBool(strVal)
	if err != nil {
		return false, fmt.Errorf("unable to convert env %s=%s to bool: %v", EnableCloudEnvVar, strVal, err)
	}
	return val, nil
}

func parseBoolFromEnvOrConfigMap(key string, configMap map[string]string) (bool, error) {
	var cmVal *bool
	if strVal := configMap[key]; strVal != "" {
		val, err := strconv.ParseBool(configMap[key])
		if err != nil {
			return false, fmt.Errorf("unable to convert configmap %s=%s to bool: %v", key, strVal, err)
		}
		setupLog.Info("parsed config from cloud configmap", key, val)
		cmVal = &val
	}

	var envVal *bool
	if strVal := os.Getenv(key); strVal != "" {
		val, err := strconv.ParseBool(strVal)
		if err != nil {
			return false, fmt.Errorf("unable to convert env %s=%s to bool: %v", key, strVal, err)
		}
		setupLog.Info("parsed config from env", key, val)
		envVal = &val
	}

	if cmVal == nil && envVal == nil {
		return false, fmt.Errorf("value %s not found in configmap or env", key)
	}

	if cmVal != nil && envVal != nil && *cmVal != *envVal {
		return false, fmt.Errorf("value for %s differs: set to %t in configmap and %t in env", key, *cmVal, *envVal)
	}

	if cmVal != nil {
		return *cmVal, nil
	} else {
		return *envVal, nil
	}
}

func verify(ctx context.Context, cs kubernetes.Interface, opts Options) error {
	if opts.ESMigration {
		return nil
	}
	if opts.ElasticExternal {
		// there should not be an internal-es cert
		_, err := cs.CoreV1().Secrets(render.ElasticsearchNamespace).Get(ctx, render.TigeraElasticsearchInternalCertSecret, metav1.GetOptions{})
		if err != nil {
			if kerrors.IsNotFound(err) {
				return nil
			}
			return fmt.Errorf("unexpected error encountered when confirming elastic is not currently internal: %v", err)
		}
		return fmt.Errorf("refusing to run: operator configured as external-es but secret/%s found which suggests its internal-es", render.TigeraElasticsearchInternalCertSecret)
	} else {
		// there should not be an external-es cert
		_, err := cs.CoreV1().Secrets(render.ElasticsearchNamespace).Get(ctx, logstorage.ExternalCertsSecret, metav1.GetOptions{})
		if err != nil {
			if kerrors.IsNotFound(err) {
				return nil
			}
			return fmt.Errorf("unexpected error encountered when confirming elastic is not currently external: %v", err)
		}
		return fmt.Errorf("refusing to run: operator configured as internal-es but configmap/%s found which suggests its external-es", cloudconfig.CloudConfigConfigMapName)
	}
}

// Redefine ptr.To as ToPtr since aliases to a generic function are unsupported. See https://github.com/golang/go/issues/52654
func ToPtr[T any](v T) *T {
	return ptr.To(v)
}
