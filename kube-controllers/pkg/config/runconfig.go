// Copyright (c) 2025-2026 Tigera, Inc. All rights reserved.
//
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

package config

import (
	"context"
	"os"
	"reflect"
	"strconv"
	"strings"
	"time"

	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	log "github.com/sirupsen/logrus"
	"golang.org/x/text/cases"
	"golang.org/x/text/language"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/projectcalico/calico/libcalico-go/lib/clientv3"
	"github.com/projectcalico/calico/libcalico-go/lib/errors"
	"github.com/projectcalico/calico/libcalico-go/lib/options"
	"github.com/projectcalico/calico/libcalico-go/lib/watch"
)

var title = cases.Title(language.English)

const (
	datastoreBackoff                 = time.Second
	defaultKubeControllersConfigName = "default"

	defaultReconcilerPeriod = 5 * time.Minute
	defaultCompactionPeriod = 10 * time.Minute
	defaultLeakGracePeriod  = 15 * time.Minute
)

type RunConfigController struct {
	out chan v3.KubeControllersConfigurationSpec
}

// ConfigChan returns a channel that sends an initial config snapshot at start
// of day, and updates whenever the config changes.
func (r *RunConfigController) ConfigChan() <-chan v3.KubeControllersConfigurationSpec {
	return r.out
}

// NewDefaultKubeControllersConfig returns the default kcc with all default values prefilled
func NewDefaultKubeControllersConfig() *v3.KubeControllersConfiguration {
	kubeControllersConfig := v3.NewKubeControllersConfiguration()
	kubeControllersConfig.Name = defaultKubeControllersConfigName
	kubeControllersConfig.Spec = v3.KubeControllersConfigurationSpec{
		LogSeverityScreen:      "Info",
		HealthChecks:           v3.Enabled,
		EtcdV3CompactionPeriod: &v1.Duration{Duration: defaultCompactionPeriod},
		Controllers: v3.ControllersConfig{
			Node: &v3.NodeControllerConfig{
				ReconcilerPeriod: &v1.Duration{Duration: defaultReconcilerPeriod},
				SyncLabels:       v3.Enabled,
				HostEndpoint: &v3.AutoHostEndpointConfig{
					AutoCreate:                v3.Disabled,
					CreateDefaultHostEndpoint: v3.DefaultHostEndpointsEnabled,
				},
				LeakGracePeriod: &v1.Duration{Duration: defaultLeakGracePeriod},
			},
			Policy: &v3.PolicyControllerConfig{
				ReconcilerPeriod: &v1.Duration{Duration: defaultReconcilerPeriod},
			},
			WorkloadEndpoint: &v3.WorkloadEndpointControllerConfig{
				ReconcilerPeriod: &v1.Duration{Duration: defaultReconcilerPeriod},
			},
			ServiceAccount: &v3.ServiceAccountControllerConfig{
				ReconcilerPeriod: &v1.Duration{Duration: defaultReconcilerPeriod},
			},
			Namespace: &v3.NamespaceControllerConfig{
				ReconcilerPeriod: &v1.Duration{Duration: defaultReconcilerPeriod},
			},
			LoadBalancer: &v3.LoadBalancerControllerConfig{
				AssignIPs: v3.AllServices,
			},
			Migration: &v3.MigrationControllerConfig{
				PolicyNameMigrator: v3.ControllerEnabled,
			},
		},
	}

	return kubeControllersConfig
}

// NewRunConfigController creates the RunConfigController. The controller connects
// to the datastore to get the KubeControllersConfiguration resource, merges it with
// the config from environment variables, and emits resolved specs over a channel
// to push config out to the rest of the controllers. It also handles setting the
// KubeControllersConfiguration.Status with the current running configuration.
func NewRunConfigController(ctx context.Context, cfg Config, client clientv3.KubeControllersConfigurationInterface) *RunConfigController {
	ctrl := &RunConfigController{out: make(chan v3.KubeControllersConfigurationSpec)}
	go syncDatastore(ctx, cfg, client, ctrl.out)
	return ctrl
}

func syncDatastore(ctx context.Context, cfg Config, client clientv3.KubeControllersConfigurationInterface, out chan<- v3.KubeControllersConfigurationSpec) {
	var snapshot *v3.KubeControllersConfiguration
	var err error
	var current v3.KubeControllersConfigurationSpec
	// currentSet tracks whether we've explicitly set `current` so we can
	// tell the difference between its initial state and being explicitly
	// set to the empty state.
	var currentSet bool
	var w watch.Interface
	defer func() {
		if w != nil {
			w.Stop()
		}
	}()

	env := make(map[string]string)
	for _, k := range AllEnvs {
		v, ok := os.LookupEnv(k)
		if ok {
			env[k] = v
		}
	}

MAINLOOP:
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		if snapshot == nil {
			snapshot, err = getOrCreateSnapshot(ctx, client)
			if err != nil {
				log.WithError(err).Warn("unable to get KubeControllersConfiguration(default)")
				snapshot = nil
				time.Sleep(datastoreBackoff)
				continue MAINLOOP
			}
		}

		resolved, envReport := resolveSpec(env, cfg.DatastoreType, snapshot.Spec)
		status := v3.KubeControllersConfigurationStatus{
			RunningConfig:   &resolved,
			EnvironmentVars: envReport,
		}

		// Write the status back so end users can inspect the running config.
		snapshot.Status = status
		snapshot, err = client.UpdateStatus(ctx, snapshot, options.SetOptions{})
		if err != nil {
			log.WithError(err).Warn("unable to perform status update on KubeControllersConfiguration(default)")
			snapshot = nil
			time.Sleep(datastoreBackoff)
			continue MAINLOOP
		}

		kccList, err := client.List(ctx, options.ListOptions{Name: defaultKubeControllersConfigName})
		if err != nil {
			log.WithError(err).Warn("unable to list KubeControllersConfiguration(default)")
			snapshot = nil
			time.Sleep(datastoreBackoff)
			continue MAINLOOP
		}

		if !currentSet || !reflect.DeepEqual(resolved, current) {
			out <- resolved
			currentSet = true
			current = resolved
		}

		if w != nil {
			w.Stop()
		}
		w, err = client.Watch(ctx, options.ListOptions{ResourceVersion: kccList.ResourceVersion})
		if err != nil {
			log.WithError(err).Warn("unable to watch KubeControllersConfigurations")
			snapshot = nil
			time.Sleep(datastoreBackoff)
			continue MAINLOOP
		}
		for e := range w.ResultChan() {
			switch e.Type {
			case watch.Error:
				log.WithError(err).Error("error watching KubeControllersConfiguration")
				snapshot = nil
				time.Sleep(datastoreBackoff)
				continue MAINLOOP
			case watch.Added, watch.Modified:
				newKCC := e.Object.(*v3.KubeControllersConfiguration)
				if newKCC.Name != defaultKubeControllersConfigName {
					log.WithField("name", newKCC.Name).Warning("unexpected KubeControllersConfiguration object")
					continue
				}
				snapshot = newKCC
				resolved, envReport = resolveSpec(env, cfg.DatastoreType, snapshot.Spec)
				status = v3.KubeControllersConfigurationStatus{
					RunningConfig:   &resolved,
					EnvironmentVars: envReport,
				}

				if !reflect.DeepEqual(snapshot.Status, status) {
					snapshot.Status = status
					snapshot, err = client.UpdateStatus(ctx, snapshot, options.SetOptions{})
					if err != nil {
						log.WithError(err).Warn("unable to perform status update on KubeControllersConfiguration(default)")
						snapshot = nil
						time.Sleep(datastoreBackoff)
						continue MAINLOOP
					}
				}

				if !reflect.DeepEqual(resolved, current) {
					out <- resolved
					currentSet = true
					current = resolved
				}
			case watch.Deleted:
				if e.Previous != nil {
					oldKCC := e.Previous.(*v3.KubeControllersConfiguration)
					if oldKCC.Name == defaultKubeControllersConfigName {
						snapshot = nil
						continue MAINLOOP
					}
				}
			}
		}
	}
}

// getOrCreateSnapshot gets the current KubeControllersConfig from the datastore,
// or creates and returns a default if it doesn't exist
func getOrCreateSnapshot(ctx context.Context, kcc clientv3.KubeControllersConfigurationInterface) (*v3.KubeControllersConfiguration, error) {
	snapshot, err := kcc.Get(ctx, defaultKubeControllersConfigName, options.GetOptions{})
	if _, ok := err.(errors.ErrorResourceDoesNotExist); ok {
		kubeControllersConfig := NewDefaultKubeControllersConfig()
		snapshot = kubeControllersConfig.DeepCopy()
		var err2 error
		snapshot, err2 = kcc.Create(ctx, snapshot, options.SetOptions{})
		if err2 != nil {
			return nil, err2
		}
	} else if err != nil {
		return nil, err
	}
	return snapshot, nil
}

// resolveSpec takes the API spec and applies environment variable overrides,
// filling in defaults for any unset fields. Returns the fully-resolved spec
// and a map of environment variables that were set (for status reporting).
func resolveSpec(env map[string]string, datastoreType string, apiSpec v3.KubeControllersConfigurationSpec) (v3.KubeControllersConfigurationSpec, map[string]string) {
	resolved := *apiSpec.DeepCopy()
	report := map[string]string{}

	// Log level
	if v, ok := env[EnvLogLevel]; ok {
		report[EnvLogLevel] = v
		if _, err := log.ParseLevel(v); err != nil {
			log.WithField(EnvLogLevel, v).Fatal("invalid environment variable value")
		}
		resolved.LogSeverityScreen = title.String(v)
	}
	if resolved.LogSeverityScreen == "" {
		resolved.LogSeverityScreen = "Info"
	}

	// Enabled controllers — env overrides which controllers are non-nil.
	if v, ok := env[EnvEnabledControllers]; ok {
		report[EnvEnabledControllers] = v
		resolved.Controllers = resolveEnabledControllers(v, resolved.Controllers)
	}

	// Reconciler period — env overrides per-controller API values.
	if v, ok := env[EnvReconcilerPeriod]; ok {
		report[EnvReconcilerPeriod] = v
		d, err := time.ParseDuration(v)
		if err != nil {
			log.WithField(EnvReconcilerPeriod, v).Fatal("invalid environment variable value")
		}
		dp := &v1.Duration{Duration: d}
		if resolved.Controllers.Policy != nil {
			resolved.Controllers.Policy.ReconcilerPeriod = dp
		}
		if resolved.Controllers.WorkloadEndpoint != nil {
			resolved.Controllers.WorkloadEndpoint.ReconcilerPeriod = dp
		}
		if resolved.Controllers.ServiceAccount != nil {
			resolved.Controllers.ServiceAccount.ReconcilerPeriod = dp
		}
		if resolved.Controllers.Namespace != nil {
			resolved.Controllers.Namespace.ReconcilerPeriod = dp
		}
	}

	// Compaction period
	if v, ok := env[EnvCompactionPeriod]; ok {
		report[EnvCompactionPeriod] = v
		d, err := time.ParseDuration(v)
		if err != nil {
			log.WithField(EnvCompactionPeriod, v).Fatal("invalid environment variable value")
		}
		resolved.EtcdV3CompactionPeriod = &v1.Duration{Duration: d}
	}
	if resolved.EtcdV3CompactionPeriod == nil {
		resolved.EtcdV3CompactionPeriod = &v1.Duration{Duration: defaultCompactionPeriod}
	}

	// Health checks
	if v, ok := env[EnvHealthEnabled]; ok {
		report[EnvHealthEnabled] = v
		he, err := strconv.ParseBool(v)
		if err != nil {
			log.WithField(EnvHealthEnabled, v).Fatal("invalid environment variable value")
		}
		if he {
			resolved.HealthChecks = v3.Enabled
		} else {
			resolved.HealthChecks = v3.Disabled
		}
	}
	if resolved.HealthChecks != v3.Disabled {
		resolved.HealthChecks = v3.Enabled
	}

	// Node-specific settings
	if resolved.Controllers.Node != nil {
		// Sync labels — disabled for kubernetes datastore since labels are already there.
		if datastoreType == "kubernetes" {
			report["DATASTORE_TYPE"] = "kubernetes"
			resolved.Controllers.Node.SyncLabels = v3.Disabled
		} else if v, ok := env[EnvSyncNodeLabels]; ok {
			report[EnvSyncNodeLabels] = v
			snl, err := strconv.ParseBool(v)
			if err != nil {
				log.WithField(EnvSyncNodeLabels, v).Fatal("invalid environment variable value")
			}
			if snl {
				resolved.Controllers.Node.SyncLabels = v3.Enabled
			} else {
				resolved.Controllers.Node.SyncLabels = v3.Disabled
			}
		}
		if resolved.Controllers.Node.SyncLabels == "" {
			resolved.Controllers.Node.SyncLabels = v3.Enabled
		}

		// Auto host endpoints
		if v, ok := env[EnvAutoHostEndpoints]; ok {
			report[EnvAutoHostEndpoints] = v
			switch strings.ToLower(v) {
			case "enabled":
				resolved.Controllers.Node.HostEndpoint = &v3.AutoHostEndpointConfig{
					AutoCreate:                v3.Enabled,
					CreateDefaultHostEndpoint: v3.DefaultHostEndpointsEnabled,
				}
			case "disabled":
				resolved.Controllers.Node.HostEndpoint = &v3.AutoHostEndpointConfig{
					AutoCreate:                v3.Disabled,
					CreateDefaultHostEndpoint: v3.DefaultHostEndpointsEnabled,
				}
			default:
				log.WithField(EnvAutoHostEndpoints, v).Fatal("invalid environment variable value")
			}
		}
		if resolved.Controllers.Node.HostEndpoint == nil {
			resolved.Controllers.Node.HostEndpoint = &v3.AutoHostEndpointConfig{
				AutoCreate:                v3.Disabled,
				CreateDefaultHostEndpoint: v3.DefaultHostEndpointsEnabled,
			}
		}
		if resolved.Controllers.Node.HostEndpoint.CreateDefaultHostEndpoint == "" {
			resolved.Controllers.Node.HostEndpoint.CreateDefaultHostEndpoint = v3.DefaultHostEndpointsEnabled
		}

		// Leak grace period default
		if resolved.Controllers.Node.LeakGracePeriod == nil {
			resolved.Controllers.Node.LeakGracePeriod = &v1.Duration{Duration: defaultLeakGracePeriod}
		}
	}

	// Fill in default reconciler periods for enabled controllers.
	fillDefaultReconcilerPeriods(&resolved)

	// Migration controller — participates in the normal enabled/disabled flow.
	// If the API spec didn't include it and ENABLED_CONTROLLERS wasn't set,
	// it stays as-is from the API (which may be nil if not in the default config).
	// The default config enables it.

	return resolved, report
}

// resolveEnabledControllers determines which controllers are enabled based on
// the ENABLED_CONTROLLERS env var. Only listed controllers are enabled; their
// settings are preserved from the API config if present.
func resolveEnabledControllers(envVal string, apiControllers v3.ControllersConfig) v3.ControllersConfig {
	var out v3.ControllersConfig
	for controllerType := range strings.SplitSeq(envVal, ",") {
		switch controllerType {
		case "node":
			out.Node = apiControllers.Node
			if out.Node == nil {
				out.Node = &v3.NodeControllerConfig{}
			}
		case "policy":
			out.Policy = apiControllers.Policy
			if out.Policy == nil {
				out.Policy = &v3.PolicyControllerConfig{}
			}
		case "workloadendpoint":
			out.WorkloadEndpoint = apiControllers.WorkloadEndpoint
			if out.WorkloadEndpoint == nil {
				out.WorkloadEndpoint = &v3.WorkloadEndpointControllerConfig{}
			}
		case "profile", "namespace":
			out.Namespace = apiControllers.Namespace
			if out.Namespace == nil {
				out.Namespace = &v3.NamespaceControllerConfig{}
			}
		case "serviceaccount":
			out.ServiceAccount = apiControllers.ServiceAccount
			if out.ServiceAccount == nil {
				out.ServiceAccount = &v3.ServiceAccountControllerConfig{}
			}
		case "loadbalancer":
			out.LoadBalancer = apiControllers.LoadBalancer
			if out.LoadBalancer == nil {
				out.LoadBalancer = &v3.LoadBalancerControllerConfig{
					AssignIPs: v3.AllServices,
				}
			}
		case "migration":
			out.Migration = apiControllers.Migration
			if out.Migration == nil {
				out.Migration = &v3.MigrationControllerConfig{
					PolicyNameMigrator: v3.ControllerEnabled,
				}
			}
		case "flannelmigration":
			log.WithField(EnvEnabledControllers, envVal).Fatal("cannot run flannelmigration with other controllers")
		default:
			log.Fatalf("Invalid controller '%s' provided.", controllerType)
		}
	}
	return out
}

// fillDefaultReconcilerPeriods fills in the default reconciler period for any
// enabled controller that doesn't have one set.
func fillDefaultReconcilerPeriods(spec *v3.KubeControllersConfigurationSpec) {
	dp := &v1.Duration{Duration: defaultReconcilerPeriod}
	if spec.Controllers.Policy != nil && spec.Controllers.Policy.ReconcilerPeriod == nil {
		spec.Controllers.Policy.ReconcilerPeriod = dp
	}
	if spec.Controllers.WorkloadEndpoint != nil && spec.Controllers.WorkloadEndpoint.ReconcilerPeriod == nil {
		spec.Controllers.WorkloadEndpoint.ReconcilerPeriod = dp
	}
	if spec.Controllers.ServiceAccount != nil && spec.Controllers.ServiceAccount.ReconcilerPeriod == nil {
		spec.Controllers.ServiceAccount.ReconcilerPeriod = dp
	}
	if spec.Controllers.Namespace != nil && spec.Controllers.Namespace.ReconcilerPeriod == nil {
		spec.Controllers.Namespace.ReconcilerPeriod = dp
	}
}
