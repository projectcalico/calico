// Copyright (c) 2016-2017,2025 Tigera, Inc. All rights reserved.
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

package calc

import (
	"fmt"
	"maps"
	"reflect"
	"strings"
	"time"

	apiv3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	log "github.com/sirupsen/logrus"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/projectcalico/calico/felix/dispatcher"
	"github.com/projectcalico/calico/libcalico-go/lib/apis/internalapi"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/calico/libcalico-go/lib/selector"
)

// selectorConfigEntry stores a selector-scoped FelixConfiguration along with
// its parsed selector and extracted config key-value pairs.
type selectorConfigEntry struct {
	selectorStr string
	sel         *selector.Selector
	config      map[string]string
}

type ConfigBatcher struct {
	hostname        string
	datastoreInSync bool
	configDirty     bool
	globalConfig    map[string]string
	hostConfig      map[string]string
	datastoreReady  bool
	callbacks       configCallbacks

	// nodeLabels holds the labels of the local node, used for evaluating
	// selector-scoped FelixConfiguration resources.
	nodeLabels map[string]string

	// selectorConfigs stores selector-scoped FelixConfiguration resources,
	// keyed by the resource name.
	selectorConfigs map[string]*selectorConfigEntry
}

func NewConfigBatcher(hostname string, callbacks configCallbacks) *ConfigBatcher {
	return &ConfigBatcher{
		hostname:        hostname,
		configDirty:     true,
		globalConfig:    make(map[string]string),
		hostConfig:      make(map[string]string),
		callbacks:       callbacks,
		selectorConfigs: make(map[string]*selectorConfigEntry),
	}
}

func (cb *ConfigBatcher) RegisterWith(allUpdDispatcher *dispatcher.Dispatcher) {
	allUpdDispatcher.Register(model.GlobalConfigKey{}, cb.OnUpdate)
	allUpdDispatcher.Register(model.HostConfigKey{}, cb.OnUpdate)
	allUpdDispatcher.Register(model.ReadyFlagKey{}, cb.OnUpdate)
	allUpdDispatcher.Register(model.ResourceKey{}, cb.OnUpdate)
	allUpdDispatcher.RegisterStatusHandler(cb.OnDatamodelStatus)
}

func (cb *ConfigBatcher) OnUpdate(update api.Update) (filterOut bool) {
	switch key := update.Key.(type) {
	case model.HostConfigKey:
		if key.Hostname != cb.hostname {
			log.Debugf("Ignoring host config not for this host: %v", key)
			filterOut = true
			return
		}
		if value, ok := update.Value.(string); value != cb.hostConfig[key.Name] {
			log.Infof("Host config update for this host: %v", update)
			if ok {
				cb.hostConfig[key.Name] = value
			} else {
				delete(cb.hostConfig, key.Name)
			}
			cb.configDirty = true
		} else {
			log.Debugf("Ignoring no-op host config update for this host: %v", update)
			return
		}
	case model.GlobalConfigKey:
		if value, ok := update.Value.(string); value != cb.globalConfig[key.Name] {
			log.Infof("Global config update: %v", update)
			if ok {
				cb.globalConfig[key.Name] = value
			} else {
				delete(cb.globalConfig, key.Name)
			}
			cb.configDirty = true
		} else {
			log.Debugf("Ignoring no-op global config update: %v", update)
			return
		}
	case model.ReadyFlagKey:
		if update.Value != true {
			log.WithField("value", update.Value).Warn("Ready flag updated/deleted")
			cb.datastoreReady = false
			cb.configDirty = true
		} else {
			cb.datastoreReady = true
		}
	case model.ResourceKey:
		return cb.onResourceUpdate(key, update)
	default:
		// Ignore updates for unknown key types; other components may register
		// for model.ResourceKey and dispatch updates that aren't relevant here.
		return
	}
	cb.maybeSendCachedConfig()
	return
}

// onResourceUpdate handles ResourceKey-typed updates. These are used for:
//   - selector-scoped FelixConfiguration resources (Kind == KindFelixConfiguration)
//   - Node resources (Kind == KindNode) for tracking local node labels
func (cb *ConfigBatcher) onResourceUpdate(key model.ResourceKey, update api.Update) (filterOut bool) {
	switch key.Kind {
	case apiv3.KindFelixConfiguration:
		cb.onFelixConfigResourceUpdate(key.Name, update)
	case internalapi.KindNode:
		if key.Name != cb.hostname {
			return
		}
		cb.onNodeUpdate(update)
	default:
		// Not a resource we care about.
		return
	}
	cb.maybeSendCachedConfig()
	return
}

// onFelixConfigResourceUpdate handles a selector-scoped FelixConfiguration resource update.
func (cb *ConfigBatcher) onFelixConfigResourceUpdate(name string, update api.Update) {
	if update.Value == nil {
		// Delete
		if _, existed := cb.selectorConfigs[name]; existed {
			delete(cb.selectorConfigs, name)
			cb.configDirty = true
			log.WithField("name", name).Info("Selector-scoped FelixConfiguration deleted")
		}
		return
	}

	fc, ok := update.Value.(*apiv3.FelixConfiguration)
	if !ok {
		log.WithField("value", update.Value).Warn("Unexpected value type for FelixConfiguration resource")
		return
	}

	selectorStr := fc.Spec.NodeSelector
	if selectorStr == "" {
		// Empty selector on a selector-scoped resource — matches no nodes.
		// We still store it in case a selector is added later via update.
		log.WithField("name", name).Debug("Selector-scoped FelixConfiguration with empty selector, matches no nodes")
	}

	var sel *selector.Selector
	if selectorStr != "" {
		var err error
		sel, err = selector.Parse(selectorStr)
		if err != nil {
			log.WithError(err).WithFields(log.Fields{
				"name":     name,
				"selector": selectorStr,
			}).Warn("Failed to parse nodeSelector on FelixConfiguration, ignoring")
			return
		}
	}

	config := ExtractConfigFromFelixSpec(&fc.Spec)

	cb.selectorConfigs[name] = &selectorConfigEntry{
		selectorStr: selectorStr,
		sel:         sel,
		config:      config,
	}
	cb.configDirty = true
	log.WithFields(log.Fields{
		"name":     name,
		"selector": selectorStr,
		"config":   config,
	}).Info("Selector-scoped FelixConfiguration updated")
}

// onNodeUpdate handles an update to the local node resource, tracking label changes.
func (cb *ConfigBatcher) onNodeUpdate(update api.Update) {
	if update.Value == nil {
		if cb.nodeLabels != nil {
			cb.nodeLabels = nil
			cb.configDirty = true
			log.Info("Local node deleted, clearing node labels")
		}
		return
	}

	node, ok := update.Value.(*internalapi.Node)
	if !ok {
		log.WithField("value", update.Value).Warn("Unexpected value type for Node resource")
		return
	}

	newLabels := node.Labels
	if !maps.Equal(cb.nodeLabels, newLabels) {
		cb.nodeLabels = newLabels
		cb.configDirty = true
		log.WithField("labels", newLabels).Info("Local node labels changed")
	}
}

func (cb *ConfigBatcher) OnDatamodelStatus(status api.SyncStatus) {
	if !cb.datastoreInSync && status == api.InSync {
		log.Infof("Datamodel in sync, flushing config update")
		cb.datastoreInSync = true
		cb.maybeSendCachedConfig()
	}
}

func (cb *ConfigBatcher) maybeSendCachedConfig() {
	if !cb.configDirty || !cb.datastoreInSync {
		return
	}
	log.Infof("Sending config update global: %v, host: %v.",
		cb.globalConfig, cb.hostConfig)
	globalConfigCopy := make(map[string]string)
	hostConfigCopy := make(map[string]string)
	maps.Copy(globalConfigCopy, cb.globalConfig)
	maps.Copy(hostConfigCopy, cb.hostConfig)

	// Merge all matching selector-scoped configs into a single map.
	selectorConfigMerged := cb.mergeMatchingSelectorConfigs()

	if !cb.datastoreReady {
		cb.callbacks.OnDatastoreNotReady()
	}
	cb.callbacks.OnConfigUpdate(globalConfigCopy, selectorConfigMerged, hostConfigCopy)
	cb.configDirty = false
}

// mergeMatchingSelectorConfigs evaluates all selector-scoped FelixConfiguration
// resources against the local node's labels and merges matching configs into a
// single map. When multiple resources match, values from all are merged; if
// multiple resources set the same key, the effective value is not well defined.
func (cb *ConfigBatcher) mergeMatchingSelectorConfigs() map[string]string {
	merged := make(map[string]string)
	for name, entry := range cb.selectorConfigs {
		if entry.sel == nil {
			// No selector means this doesn't match any node.
			continue
		}
		if cb.nodeLabels == nil {
			// No node labels available; can't match.
			continue
		}
		if entry.sel.Evaluate(cb.nodeLabels) {
			log.WithField("name", name).Debug("Selector-scoped FelixConfiguration matches local node")
			maps.Copy(merged, entry.config)
		}
	}
	return merged
}

// ExtractConfigFromFelixSpec extracts the configuration key-value pairs from a
// FelixConfigurationSpec using reflection. This mirrors the logic in the
// configUpdateProcessor but produces a simple map rather than v1-model KVPairs.
func ExtractConfigFromFelixSpec(spec *apiv3.FelixConfigurationSpec) map[string]string {
	config := make(map[string]string)
	specValue := reflect.ValueOf(spec).Elem()
	specType := specValue.Type()

	for i := 0; i < specType.NumField(); i++ {
		fieldInfo := specType.Field(i)
		name := fieldInfo.Tag.Get("confignamev1")
		if name == "-" {
			continue
		}
		if name == "" {
			name = fieldInfo.Name
		}

		field := specValue.Field(i)

		// Skip unset (nil pointer) fields and empty strings.
		if field.Kind() == reflect.Pointer {
			if field.IsNil() {
				continue
			}
			field = field.Elem()
		} else {
			if field.Kind() == reflect.String && field.Len() == 0 {
				continue
			}
		}

		value := field.Interface()

		// Convert the value to string, similar to the configurationprocessor.
		var strValue string
		switch vt := value.(type) {
		case string:
			strValue = vt
		case v1.Duration:
			switch fieldInfo.Tag.Get("configv1timescale") {
			case "milliseconds":
				ms := vt.Duration / time.Millisecond
				nMs := vt.Duration % time.Millisecond
				strValue = fmt.Sprintf("%v", float64(ms)+float64(nMs)/1e6)
			default:
				strValue = fmt.Sprintf("%v", vt.Seconds())
			}
		case []string:
			strValue = strings.Join(vt, ",")
		case map[string]string:
			var kvp strings.Builder
			for k, v := range vt {
				kvp.WriteString(k + "=" + v + ",")
			}
			strValue = kvp.String()
		default:
			strValue = fmt.Sprintf("%v", vt)
		}

		config[name] = strValue
	}
	return config
}
