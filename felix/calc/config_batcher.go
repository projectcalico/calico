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
	"maps"
	"slices"
	"time"

	apiv3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/felix/dispatcher"
	"github.com/projectcalico/calico/libcalico-go/lib/apis/internalapi"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/syncersv1/updateprocessors"
	"github.com/projectcalico/calico/libcalico-go/lib/selector"
)

// SelectorConfigEntry stores a selector-scoped FelixConfiguration along with
// its parsed selector and extracted config key-value pairs.
type SelectorConfigEntry struct {
	ResourceName string
	Sel          *selector.Selector
	Config       map[string]string
	CreationTime time.Time
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
	selectorConfigs map[string]*SelectorConfigEntry
}

func NewConfigBatcher(hostname string, callbacks configCallbacks) *ConfigBatcher {
	return &ConfigBatcher{
		hostname:        hostname,
		configDirty:     true,
		globalConfig:    make(map[string]string),
		hostConfig:      make(map[string]string),
		callbacks:       callbacks,
		selectorConfigs: make(map[string]*SelectorConfigEntry),
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
		log.WithField("key", update.Key).Debug("Ignoring update with unhandled key type")
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
		cb.onNodeUpdate(key.Name, update)
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

	var selectorStr string
	if fc.Spec.NodeSelector != nil {
		selectorStr = *fc.Spec.NodeSelector
	}

	var sel *selector.Selector
	if selectorStr != "" {
		var err error
		sel, err = selector.Parse(selectorStr)
		if err != nil {
			log.WithError(err).WithFields(log.Fields{
				"name":     name,
				"selector": selectorStr,
			}).Warn("Failed to parse nodeSelector on FelixConfiguration, removing selector-scoped config")
			if _, existed := cb.selectorConfigs[name]; existed {
				delete(cb.selectorConfigs, name)
				cb.configDirty = true
			}
			return
		}
	}

	config := updateprocessors.ExtractFelixConfigFields(fc)

	cb.selectorConfigs[name] = &SelectorConfigEntry{
		ResourceName: name,
		Sel:          sel,
		Config:       config,
		CreationTime: fc.CreationTimestamp.Time,
	}
	cb.configDirty = true
	log.WithFields(log.Fields{
		"name":     name,
		"selector": selectorStr,
		"config":   config,
	}).Info("Selector-scoped FelixConfiguration updated")
}

// onNodeUpdate handles an update to the local node resource, tracking label changes.
func (cb *ConfigBatcher) onNodeUpdate(name string, update api.Update) {
	if name != cb.hostname {
		return
	}
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
		cb.nodeLabels = maps.Clone(newLabels)
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

func (cb *ConfigBatcher) mergeMatchingSelectorConfigs() map[string]string {
	entries := make([]*SelectorConfigEntry, 0, len(cb.selectorConfigs))
	for _, entry := range cb.selectorConfigs {
		entries = append(entries, entry)
	}
	return MergeSelectorConfigs(entries, cb.nodeLabels)
}

// MergeSelectorConfigs evaluates selector-scoped FelixConfiguration entries
// against nodeLabels and returns the config from the winning match. If
// multiple entries match, the oldest by CreationTimestamp wins (tie-broken
// by resource name). This ensures that creating a new conflicting resource
// does not disrupt an existing, working configuration.
//
// This function is shared between the startup path (daemon.go) and the
// runtime path (ConfigBatcher) to avoid duplication of the merge logic.
func MergeSelectorConfigs(entries []*SelectorConfigEntry, nodeLabels map[string]string) map[string]string {
	if nodeLabels == nil {
		return map[string]string{}
	}
	var matches []*SelectorConfigEntry
	for _, entry := range entries {
		if entry.Sel == nil {
			continue
		}
		if entry.Sel.Evaluate(nodeLabels) {
			matches = append(matches, entry)
		}
	}
	if len(matches) == 0 {
		return map[string]string{}
	}
	winner := slices.MinFunc(matches, func(a, b *SelectorConfigEntry) int {
		if a.CreationTime.Before(b.CreationTime) {
			return -1
		}
		if b.CreationTime.Before(a.CreationTime) {
			return 1
		}
		if a.ResourceName < b.ResourceName {
			return -1
		}
		if a.ResourceName > b.ResourceName {
			return 1
		}
		return 0
	})
	if len(matches) > 1 {
		names := make([]string, len(matches))
		for i, m := range matches {
			names[i] = m.ResourceName
		}
		log.WithFields(log.Fields{
			"matching": names,
			"winner":   winner.ResourceName,
		}).Warn("Multiple selector-scoped FelixConfigurations match this node; using the oldest by creation time. This is likely a misconfiguration.")
	} else {
		log.WithField("name", winner.ResourceName).Debug("Selector-scoped FelixConfiguration matches local node")
	}
	return maps.Clone(winner.Config)
}
