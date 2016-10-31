// Copyright (c) 2016 Tigera, Inc. All rights reserved.
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
	log "github.com/Sirupsen/logrus"
	"github.com/projectcalico/felix/go/felix/dispatcher"
	"github.com/projectcalico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/libcalico-go/lib/backend/model"
)

type ConfigBatcher struct {
	hostname        string
	datastoreInSync bool
	configDirty     bool
	globalConfig    map[string]string
	hostConfig      map[string]string
	datastoreReady  bool
	callbacks       configCallbacks
}

func NewConfigBatcher(hostname string, callbacks configCallbacks) *ConfigBatcher {
	return &ConfigBatcher{
		hostname:     hostname,
		configDirty:  true,
		globalConfig: make(map[string]string),
		hostConfig:   make(map[string]string),
		callbacks:    callbacks,
	}
}

func (cb *ConfigBatcher) RegisterWith(allUpdDispatcher *dispatcher.Dispatcher) {
	allUpdDispatcher.Register(model.GlobalConfigKey{}, cb.OnUpdate)
	allUpdDispatcher.Register(model.HostConfigKey{}, cb.OnUpdate)
	allUpdDispatcher.Register(model.ReadyFlagKey{}, cb.OnUpdate)
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
		log.Infof("Host config update for this host: %v", update)
		if value, ok := update.Value.(string); value != cb.hostConfig[key.Name] {
			if ok {
				cb.hostConfig[key.Name] = value
			} else {
				delete(cb.hostConfig, key.Name)
			}
			cb.configDirty = true
		}
	case model.GlobalConfigKey:
		log.Infof("Global config update: %v", update)
		if value, ok := update.Value.(string); value != cb.globalConfig[key.Name] {
			if ok {
				cb.globalConfig[key.Name] = value
			} else {
				delete(cb.globalConfig, key.Name)
			}
			cb.configDirty = true
		}
	case model.ReadyFlagKey:
		if update.Value != true {
			log.WithField("value", update.Value).Warn(
				"Ready flag updated/deleted")
			cb.datastoreReady = false
			cb.configDirty = true
		} else {
			cb.datastoreReady = true
		}
	default:
		log.Fatalf("Unexpected update: %#v", update)
	}
	cb.maybeSendCachedConfig()
	return
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
	for k, v := range cb.globalConfig {
		globalConfigCopy[k] = v
	}
	for k, v := range cb.hostConfig {
		hostConfigCopy[k] = v
	}
	if !cb.datastoreReady {
		cb.callbacks.OnDatastoreNotReady()
	}
	cb.callbacks.OnConfigUpdate(globalConfigCopy, hostConfigCopy)
}
