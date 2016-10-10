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

package store

import (
	log "github.com/Sirupsen/logrus"
	"github.com/projectcalico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/libcalico-go/lib/backend/model"
	"reflect"
)

type UpdateHandler interface {
	OnUpdate(update model.KVPair) (filterOut bool)
	OnDatamodelStatus(status api.SyncStatus)
}

type Dispatcher struct {
	typeToHandler map[reflect.Type][]UpdateHandler
	allHandlers   map[UpdateHandler]bool
}

// NewDispatcher creates a Dispatcher with all its event handlers set to no-ops.
func NewDispatcher() *Dispatcher {
	d := &Dispatcher{
		typeToHandler: make(map[reflect.Type][]UpdateHandler),
		allHandlers:   make(map[UpdateHandler]bool),
	}
	return d
}

func (d *Dispatcher) Register(keyExample model.Key, receiver UpdateHandler) {
	keyType := reflect.TypeOf(keyExample)
	if keyType.Kind() == reflect.Ptr {
		panic("Register expects a non-pointer")
	}
	log.Infof("Registering listener for type %v: %#v", keyType, receiver)
	d.typeToHandler[keyType] = append(d.typeToHandler[keyType], receiver)
	d.allHandlers[receiver] = true
}

// Syncer callbacks.

func (d *Dispatcher) OnUpdates(updates []model.KVPair) {
	for _, update := range updates {
		d.OnUpdate(update)
	}
}

func (d *Dispatcher) OnStatusUpdated(status api.SyncStatus) {
	for handler, _ := range d.allHandlers {
		handler.OnDatamodelStatus(status)
	}
}

// Dispatcher callbacks.

func (d *Dispatcher) OnUpdate(update model.KVPair) (filterOut bool) {
	log.Debugf("Dispatching %v", update)
	keyType := reflect.TypeOf(update.Key)
	log.Debug("Type: ", keyType)
	listeners := d.typeToHandler[keyType]
	if update.Value != nil && reflect.TypeOf(update.Value).Kind() == reflect.Struct {
		log.Fatalf("KVPair contained a struct instead of expected pointer: %#v", update)
	}
	log.Debugf("Listeners: %#v", listeners)
	for _, recv := range listeners {
		filterOut := recv.OnUpdate(update)
		if filterOut {
			// Note: we don't propagate the filterOut flag.  We only
			// filter downstream in the processing pipeline, we don't
			// want to prevent our peers from handling updates.
			break
		}
	}
	return
}

func (d *Dispatcher) OnDatamodelStatus(status api.SyncStatus) {
	d.OnStatusUpdated(status)
}
