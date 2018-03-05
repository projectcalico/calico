// Copyright (c) 2018 Tigera, Inc. All rights reserved.
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
	"strings"

	"github.com/projectcalico/felix/dispatcher"
	"github.com/projectcalico/felix/proto"
	"github.com/projectcalico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/libcalico-go/lib/backend/k8s/conversion"
	"github.com/projectcalico/libcalico-go/lib/backend/model"

	log "github.com/sirupsen/logrus"
)

type kind int

const (
	KindUnknown kind = iota
	KindServiceAccount
	KindNamespace
)

// ProfileDecoder takes updates from a dispatcher, determines if the profile is a Kubernetes Service Account or
// Kubernetes Namespace, and if it is, generates a dataplane update or remove for it.
type ProfileDecoder struct {
	callbacks passthruCallbacks
	converter conversion.Converter
}

func NewProfileDecoder(callbacks passthruCallbacks) *ProfileDecoder {
	return &ProfileDecoder{callbacks: callbacks, converter: conversion.Converter{true}}
}

func (p *ProfileDecoder) RegisterWith(d *dispatcher.Dispatcher) {
	d.Register(model.ProfileLabelsKey{}, p.OnUpdate)
}

func (p *ProfileDecoder) OnUpdate(update api.Update) (filterOut bool) {
	// This type assertion is safe because we only registered for ProfileLabels updates.
	key := update.Key.(model.ProfileLabelsKey)
	log.WithField("key", key.String()).Debug("Decoding ProfileLabels")
	id, knd := p.classifyProfile(key)
	switch knd {
	case KindUnknown:
		log.WithField("key", key.String()).Debug("Ignoring ProfileLabels")
	case KindServiceAccount:
		id := id.(proto.ServiceAccountID)
		if update.Value == nil {
			p.callbacks.OnServiceAccountRemove(id)
		} else {
			labels := update.Value.(map[string]string)
			msg := proto.ServiceAccountUpdate{Id: &id, Labels: decodeLabels(knd, labels)}
			p.callbacks.OnServiceAccountUpdate(&msg)
		}
	case KindNamespace:
		id := id.(proto.NamespaceID)
		if update.Value == nil {
			p.callbacks.OnNamespaceRemove(id)
		} else {
			labels := update.Value.(map[string]string)
			msg := proto.NamespaceUpdate{Id: &id, Labels: decodeLabels(knd, labels)}
			p.callbacks.OnNamespaceUpdate(&msg)
		}
	}
	return false
}

func (p *ProfileDecoder) classifyProfile(key model.ProfileLabelsKey) (interface{}, kind) {
	namespace, name, err := p.converter.ProfileNameToServiceAccount(key.Name)
	if err == nil {
		return proto.ServiceAccountID{Name: name, Namespace: namespace}, KindServiceAccount
	}
	name, err = p.converter.ProfileNameToNamespace(key.Name)
	if err == nil {
		return proto.NamespaceID{Name: name}, KindNamespace
	}
	return nil, KindUnknown
}

// decodeLabels strips the special prefix we add to Profile labels when converting. This gives us the original labels on
// the ServiceAccount or Namespace object.
func decodeLabels(k kind, in map[string]string) map[string]string {
	var prefix string
	if k == KindServiceAccount {
		prefix = conversion.ServiceAccountLabelPrefix
	} else if k == KindNamespace {
		prefix = conversion.NamespaceLabelPrefix
	}
	out := make(map[string]string)
	for k, v := range in {
		k = strings.TrimPrefix(k, prefix)
		out[k] = v
	}
	return out
}
