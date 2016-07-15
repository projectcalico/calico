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

package backend

import (
	"encoding/json"
	"errors"
	"github.com/golang/glog"
	"reflect"
)

// ParseKey parses a datastore key into one of the <Type>Key structs.
// Returns nil if the string doesn't match one of our objects.
func ParseKey(key string) KeyInterface {
	if m := matchWorkloadEndpoint.FindStringSubmatch(key); m != nil {
		return WorkloadEndpointKey{
			Hostname:       m[1],
			OrchestratorID: m[2],
			WorkloadID:     m[3],
			EndpointID:     m[4],
		}
	} else if m := matchPolicy.FindStringSubmatch(key); m != nil {
		return PolicyKey{
			Name: m[2],
		}
	} else if m := matchProfile.FindStringSubmatch(key); m != nil {
		pk := ProfileKey{m[1]}
		switch m[2] {
		case "tags":
			return ProfileTagsKey{ProfileKey: pk}
		case "rules":
			return ProfileRulesKey{ProfileKey: pk}
		case "labels":
			return ProfileLabelsKey{ProfileKey: pk}
		}
		return nil
	} else if m := matchHostIp.FindStringSubmatch(key); m != nil {
		return HostIPKey{Hostname: m[1]}
	}
	// Not a key we know about.
	return nil
}

func ParseValue(key KeyInterface, rawData []byte) (interface{}, error) {
	value := reflect.New(key.valueType())
	iface := value.Interface()
	err := json.Unmarshal(rawData, iface)
	if err != nil {
		glog.Errorf("Failed to unmarshal %#v into value %#v",
			string(rawData), value)
		return nil, err
	}
	if value.Elem().Kind() != reflect.Struct {
		// Pointer to a map or slice, unwrap.
		iface = value.Elem().Interface()
	}
	return iface, nil
}

func ParseKeyValue(key string, rawData []byte) (KeyInterface, interface{}, error) {
	parsedKey := ParseKey(key)
	if parsedKey == nil {
		return nil, nil, errors.New("Failed to parse key")
	}
	value, err := ParseValue(parsedKey, rawData)
	return parsedKey, value, err
}
