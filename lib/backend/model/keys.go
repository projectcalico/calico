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

package model

import (
	"encoding/json"
	"errors"
	"reflect"
	"strings"

	"github.com/golang/glog"
	"github.com/tigera/libcalico-go/lib/types"
)

// RawString is used a value type to indicate that the value is a bare non-JSON string
type rawString string
type rawBool bool

var rawStringType = reflect.TypeOf(rawString(""))
var rawBoolType = reflect.TypeOf(rawBool(true))

// Key represents a parsed datastore key.
type Key interface {
	// DefaultPath() returns a default stringified path for this object,
	// suitable for use in most datastores (and used on the Felix API,
	// for example).
	DefaultPath() (string, error)
	// DefaultDeletePath() returns a default stringified path for deleting
	// this object.
	DefaultDeletePath() (string, error)
	valueType() reflect.Type
}

// Interface used to perform datastore lookups.
type ListInterface interface {
	// DefaultPathRoot() returns a default stringified root path, i.e. path
	// to the directory containing all the keys to be listed.
	DefaultPathRoot() string
	ParseDefaultKey(key string) Key
}

// KVPair holds a parsed key and value as well as datastore specific revision
// information.
type KVPair struct {
	Key      Key
	Value    interface{}
	Revision interface{}
}

// ParseKey parses a datastore key into one of the <Type>Key structs.
// Returns nil if the string doesn't match one of our objects.
func ParseKey(key string) Key {
	glog.V(4).Infof("Parsing key %v", key)
	if m := matchWorkloadEndpoint.FindStringSubmatch(key); m != nil {
		glog.V(5).Infof("Workload endpoint")
		return WorkloadEndpointKey{
			Hostname:       m[1],
			OrchestratorID: m[2],
			WorkloadID:     m[3],
			EndpointID:     m[4],
		}
	} else if m := matchHostEndpoint.FindStringSubmatch(key); m != nil {
		glog.V(5).Infof("Host endpoint")
		return HostEndpointKey{
			Hostname:   m[1],
			EndpointID: m[2],
		}
	} else if m := matchPolicy.FindStringSubmatch(key); m != nil {
		glog.V(5).Infof("Policy")
		return PolicyKey{
			Name: m[2],
		}
	} else if m := matchProfile.FindStringSubmatch(key); m != nil {
		glog.V(5).Infof("Profile %v", m)
		pk := ProfileKey{m[1]}
		switch m[2] {
		case "tags":
			glog.V(5).Infof("Profile tags")
			return ProfileTagsKey{ProfileKey: pk}
		case "rules":
			glog.V(5).Infof("Profile rules")
			return ProfileRulesKey{ProfileKey: pk}
		case "labels":
			glog.V(5).Infof("Profile labels")
			return ProfileLabelsKey{ProfileKey: pk}
		}
		return nil
	} else if m := matchHostIp.FindStringSubmatch(key); m != nil {
		glog.V(5).Infof("Host ID")
		return HostIPKey{Hostname: m[1]}
	} else if m := matchPool.FindStringSubmatch(key); m != nil {
		glog.V(5).Infof("Pool")
		mungedCIDR := m[1]
		cidr := strings.Replace(mungedCIDR, "-", "/", 1)
		_, c, err := types.ParseCIDR(cidr)
		if err != nil {
			panic(err)
		}
		return PoolKey{CIDR: *c}
	} else if m := matchGlobalConfig.FindStringSubmatch(key); m != nil {
		return GlobalConfigKey{Name: m[1]}
	} else if m := matchHostConfig.FindStringSubmatch(key); m != nil {
		return HostConfigKey{Hostname: m[1], Name: m[2]}
	} else if matchReadyFlag.MatchString(key) {
		return ReadyFlagKey{}
	}
	// Not a key we know about.
	return nil
}

func ParseValue(key Key, rawData []byte) (interface{}, error) {
	valueType := key.valueType()
	if valueType == rawStringType {
		return string(rawData), nil
	}
	if valueType == rawBoolType {
		return string(rawData) == "true", nil
	}
	value := reflect.New(valueType)
	elem := value.Elem()
	if elem.Kind() == reflect.Struct && elem.NumField() > 0 {
		if elem.Field(0).Type() == reflect.ValueOf(key).Type() {
			elem.Field(0).Set(reflect.ValueOf(key))
		}
	}
	iface := value.Interface()
	err := json.Unmarshal(rawData, iface)
	if err != nil {
		glog.V(0).Infof("Failed to unmarshal %#v into value %#v",
			string(rawData), value)
		return nil, err
	}
	if elem.Kind() != reflect.Struct {
		// Pointer to a map or slice, unwrap.
		iface = elem.Interface()
	}
	return iface, nil
}

func ParseKeyValue(key string, rawData []byte) (Key, interface{}, error) {
	parsedKey := ParseKey(key)
	if parsedKey == nil {
		return nil, nil, errors.New("Failed to parse key")
	}
	value, err := ParseValue(parsedKey, rawData)
	return parsedKey, value, err
}
