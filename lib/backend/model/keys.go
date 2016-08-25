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
	"reflect"
	"strings"

	"github.com/golang/glog"
	"github.com/tigera/libcalico-go/lib/net"
)

// RawString is used a value type to indicate that the value is a bare non-JSON string
type rawString string
type rawBool bool

var rawStringType = reflect.TypeOf(rawString(""))
var rawBoolType = reflect.TypeOf(rawBool(true))

// Key represents a parsed datastore key.
type Key interface {
	defaultPath() (string, error)
	defaultDeletePath() (string, error)
	valueType() reflect.Type
}

// Interface used to perform datastore lookups.
type ListInterface interface {
	// defaultPathRoot() returns a default stringified root path, i.e. path
	// to the directory containing all the keys to be listed.
	defaultPathRoot() string

	// BUG(smc) I think we should remove this and use the package KeyFromDefaultPath function.
	// KeyFromDefaultPath parses the default path representation of the
	// Key type for this list.  It returns nil if passed a different kind
	// of path.
	KeyFromDefaultPath(key string) Key
}

// KVPair holds a typed key and value struct as well as datastore specific
// revision information.
type KVPair struct {
	Key      Key
	Value    interface{}
	Revision interface{}
}

// KeyToDefaultPath converts one of the Keys from this package into a unique
// '/'-delimited path, which is suitable for use as the key when storing the
// value in a hierarchical (i.e. one with directories and leaves) key/value
// datastore such as etcd v2.
//
// Each unique key returns a unique path.
//
// Keys with a hierarchical relationship share a common prefix.  However, in
// order to support datastores that do not support storing data at non-leaf
// nodes in the hierarchy (such as etcd v2), the path returned for a "parent"
// key, is not a direct ancestor of its children.
func KeyToDefaultPath(key Key) (string, error) {
	return key.defaultPath()
}

// KeyToDefaultDeletePath converts one of the Keys from this package into a
// unique '/'-delimited path, which is suitable for use as the key when
// (recursively) deleting the value from a hierarchical (i.e. one with
// directories and leaves) key/value datastore such as etcd v2.
//
// KeyToDefaultDeletePath returns a different path to KeyToDefaultPath when
// it is a passed a Key that represents a non-leaf which, for example, has its
// own metadata but also contains other resource types as children.
//
// KeyToDefaultDeletePath returns the common prefix of the non-leaf key and
// its children so that a recursive delete of that key would delete the
// object itself and any children it has.
func KeyToDefaultDeletePath(key Key) (string, error) {
	return key.defaultDeletePath()
}

// ListOptionsToDefaultPathRoot converts list options struct into a
// common-prefix path suitable for querying a datastore that uses the paths
// returned by KeyToDefaultPath.
func ListOptionsToDefaultPathRoot(listOptions ListInterface) string {
	return listOptions.defaultPathRoot()
}

// KeyFromDefaultPath parses the default path representation of a key into one
// of our <Type>Key structs.  Returns nil if the string doesn't match one of
// our key types.
func KeyFromDefaultPath(path string) Key {
	glog.V(4).Infof("Parsing key %v", path)
	if m := matchWorkloadEndpoint.FindStringSubmatch(path); m != nil {
		glog.V(5).Infof("Workload endpoint")
		return WorkloadEndpointKey{
			Hostname:       m[1],
			OrchestratorID: m[2],
			WorkloadID:     m[3],
			EndpointID:     m[4],
		}
	} else if m := matchHostEndpoint.FindStringSubmatch(path); m != nil {
		glog.V(5).Infof("Host endpoint")
		return HostEndpointKey{
			Hostname:   m[1],
			EndpointID: m[2],
		}
	} else if m := matchPolicy.FindStringSubmatch(path); m != nil {
		glog.V(5).Infof("Policy")
		return PolicyKey{
			Name: m[2],
		}
	} else if m := matchProfile.FindStringSubmatch(path); m != nil {
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
	} else if m := matchHostIp.FindStringSubmatch(path); m != nil {
		glog.V(5).Infof("Host ID")
		return HostIPKey{Hostname: m[1]}
	} else if m := matchPool.FindStringSubmatch(path); m != nil {
		glog.V(5).Infof("Pool")
		mungedCIDR := m[1]
		cidr := strings.Replace(mungedCIDR, "-", "/", 1)
		_, c, err := net.ParseCIDR(cidr)
		if err != nil {
			panic(err)
		}
		return PoolKey{CIDR: *c}
	} else if m := matchGlobalConfig.FindStringSubmatch(path); m != nil {
		return GlobalConfigKey{Name: m[1]}
	} else if m := matchHostConfig.FindStringSubmatch(path); m != nil {
		return HostConfigKey{Hostname: m[1], Name: m[2]}
	} else if matchReadyFlag.MatchString(path) {
		return ReadyFlagKey{}
	}
	// Not a key we know about.
	return nil
}

// ParseValue parses the default JSON representation of our data into one of
// our value structs, according to the type of key.  I.e. if passed a
// PolicyKey as the first parameter, it will try to parse rawData into a
// Policy struct.
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
