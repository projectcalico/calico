// Copyright (c) 2016 Tigera, Inc. All rights reserved.

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
	"fmt"

	"regexp"

	"reflect"

	"github.com/golang/glog"
	. "github.com/tigera/libcalico-go/lib/common"
)

var (
	matchHostEndpoint = regexp.MustCompile("^/?calico/v1/host/([^/]+)/endpoint/([^/]+)$")
	typeHostEndpoint  = reflect.TypeOf(HostEndpoint{})
)

type HostEndpointKey struct {
	Hostname   string `json:"-" validate:"required,hostname"`
	EndpointID string `json:"-" validate:"required,hostname"`
}

func (key HostEndpointKey) DefaultPath() (string, error) {
	if key.Hostname == "" {
		return "", ErrorInsufficientIdentifiers{Name: "hostname"}
	}
	if key.EndpointID == "" {
		return "", ErrorInsufficientIdentifiers{Name: "name"}
	}
	e := fmt.Sprintf("/calico/v1/host/%s/endpoint/%s",
		key.Hostname, key.EndpointID)
	return e, nil
}

func (key HostEndpointKey) DefaultDeletePath() (string, error) {
	return key.DefaultPath()
}

func (key HostEndpointKey) valueType() reflect.Type {
	return typeHostEndpoint
}

func (key HostEndpointKey) String() string {
	return fmt.Sprintf("HostEndpoint(hostname=%s, name=%s)", key.Hostname, key.EndpointID)
}

type HostEndpointListOptions struct {
	Hostname   string
	EndpointID string
}

func (options HostEndpointListOptions) DefaultPathRoot() string {
	k := "/calico/v1/host"
	if options.Hostname == "" {
		return k
	}
	k = k + fmt.Sprintf("/%s/endpoint", options.Hostname)
	if options.EndpointID == "" {
		return k
	}
	k = k + fmt.Sprintf("/%s", options.EndpointID)
	return k
}

func (options HostEndpointListOptions) ParseDefaultKey(ekey string) Key {
	glog.V(2).Infof("Get HostEndpoint key from %s", ekey)
	r := matchHostEndpoint.FindAllStringSubmatch(ekey, -1)
	if len(r) != 1 {
		glog.V(2).Infof("Didn't match regex")
		return nil
	}
	hostname := r[0][1]
	endpointID := r[0][2]
	if options.Hostname != "" && hostname != options.Hostname {
		glog.V(2).Infof("Didn't match hostname %s != %s", options.Hostname, hostname)
		return nil
	}
	if options.EndpointID != "" && endpointID != options.EndpointID {
		glog.V(2).Infof("Didn't match endpointID %s != %s", options.EndpointID, endpointID)
		return nil
	}
	return HostEndpointKey{Hostname: hostname, EndpointID: endpointID}
}

type HostEndpoint struct {
	Name              string            `json:"name,omitempty" validate:"omitempty,interface"`
	ExpectedIPv4Addrs []IP              `json:"expected_ipv4_addrs,omitempty" validate:"omitempty,dive,ipv4"`
	ExpectedIPv6Addrs []IP              `json:"expected_ipv6_addrs,omitempty" validate:"omitempty,dive,ipv6"`
	Labels            map[string]string `json:"labels,omitempty" validate:"omitempty,labels"`
	ProfileIDs        []string          `json:"profile_ids,omitempty" validate:"omitempty,dive,name"`
}
