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
	"fmt"
	"reflect"

	"github.com/projectcalico/libcalico-go/lib/errors"
)

var (
	typeGlobalBGPConfig = rawStringType
	typeHostBGPConfig   = rawStringType
)

type GlobalBGPConfigKey struct {
	// The name of the global BGP config key.
	Name string `json:"-" validate:"required,name"`
}

func (key GlobalBGPConfigKey) defaultPath() (string, error) {
	return key.defaultDeletePath()
}

func (key GlobalBGPConfigKey) defaultDeletePath() (string, error) {
	if key.Name == "" {
		return "", errors.ErrorInsufficientIdentifiers{Name: "name"}
	}
	e := fmt.Sprintf("/calico/bgp/v1/global/%s", key.Name)
	return e, nil
}

func (key GlobalBGPConfigKey) defaultDeleteParentPaths() ([]string, error) {
	return nil, nil
}

func (key GlobalBGPConfigKey) valueType() reflect.Type {
	return typeGlobalBGPConfig
}

func (key GlobalBGPConfigKey) String() string {
	return fmt.Sprintf("GlobalBGPConfig(name=%s)", key.Name)
}

type HostBGPConfigKey struct {
	// The hostname for the host specific BGP config
	Hostname string `json:"-" validate:"required,name"`

	// The name of the host specific BGP config key.
	Name string `json:"-" validate:"required,name"`
}

func (key HostBGPConfigKey) defaultPath() (string, error) {
	return key.defaultDeletePath()
}

func (key HostBGPConfigKey) defaultDeletePath() (string, error) {
	if key.Hostname == "" {
		return "", errors.ErrorInsufficientIdentifiers{Name: "node"}
	}
	if key.Name == "" {
		return "", errors.ErrorInsufficientIdentifiers{Name: "name"}
	}
	e := fmt.Sprintf("/calico/bgp/v1/host/%s/%s", key.Hostname, key.Name)
	return e, nil
}

func (key HostBGPConfigKey) defaultDeleteParentPaths() ([]string, error) {
	return nil, nil
}

func (key HostBGPConfigKey) valueType() reflect.Type {
	return typeHostBGPConfig
}

func (key HostBGPConfigKey) String() string {
	return fmt.Sprintf("HostBGPConfig(node=%s; name=%s)", key.Hostname, key.Name)
}
