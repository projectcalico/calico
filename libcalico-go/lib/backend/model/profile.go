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
	"reflect"
	"regexp"

	"github.com/projectcalico/calico/libcalico-go/lib/errors"
)

var matchProfile = regexp.MustCompile("^/?calico/v1/policy/profile/([^/]+)/(rules|labels)$")

// ProfileKey is the common parent of a profile's v1 entries.  It is not a key in its own right.
type ProfileKey struct {
	Name string `json:"-" validate:"required,name"`
}

func (key ProfileKey) defaultPath() (string, error) {
	if key.Name == "" {
		return "", errors.ErrorInsufficientIdentifiers{Name: "name"}
	}
	e := fmt.Sprintf("/calico/v1/policy/profile/%s", escapeName(key.Name))
	return e, nil
}

func (key ProfileKey) defaultDeletePath() (string, error) {
	return key.defaultPath()
}

func (key ProfileKey) defaultDeleteParentPaths() ([]string, error) {
	return nil, nil
}

func (key ProfileKey) String() string {
	return fmt.Sprintf("Profile(name=%s)", key.Name)
}

// ProfileRulesKey implements the KeyInterface for the profile rules
type ProfileRulesKey struct {
	ProfileKey
}

func (key ProfileRulesKey) defaultPath() (string, error) {
	e, err := key.ProfileKey.defaultPath()
	return e + "/rules", err
}

func (key ProfileRulesKey) valueType() (reflect.Type, error) {
	return reflect.TypeFor[ProfileRules](), nil
}

func (key ProfileRulesKey) parseValue(rawData []byte) (any, error) {
	return parseJSONPointer[ProfileRules](key, rawData)
}

func (key ProfileRulesKey) String() string {
	return fmt.Sprintf("ProfileRules(name=%s)", key.Name)
}

// ProfileLabelsKey is the key for a profile's labels.
//
// Deprecated: Typha v3.33 and earlier stream these keys, but nothing consumes them.  The type
// remains only so that a newer Felix can parse them during an upgrade, instead of logging an error
// for each one.
type ProfileLabelsKey struct {
	ProfileKey
}

func (key ProfileLabelsKey) defaultPath() (string, error) {
	e, err := key.ProfileKey.defaultPath()
	return e + "/labels", err
}

func (key ProfileLabelsKey) valueType() (reflect.Type, error) {
	return reflect.TypeFor[map[string]string](), nil
}

func (key ProfileLabelsKey) parseValue(rawData []byte) (any, error) {
	return parseJSONValue[map[string]string](key, rawData)
}

func (key ProfileLabelsKey) String() string {
	return fmt.Sprintf("ProfileLabels(name=%s)", key.Name)
}

type ProfileRules struct {
	InboundRules  []Rule `json:"inbound_rules,omitempty" validate:"omitempty,dive"`
	OutboundRules []Rule `json:"outbound_rules,omitempty" validate:"omitempty,dive"`
}
