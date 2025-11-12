// Copyright (c) 2024 Tigera, Inc. All rights reserved.

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

	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/libcalico-go/lib/errors"
)

var (
	matchTier = regexp.MustCompile("^/?calico/v1/policy/tier/([^/]+)/metadata$")
	typeTier  = reflect.TypeOf(Tier{})
)

type TierKey struct {
	Name string `json:"-" validate:"required,name"`
}

func (key TierKey) defaultPath() (string, error) {
	k, err := key.defaultDeletePath()
	return k + "/metadata", err
}

func (key TierKey) defaultDeletePath() (string, error) {
	if key.Name == "" {
		return "", errors.ErrorInsufficientIdentifiers{Name: "name"}
	}
	e := fmt.Sprintf("/calico/v1/policy/tier/%s", key.Name)
	return e, nil
}

func (key TierKey) defaultDeleteParentPaths() ([]string, error) {
	return nil, nil
}

func (key TierKey) valueType() (reflect.Type, error) {
	return typeTier, nil
}

func (key TierKey) parseValue(rawData []byte) (any, error) {
	return parseJSONPointer[Tier](key, rawData)
}

func (key TierKey) String() string {
	return fmt.Sprintf("Tier(name=%s)", key.Name)
}

type TierListOptions struct {
	Name string
}

func (options TierListOptions) defaultPathRoot() string {
	k := "/calico/v1/policy/tier"
	if options.Name == "" {
		return k
	}
	k = k + fmt.Sprintf("/%s/metadata", options.Name)
	return k
}

func (options TierListOptions) KeyFromDefaultPath(path string) Key {
	log.Infof("Get Tier key from %s", path)
	r := matchTier.FindAllStringSubmatch(path, -1)
	if len(r) != 1 {
		log.Infof("Didn't match regex")
		return nil
	}
	name := r[0][1]
	if options.Name != "" && name != options.Name {
		log.Infof("Didn't match name %s != %s", options.Name, name)
		return nil
	}
	return TierKey{Name: name}
}

type Tier struct {
	Order         *float64  `json:"order,omitempty"`
	DefaultAction v3.Action `json:"defaultAction,omitempty"`
}
