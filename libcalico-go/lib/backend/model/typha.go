// Copyright (c) 2025 Tigera, Inc. All rights reserved.

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

	log "github.com/sirupsen/logrus"
)

var (
	typeTyphaRevision = reflect.TypeOf(TyphaRevision{})
)

type TyphaRevisionKey struct{}

func (key TyphaRevisionKey) defaultPath() (string, error) {
	e := fmt.Sprintf("/calico/v1/typha/revision")
	return e, nil
}

func (key TyphaRevisionKey) defaultDeletePath() (string, error) {
	return key.defaultPath()
}

func (key TyphaRevisionKey) defaultDeleteParentPaths() ([]string, error) {
	return nil, nil
}

func (key TyphaRevisionKey) valueType() (reflect.Type, error) {
	return typeTyphaRevision, nil
}

func (key TyphaRevisionKey) String() string {
	return fmt.Sprintf("TyphaRevision()")
}

type TyphaRevisionListOptions struct {
}

func (options TyphaRevisionListOptions) defaultPathRoot() string {
	return "/calico/v1/typha/revision"
}

func (options TyphaRevisionListOptions) KeyFromDefaultPath(path string) Key {
	log.Debugf("Get TyphaRevision key from %s", path)
	if path == "/calico/v1/typha/revision" {
		return TyphaRevisionKey{}
	}
	return nil
}

type TyphaRevision struct {
	Revision string `json:"revision,omitempty"`
}
