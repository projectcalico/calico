// Copyright (c) 2017 Tigera, Inc. All rights reserved.

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

package thirdparty

import (
	"encoding/json"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

type GlobalBgpConfigSpec struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type GlobalBgpConfig struct {
	metav1.TypeMeta `json:",inline"`
	Metadata        metav1.ObjectMeta `json:"metadata"`

	Spec GlobalBgpConfigSpec `json:"spec"`
}

type GlobalBgpConfigList struct {
	metav1.TypeMeta `json:",inline"`
	Metadata        metav1.ListMeta `json:"metadata"`

	Items []GlobalBgpConfig `json:"items"`
}

// Required to satisfy Object interface
func (e *GlobalBgpConfig) GetObjectKind() schema.ObjectKind {
	return &e.TypeMeta
}

// Required to satisfy ObjectMetaAccessor interface
func (e *GlobalBgpConfig) GetObjectMeta() metav1.Object {
	return &e.Metadata
}

// Required to satisfy Object interface
func (el *GlobalBgpConfigList) GetObjectKind() schema.ObjectKind {
	return &el.TypeMeta
}

// Required to satisfy ListMetaAccessor interface
func (el *GlobalBgpConfigList) GetListMeta() metav1.List {
	return &el.Metadata
}

// The code below is used only to work around a known problem with third-party
// resources and ugorji. If/when these issues are resolved, the code below
// should no longer be required.

type GlobalBgpConfigListCopy GlobalBgpConfigList
type GlobalBgpConfigCopy GlobalBgpConfig

func (g *GlobalBgpConfig) UnmarshalJSON(data []byte) error {
	tmp := GlobalBgpConfigCopy{}
	err := json.Unmarshal(data, &tmp)
	if err != nil {
		return err
	}
	tmp2 := GlobalBgpConfig(tmp)
	*g = tmp2
	return nil
}

func (l *GlobalBgpConfigList) UnmarshalJSON(data []byte) error {
	tmp := GlobalBgpConfigListCopy{}
	err := json.Unmarshal(data, &tmp)
	if err != nil {
		return err
	}
	tmp2 := GlobalBgpConfigList(tmp)
	*l = tmp2
	return nil
}
