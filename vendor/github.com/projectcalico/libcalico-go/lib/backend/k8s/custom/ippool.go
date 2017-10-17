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

package custom

import (
	"encoding/json"

	"github.com/projectcalico/libcalico-go/lib/api"
	"github.com/projectcalico/libcalico-go/lib/net"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

// IPPool is the CustomResourceDefinition definition of an IPPool in the Kubernetes API.
type IPPool struct {
	metav1.TypeMeta `json:",inline"`
	Metadata        metav1.ObjectMeta `json:"metadata"`
	Spec            IPPoolSpec        `json:"spec"`
}

type IPPoolSpec struct {
	api.IPPoolSpec
	CIDR net.IPNet `json:"cidr"`
}

// IPPoolList is a list of IPPool resources.
type IPPoolList struct {
	metav1.TypeMeta `json:",inline"`
	Metadata        metav1.ListMeta `json:"metadata"`
	Items           []IPPool        `json:"items"`
}

// GetObjectKind returns the kind of this object.  Required to satisfy Object interface
func (e *IPPool) GetObjectKind() schema.ObjectKind {
	return &e.TypeMeta
}

// GetOjbectMeta returns the object metadata of this object. Required to satisfy ObjectMetaAccessor interface
func (e *IPPool) GetObjectMeta() metav1.Object {
	return &e.Metadata
}

// GetObjectKind returns the kind of this object. Required to satisfy Object interface
func (el *IPPoolList) GetObjectKind() schema.ObjectKind {
	return &el.TypeMeta
}

// GetListMeta returns the list metadata of this object. Required to satisfy ListMetaAccessor interface
func (el *IPPoolList) GetListMeta() metav1.List {
	return &el.Metadata
}

// The code below is used only to work around a known problem with third-party
// resources and ugorji. If/when these issues are resolved, the code below
// should no longer be required.

type IPPoolListCopy IPPoolList
type IPPoolCopy IPPool

func (g *IPPool) UnmarshalJSON(data []byte) error {
	tmp := IPPoolCopy{}
	err := json.Unmarshal(data, &tmp)
	if err != nil {
		return err
	}
	tmp2 := IPPool(tmp)
	*g = tmp2
	return nil
}

func (l *IPPoolList) UnmarshalJSON(data []byte) error {
	tmp := IPPoolListCopy{}
	err := json.Unmarshal(data, &tmp)
	if err != nil {
		return err
	}
	tmp2 := IPPoolList(tmp)
	*l = tmp2
	return nil
}
