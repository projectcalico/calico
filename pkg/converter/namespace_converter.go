// Copyright (c) 2017 Tigera, Inc. All rights reserved.
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

package converter

import (
	"github.com/projectcalico/libcalico-go/lib/api"
	"github.com/projectcalico/libcalico-go/lib/backend/k8s"
	backendConverter "github.com/projectcalico/libcalico-go/lib/converter"
	"k8s.io/client-go/pkg/api/v1"
)

// ProfileNameFormat Format used by policy controller to name Calico profiles
const ProfileNameFormat = "k8s_ns."

// profileLabelFormat Format used by policy controller to label Calico profiles
const profileLabelFormat = "pcns."

type namespaceConverter struct {
}

// NewNamespaceConverter Constructor for namespaceConverter
func NewNamespaceConverter() Converter {
	return &namespaceConverter{}
}
func (nc *namespaceConverter) Convert(k8sObj interface{}) (interface{}, error) {
	var c k8s.Converter
	namespace := k8sObj.(*v1.Namespace)
	kvpair, err := c.NamespaceToProfile(namespace)
	if err != nil {
		return nil, err
	}

	var bc backendConverter.ProfileConverter
	p, err := bc.ConvertKVPairToAPI(kvpair)
	if err != nil {
		return nil, err
	}
	profile := p.(*api.Profile)

	return *profile, nil
}

// GetKey returns name of the Profile as its key.  For Profiles
// backed by Kubernetes namespaces and managed by this controller, the name
// is of format `k8s_ns.name`.
func (nc *namespaceConverter) GetKey(obj interface{}) string {
	profile := obj.(api.Profile)
	return profile.Metadata.Name
}
