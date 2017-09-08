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
	"fmt"
	"reflect"

	"github.com/projectcalico/libcalico-go/lib/api"
	log "github.com/sirupsen/logrus"
	k8sApiV1 "k8s.io/client-go/pkg/api/v1"
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
func (p *namespaceConverter) Convert(k8sObj interface{}) (interface{}, error) {
	if reflect.TypeOf(k8sObj).String() != "*v1.Namespace" {
		log.Fatalf("can not convert object %#v to calico profile. Object is not of type *v1.Namespace", k8sObj)
	}

	namespace := k8sObj.(*k8sApiV1.Namespace)
	profile := api.NewProfile()

	name := fmt.Sprintf(ProfileNameFormat+"%s", namespace.ObjectMeta.Name)

	// Generate the labels to apply to the profile, using a special prefix
	// to indicate that these are the labels from the parent Kubernetes Namespace.
	labels := map[string]string{}

	for k, v := range namespace.ObjectMeta.Labels {
		labels[fmt.Sprintf(profileLabelFormat+"%s", k)] = v
	}

	profile.Metadata.Name = name
	profile.Metadata.Labels = labels
	profile.Spec = api.ProfileSpec{
		IngressRules: []api.Rule{api.Rule{Action: "allow"}},
		EgressRules:  []api.Rule{api.Rule{Action: "allow"}},
	}

	return *profile, nil
}

// GetKey returns name of the Profile as its key.  For Profiles
// backed by Kubernetes namespaces and managed by this controller, the name
// is of format `k8s_ns.name`.
func (p *namespaceConverter) GetKey(obj interface{}) string {

	if reflect.TypeOf(obj) != reflect.TypeOf(api.Profile{}) {
		log.Fatalf("can not construct key for object %#v. Object is not of type api.WorkloadEndpoint", obj)
	}
	profile := obj.(api.Profile)
	return profile.Metadata.Name
}
