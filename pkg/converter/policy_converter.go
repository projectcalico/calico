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
	"reflect"

	"github.com/projectcalico/libcalico-go/lib/api"
	"github.com/projectcalico/libcalico-go/lib/backend/k8s"
	backendConverter "github.com/projectcalico/libcalico-go/lib/converter"
	log "github.com/sirupsen/logrus"
	"k8s.io/client-go/pkg/apis/extensions/v1beta1"
)

type policyConverter struct {
}

// NewPolicyConverter Constructor for policyConverter
func NewPolicyConverter() Converter {
	return &policyConverter{}
}

func (p *policyConverter) Convert(k8sObj interface{}) (interface{}, error) {
	if reflect.TypeOf(k8sObj) != reflect.TypeOf(&v1beta1.NetworkPolicy{}) {
		log.Fatalf("can not convert object %#v to calico policy. Object is not of type *v1beta1.NetworkPolicy", k8sObj)
	}

	np := k8sObj.(*v1beta1.NetworkPolicy)

	var policyConverter k8s.Converter
	kvpair, err := policyConverter.NetworkPolicyToPolicy(np)
	if err != nil {
		return nil, err
	}

	var backendConverter backendConverter.PolicyConverter
	policy, err := backendConverter.ConvertKVPairToAPI(kvpair)
	if err != nil {
		return nil, err
	}
	calicoPolicy := policy.(*api.Policy)
	return *calicoPolicy, err
}

// GetKey returns name of Policy as its key.  For Policies created by this controller
// and backed by NetworkPolicy objects, the name is of the format
// `knp.default.namespace.name`.
func (p *policyConverter) GetKey(obj interface{}) string {
	if reflect.TypeOf(obj) != reflect.TypeOf(api.Policy{}) {
		log.Fatalf("can not construct key for object %#v. Object is not of type api.Policy", obj)
	}
	policy := obj.(api.Policy)
	return policy.Metadata.Name
}
