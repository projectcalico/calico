// Copyright (c) 2016-2017 Tigera, Inc. All rights reserved.

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

package resources

import (
	"reflect"

	"github.com/projectcalico/libcalico-go/lib/api"
	"github.com/projectcalico/libcalico-go/lib/backend/k8s/custom"
	"github.com/projectcalico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/libcalico-go/lib/converter"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

const (
	IPPoolResourceName = "IPPools"
	IPPoolCRDName      = "ippools.crd.projectcalico.org"
)

func NewIPPoolClient(c *kubernetes.Clientset, r *rest.RESTClient) K8sResourceClient {
	return &customK8sResourceClient{
		clientSet:       c,
		restClient:      r,
		name:            IPPoolCRDName,
		resource:        IPPoolResourceName,
		description:     "Calico IP Pools",
		k8sResourceType: reflect.TypeOf(custom.IPPool{}),
		k8sListType:     reflect.TypeOf(custom.IPPoolList{}),
		converter:       IPPoolConverter{},
	}
}

// IPPoolConverter implements the K8sResourceConverter interface.
type IPPoolConverter struct {
	converter.IPPoolConverter
}

func (_ IPPoolConverter) ListInterfaceToKey(l model.ListInterface) model.Key {
	il := l.(model.IPPoolListOptions)
	if il.CIDR.IP != nil {
		return model.IPPoolKey{CIDR: il.CIDR}
	}
	return nil
}

func (_ IPPoolConverter) KeyToName(k model.Key) (string, error) {
	return IPNetToResourceName(k.(model.IPPoolKey).CIDR), nil
}

func (_ IPPoolConverter) NameToKey(name string) (model.Key, error) {
	cidr, err := ResourceNameToIPNet(name)
	if err != nil {
		return nil, err
	}
	return model.IPPoolKey{
		CIDR: *cidr,
	}, nil
}

func (i IPPoolConverter) ToKVPair(r CustomK8sResource) (*model.KVPair, error) {
	// Since we are using the Calico API Spec definition to store the Calico
	// IPPool, use the client conversion helper to convert API to KVP.
	t := r.(*custom.IPPool)

	_, err := ResourceNameToIPNet(t.Metadata.Name)
	if err != nil {
		return nil, err
	}

	ippool := api.IPPool{
		Metadata: api.IPPoolMetadata{
			CIDR: t.Spec.CIDR,
		},
		Spec: t.Spec.IPPoolSpec,
	}

	kvp, err := i.IPPoolConverter.ConvertAPIToKVPair(ippool)
	if err != nil {
		return nil, err
	}
	kvp.Revision = t.Metadata.ResourceVersion

	return kvp, nil
}

func (i IPPoolConverter) FromKVPair(kvp *model.KVPair) (CustomK8sResource, error) {
	// Since we are using the Calico API Spec definition to store the IPPool CRD Spec,
	// we can use the client conversion helper to convert KVP to API.
	r, err := i.IPPoolConverter.ConvertKVPairToAPI(kvp)
	if err != nil {
		return nil, err
	}

	crdName, err := i.KeyToName(kvp.Key)
	if err != nil {
		return nil, err
	}

	crd := custom.IPPool{
		Metadata: metav1.ObjectMeta{
			Name: crdName,
		},
		Spec: custom.IPPoolSpec{
			IPPoolSpec: r.(*api.IPPool).Spec,
			CIDR:       r.(*api.IPPool).Metadata.CIDR,
		},
	}

	if kvp.Revision != nil {
		crd.Metadata.ResourceVersion = kvp.Revision.(string)
	}
	return &crd, nil
}
