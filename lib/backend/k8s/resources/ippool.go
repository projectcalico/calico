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
	"encoding/json"
	"reflect"

	"github.com/projectcalico/libcalico-go/lib/backend/k8s/thirdparty"
	"github.com/projectcalico/libcalico-go/lib/backend/model"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

const (
	IPPoolResourceName = "ippools"
	IPPoolTPRName      = "ip-pool.projectcalico.org"
)

func NewIPPoolClient(c *kubernetes.Clientset, r *rest.RESTClient) K8sResourceClient {
	return &customK8sResourceClient{
		clientSet:       c,
		restClient:      r,
		name:            IPPoolTPRName,
		resource:        IPPoolResourceName,
		description:     "Calico IP Pools",
		k8sResourceType: reflect.TypeOf(thirdparty.IpPool{}),
		k8sListType:     reflect.TypeOf(thirdparty.IpPoolList{}),
		converter:       IPPoolConverter{},
	}
}

// IPPoolConverter implements the K8sResourceConverter interface.
type IPPoolConverter struct{}

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

func (_ IPPoolConverter) ToKVPair(r CustomK8sResource) (*model.KVPair, error) {
	t := r.(*thirdparty.IpPool)
	v := model.IPPool{}

	_, err := ResourceNameToIPNet(t.Metadata.Name)
	if err != nil {
		return nil, err
	}

	err = json.Unmarshal([]byte(t.Spec.Value), &v)
	if err != nil {
		return nil, err
	}
	return &model.KVPair{
		Key:      model.IPPoolKey{CIDR: v.CIDR},
		Value:    &v,
		Revision: t.Metadata.ResourceVersion,
	}, nil
}

func (_ IPPoolConverter) FromKVPair(kvp *model.KVPair) (CustomK8sResource, error) {
	v, err := json.Marshal(kvp.Value.(*model.IPPool))
	if err != nil {
		return nil, err
	}

	tpr := thirdparty.IpPool{
		Metadata: metav1.ObjectMeta{
			Name: IPNetToResourceName(kvp.Key.(model.IPPoolKey).CIDR),
		},
		Spec: thirdparty.IpPoolSpec{
			Value: string(v),
		},
	}
	if kvp.Revision != nil {
		tpr.Metadata.ResourceVersion = kvp.Revision.(string)
	}
	return &tpr, nil
}
