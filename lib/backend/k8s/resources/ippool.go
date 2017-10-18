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

	apiv2 "github.com/projectcalico/libcalico-go/lib/apis/v2"
	"github.com/projectcalico/libcalico-go/lib/backend/model"

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
		k8sResourceType: reflect.TypeOf(apiv2.IPPool{}),
		k8sListType:     reflect.TypeOf(apiv2.IPPoolList{}),
		converter:       IPPoolConverter{},
	}
}

// IPPoolConverter implements the K8sResourceConverter interface.
type IPPoolConverter struct {
}

func (_ IPPoolConverter) ListInterfaceToKey(l model.ListInterface) model.Key {
	il := l.(model.ResourceListOptions)
	if il.Name != "" {
		return model.ResourceKey{Name: il.Name, Kind: il.Kind}
	}
	return nil
}

func (_ IPPoolConverter) KeyToName(k model.Key) (string, error) {
	return k.(model.ResourceKey).Name, nil
}

func (_ IPPoolConverter) NameToKey(name string) (model.Key, error) {
	return model.ResourceKey{
		Name: name,
		Kind: apiv2.KindIPPool,
	}, nil
}

func (i IPPoolConverter) ToKVPair(r CustomK8sResource) (*model.KVPair, error) {
	t := r.(*apiv2.IPPool)

	// Clear any CRD TypeMeta fields and then create a KVPair.
	res := apiv2.NewIPPool()
	res.ObjectMeta.Name = t.ObjectMeta.Name
	res.ObjectMeta.Namespace = t.ObjectMeta.Namespace
	res.Spec = t.Spec
	return &model.KVPair{
		Key: model.ResourceKey{
			Name:      t.ObjectMeta.Name,
			Namespace: t.ObjectMeta.Namespace,
			Kind:      apiv2.KindIPPool,
		},
		Value:    res,
		Revision: t.ObjectMeta.ResourceVersion,
	}, nil

}

func (i IPPoolConverter) FromKVPair(kvp *model.KVPair) (CustomK8sResource, error) {
	v := kvp.Value.(*apiv2.IPPool)

	return &apiv2.IPPool{
		ObjectMeta: metav1.ObjectMeta{
			Name:            v.ObjectMeta.Name,
			Namespace:       v.ObjectMeta.Namespace,
			ResourceVersion: kvp.Revision,
		},
		Spec: v.Spec,
	}, nil
}
