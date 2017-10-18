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
	BGPConfigResourceName = "BGPConfigurations"
	BGPConfigCRDName      = "bgpconfigurations.crd.projectcalico.org"
)

func NewBGPConfigClient(c *kubernetes.Clientset, r *rest.RESTClient) K8sResourceClient {
	return &customK8sResourceClient{
		clientSet:       c,
		restClient:      r,
		name:            BGPConfigCRDName,
		resource:        BGPConfigResourceName,
		description:     "Calico BGP Configuration",
		k8sResourceType: reflect.TypeOf(apiv2.BGPConfiguration{}),
		k8sListType:     reflect.TypeOf(apiv2.BGPConfigurationList{}),
		converter:       BGPConfigConverter{},
	}
}

// BGPConfigConverter implements the K8sResourceConverter interface.
type BGPConfigConverter struct {
}

func (_ BGPConfigConverter) ListInterfaceToKey(l model.ListInterface) model.Key {
	pl := l.(model.ResourceListOptions)
	if pl.Name != "" {
		return model.ResourceKey{Name: pl.Name, Kind: pl.Kind}
	}
	return nil
}

func (_ BGPConfigConverter) KeyToName(k model.Key) (string, error) {
	return k.(model.ResourceKey).Name, nil
}

func (_ BGPConfigConverter) NameToKey(name string) (model.Key, error) {
	return model.ResourceKey{
		Name: name,
		Kind: apiv2.KindBGPConfiguration,
	}, nil
}

func (c BGPConfigConverter) ToKVPair(r CustomK8sResource) (*model.KVPair, error) {
	t := r.(*apiv2.BGPConfiguration)

	// Clear any CRD TypeMeta fields and then create a KVPair.
	conf := apiv2.NewBGPConfiguration()
	conf.ObjectMeta.Name = t.ObjectMeta.Name
	conf.ObjectMeta.Namespace = t.ObjectMeta.Namespace
	conf.Spec = t.Spec
	return &model.KVPair{
		Key: model.ResourceKey{
			Name:      t.ObjectMeta.Name,
			Namespace: t.ObjectMeta.Namespace,
			Kind:      apiv2.KindBGPConfiguration,
		},
		Value:    conf,
		Revision: t.ObjectMeta.ResourceVersion,
	}, nil
}

func (c BGPConfigConverter) FromKVPair(kvp *model.KVPair) (CustomK8sResource, error) {
	v := kvp.Value.(*apiv2.BGPConfiguration)

	crd := apiv2.BGPConfiguration{
		ObjectMeta: metav1.ObjectMeta{
			Name:            v.ObjectMeta.Name,
			Namespace:       v.ObjectMeta.Namespace,
			ResourceVersion: kvp.Revision,
		},
		Spec: v.Spec,
	}
	return &crd, nil
}
