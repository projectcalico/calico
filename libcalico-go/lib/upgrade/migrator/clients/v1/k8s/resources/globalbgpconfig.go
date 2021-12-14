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
	"fmt"
	"reflect"
	"strings"

	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/calico/libcalico-go/lib/upgrade/migrator/clients/v1/k8s/custom"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

const (
	GlobalBGPConfigResourceName = "GlobalBGPConfigs"
	GlobalBGPConfigCRDName      = "globalbgpconfigs.projectcalico.org"
)

func NewGlobalBGPConfigClient(c *kubernetes.Clientset, r *rest.RESTClient) K8sResourceClient {
	return &customK8sResourceClient{
		clientSet:       c,
		restClient:      r,
		name:            GlobalBGPConfigCRDName,
		resource:        GlobalBGPConfigResourceName,
		description:     "Calico Global BGP Configuration",
		k8sResourceType: reflect.TypeOf(custom.GlobalBGPConfig{}),
		k8sListType:     reflect.TypeOf(custom.GlobalBGPConfigList{}),
		converter:       GlobalBGPConfigConverter{},
	}
}

// GlobalBGPConfigConverter implements the K8sResourceConverter interface.
type GlobalBGPConfigConverter struct {
}

func (_ GlobalBGPConfigConverter) ListInterfaceToKey(l model.ListInterface) model.Key {
	if name := l.(model.GlobalBGPConfigListOptions).Name; name != "" {
		return model.GlobalBGPConfigKey{Name: name}
	}
	return nil
}

func (_ GlobalBGPConfigConverter) KeyToName(k model.Key) (string, error) {
	return strings.ToLower(k.(model.GlobalBGPConfigKey).Name), nil
}

func (_ GlobalBGPConfigConverter) NameToKey(name string) (model.Key, error) {
	return nil, fmt.Errorf("Mapping of Name to Key is not possible for global BGP config")
}

func (c GlobalBGPConfigConverter) ToKVPair(r CustomK8sResource) (*model.KVPair, error) {
	t := r.(*custom.GlobalBGPConfig)
	return &model.KVPair{
		Key: model.GlobalBGPConfigKey{
			Name: t.Spec.Name,
		},
		Value:    t.Spec.Value,
		Revision: t.ResourceVersion,
	}, nil
}

func (c GlobalBGPConfigConverter) FromKVPair(kvp *model.KVPair) (CustomK8sResource, error) {
	name, err := c.KeyToName(kvp.Key)
	if err != nil {
		return nil, err
	}
	crd := custom.GlobalBGPConfig{
		TypeMeta: metav1.TypeMeta{
			Kind:       "GlobalBGPConfig",
			APIVersion: "crd.projectcalico.org/v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
		},
		Spec: custom.GlobalBGPConfigSpec{
			Name:  kvp.Key.(model.GlobalBGPConfigKey).Name,
			Value: kvp.Value.(string),
		},
	}
	crd.ResourceVersion = kvp.Revision
	return &crd, nil
}
