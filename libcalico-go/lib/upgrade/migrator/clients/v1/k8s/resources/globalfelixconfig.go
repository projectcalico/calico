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
	GlobalFelixConfigResourceName = "GlobalFelixConfigs"
	GlobalFelixConfigCRDName      = "globalconfigs.crd.projectcalico.org"
)

func NewGlobalFelixConfigClient(c *kubernetes.Clientset, r *rest.RESTClient) K8sResourceClient {
	return &customK8sResourceClient{
		clientSet:       c,
		restClient:      r,
		name:            GlobalFelixConfigCRDName,
		resource:        GlobalFelixConfigResourceName,
		description:     "Calico Global Felix Configuration",
		k8sResourceType: reflect.TypeOf(custom.GlobalFelixConfig{}),
		k8sListType:     reflect.TypeOf(custom.GlobalFelixConfigList{}),
		converter:       GlobalFelixConfigConverter{},
	}
}

// GlobalFelixConfigConverter implements the K8sResourceConverter interface.
type GlobalFelixConfigConverter struct {
}

func (_ GlobalFelixConfigConverter) ListInterfaceToKey(l model.ListInterface) model.Key {
	pl := l.(model.GlobalConfigListOptions)
	if pl.Name != "" {
		return model.GlobalConfigKey{Name: pl.Name}
	}
	return nil
}

func (_ GlobalFelixConfigConverter) KeyToName(k model.Key) (string, error) {
	return strings.ToLower(k.(model.GlobalConfigKey).Name), nil
}

func (_ GlobalFelixConfigConverter) NameToKey(name string) (model.Key, error) {
	return nil, fmt.Errorf("Mapping of Name to Key is not possible for global felix config")
}

func (c GlobalFelixConfigConverter) ToKVPair(r CustomK8sResource) (*model.KVPair, error) {
	t := r.(*custom.GlobalFelixConfig)
	return &model.KVPair{
		Key: model.GlobalConfigKey{
			Name: t.Spec.Name,
		},
		Value:    t.Spec.Value,
		Revision: t.ResourceVersion,
	}, nil
}

func (c GlobalFelixConfigConverter) FromKVPair(kvp *model.KVPair) (CustomK8sResource, error) {
	name, err := c.KeyToName(kvp.Key)
	if err != nil {
		return nil, err
	}
	crd := custom.GlobalFelixConfig{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
		},
		Spec: custom.GlobalFelixConfigSpec{
			Name:  kvp.Key.(model.GlobalConfigKey).Name,
			Value: kvp.Value.(string),
		},
	}
	crd.ResourceVersion = kvp.Revision
	return &crd, nil
}
