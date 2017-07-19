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

	"github.com/projectcalico/libcalico-go/lib/backend/k8s/thirdparty"
	"github.com/projectcalico/libcalico-go/lib/backend/model"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

const (
	GlobalBgpConfigResourceName = "GlobalBgpConfigs"
	GlobalBgpConfigTPRName      = "global-bgp-config.projectcalico.org"
)

func NewGlobalBGPConfigClient(c *kubernetes.Clientset, r *rest.RESTClient) K8sResourceClient {
	return &customK8sResourceClient{
		clientSet:       c,
		restClient:      r,
		name:            GlobalBgpConfigTPRName,
		resource:        GlobalBgpConfigResourceName,
		description:     "Calico Global BGP Configuration",
		k8sResourceType: reflect.TypeOf(thirdparty.GlobalBgpConfig{}),
		k8sListType:     reflect.TypeOf(thirdparty.GlobalBgpConfigList{}),
		converter:       GlobalBgpConfigConverter{},
	}
}

// GlobalBgpConfigConverter implements the K8sResourceConverter interface.
type GlobalBgpConfigConverter struct {
}

func (_ GlobalBgpConfigConverter) ListInterfaceToKey(l model.ListInterface) model.Key {
	if name := l.(model.GlobalBGPConfigListOptions).Name; name != "" {
		return model.GlobalBGPConfigKey{Name: name}
	}
	return nil
}

func (_ GlobalBgpConfigConverter) KeyToName(k model.Key) (string, error) {
	return strings.ToLower(k.(model.GlobalBGPConfigKey).Name), nil
}

func (_ GlobalBgpConfigConverter) NameToKey(name string) (model.Key, error) {
	return nil, fmt.Errorf("Mapping of Name to Key is not possible for global BGP config")
}

func (c GlobalBgpConfigConverter) ToKVPair(r CustomK8sResource) (*model.KVPair, error) {
	t := r.(*thirdparty.GlobalBgpConfig)
	return &model.KVPair{
		Key: model.GlobalBGPConfigKey{
			Name: t.Spec.Name,
		},
		Value:    t.Spec.Value,
		Revision: t.Metadata.ResourceVersion,
	}, nil
}

func (c GlobalBgpConfigConverter) FromKVPair(kvp *model.KVPair) (CustomK8sResource, error) {
	name, err := c.KeyToName(kvp.Key)
	if err != nil {
		return nil, err
	}
	tpr := thirdparty.GlobalBgpConfig{
		Metadata: metav1.ObjectMeta{
			Name: name,
		},
		Spec: thirdparty.GlobalBgpConfigSpec{
			Name:  kvp.Key.(model.GlobalBGPConfigKey).Name,
			Value: kvp.Value.(string),
		},
	}
	if kvp.Revision != nil {
		tpr.Metadata.ResourceVersion = kvp.Revision.(string)
	}
	return &tpr, nil
}
