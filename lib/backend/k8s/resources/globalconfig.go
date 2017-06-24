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
	GlobalConfigResourceName = "globalconfigs"
	GlobalConfigTPRName      = "global-config.projectcalico.org"
)

func NewGlobalConfigClient(c *kubernetes.Clientset, r *rest.RESTClient) K8sResourceClient {
	return &customK8sResourceClient{
		clientSet:       c,
		restClient:      r,
		name:            GlobalConfigTPRName,
		resource:        GlobalConfigResourceName,
		description:     "Calico Global Configuration",
		k8sResourceType: reflect.TypeOf(thirdparty.GlobalConfig{}),
		k8sListType:     reflect.TypeOf(thirdparty.GlobalConfigList{}),
		converter:       GlobalConfigConverter{},
	}
}

// GlobalConfigConverter implements the K8sResourceConverter interface.
type GlobalConfigConverter struct {
}

func (_ GlobalConfigConverter) ListInterfaceToKey(l model.ListInterface) model.Key {
	pl := l.(model.GlobalConfigListOptions)
	if pl.Name != "" {
		return model.GlobalConfigKey{Name: pl.Name}
	}
	return nil
}

func (_ GlobalConfigConverter) KeyToName(k model.Key) (string, error) {
	return strings.ToLower(k.(model.GlobalConfigKey).Name), nil
}

func (_ GlobalConfigConverter) NameToKey(name string) (model.Key, error) {
	return nil, fmt.Errorf("Mapping of Name to Key is not possible for global config")
}

func (c GlobalConfigConverter) ToKVPair(r CustomK8sResource) (*model.KVPair, error) {
	t := r.(*thirdparty.GlobalConfig)
	return &model.KVPair{
		Key: model.GlobalConfigKey{
			Name: t.Spec.Name,
		},
		Value:    t.Spec.Value,
		Revision: t.Metadata.ResourceVersion,
	}, nil
}

func (c GlobalConfigConverter) FromKVPair(kvp *model.KVPair) (CustomK8sResource, error) {
	name, err := c.KeyToName(kvp.Key)
	if err != nil {
		return nil, err
	}
	tpr := thirdparty.GlobalConfig{
		Metadata: metav1.ObjectMeta{
			Name: name,
		},
		Spec: thirdparty.GlobalConfigSpec{
			Name:  kvp.Key.(model.GlobalConfigKey).Name,
			Value: kvp.Value.(string),
		},
	}
	if kvp.Revision != nil {
		tpr.Metadata.ResourceVersion = kvp.Revision.(string)
	}
	return &tpr, nil
}
