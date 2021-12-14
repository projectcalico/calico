// Copyright (c) 2019 Tigera, Inc. All rights reserved.

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

package updateprocessors

import (
	"errors"

	log "github.com/sirupsen/logrus"

	apiv3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"

	"github.com/projectcalico/calico/libcalico-go/lib/backend/k8s/conversion"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/watchersyncer"
	cnet "github.com/projectcalico/calico/libcalico-go/lib/net"
)

// Create a new SyncerUpdateProcessor to sync NetworkSet data in v1 format for consumption by Felix.
func NewNetworkSetUpdateProcessor() watchersyncer.SyncerUpdateProcessor {
	return NewSimpleUpdateProcessor(apiv3.KindNetworkSet, convertNetworkSetV2ToV1Key, convertNetworkSetV2ToV1Value)
}

func convertNetworkSetV2ToV1Key(v3key model.ResourceKey) (model.Key, error) {
	if v3key.Name == "" || v3key.Namespace == "" {
		return model.NetworkSetKey{}, errors.New("Missing Name or Namespace field to create a v1 NetworkSet Key")
	}
	return model.NetworkSetKey{
		Name: v3key.Namespace + "/" + v3key.Name,
	}, nil
}

func convertNetworkSetV2ToV1Value(val interface{}) (interface{}, error) {
	v3res, ok := val.(*apiv3.NetworkSet)
	if !ok {
		return nil, errors.New("Value is not a valid NetworkSet resource value")
	}

	var addrs []cnet.IPNet
	for _, cidrString := range v3res.Spec.Nets {
		_, ipNet, err := cnet.ParseCIDROrIP(cidrString)
		if err != nil {
			log.WithError(err).WithFields(log.Fields{
				"CIDR":       cidrString,
				"networkSet": v3res.GetName(),
			}).Warn("Invalid CIDR")
		}
		addrs = append(addrs, *ipNet)
	}

	// Add in the Calico namespace label for storage purposes.
	labelsWithCalicoNamespace := make(map[string]string, len(v3res.GetLabels())+1)
	for k, v := range v3res.GetLabels() {
		labelsWithCalicoNamespace[k] = v
	}
	labelsWithCalicoNamespace[apiv3.LabelNamespace] = v3res.Namespace

	// Also include the namespace profile in the profile IDs so that we get namespace label inheritance.
	// This is a wonky compared to Pods where the profile is included in the pod->WEP conversion and is therefore
	// conceptually limited to k8s, but then namespaces are themselves a k8s only concept.
	v1value := &model.NetworkSet{
		Nets:   addrs,
		Labels: labelsWithCalicoNamespace,
		ProfileIDs: []string{
			conversion.NamespaceProfileNamePrefix + v3res.Namespace,
		},
	}

	return v1value, nil
}
