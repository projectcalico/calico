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

package conversionv1v3

import (
	"fmt"
	"strings"

	log "github.com/sirupsen/logrus"
	"k8s.io/apimachinery/pkg/apis/meta/v1"

	apiv3 "github.com/projectcalico/libcalico-go/lib/apis/v3"
	"github.com/projectcalico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/libcalico-go/lib/ipip"
	cnet "github.com/projectcalico/libcalico-go/lib/net"
)

func ConvertIPPool(kvp *model.KVPair) (*model.KVPair, error) {
	pool, ok := kvp.Value.(model.IPPool)
	if !ok {
		return nil, fmt.Errorf("value is not a valid BGPPeer resource key")
	}

	return &model.KVPair{
		Key: model.ResourceKey{
			Name: cidrToName(pool.CIDR),
			Kind: strings.ToLower(apiv3.KindIPPool),
		},
		Value: apiv3.IPPool{
			ObjectMeta: v1.ObjectMeta{Name: cidrToName(pool.CIDR)},
			Spec: apiv3.IPPoolSpec{
				CIDR:        pool.CIDR.String(),
				IPIPMode:    convertIPIPMode(pool.IPIPMode, pool.IPIPInterface),
				NATOutgoing: pool.Masquerade,
				Disabled:    pool.Disabled,
			},
		},
	}, nil
}

func convertIPIPMode(mode ipip.Mode, ipipInterface string) apiv3.IPIPMode {
	ipipMode := strings.ToLower(string(mode))

	if ipipInterface == "" {
		return apiv3.IPIPModeNever
	} else if ipipMode == "cross-subnet" {
		return apiv3.IPIPModeCrossSubnet
	}
	return apiv3.IPIPModeAlways
}

func cidrToName(cidr cnet.IPNet) string {
	name := strings.Replace(cidr.String(), ".", "-", 3)
	name = strings.Replace(name, ":", "-", 7)
	name = strings.Replace(name, "/", "-", 1)

	log.WithFields(log.Fields{
		"Name":  name,
		"IPNet": cidr.String(),
	}).Debug("Converted IPNet to resource name")

	return name
}
