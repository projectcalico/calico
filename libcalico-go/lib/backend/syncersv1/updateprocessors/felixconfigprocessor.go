// Copyright (c) 2017,2020 Tigera, Inc. All rights reserved.

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
	"fmt"
	"reflect"
	"strings"

	log "github.com/sirupsen/logrus"

	apiv3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"

	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/watchersyncer"
	cnet "github.com/projectcalico/calico/libcalico-go/lib/net"
)

// Create a new SyncerUpdateProcessor to sync FelixConfiguration data in v1 format for
// consumption by Felix.
func NewFelixConfigUpdateProcessor() watchersyncer.SyncerUpdateProcessor {
	return NewConfigUpdateProcessor(
		reflect.TypeOf(apiv3.FelixConfigurationSpec{}),
		AllowAnnotations,
		func(node, name string) model.Key { return model.HostConfigKey{Hostname: node, Name: name} },
		func(name string) model.Key { return model.GlobalConfigKey{Name: name} },
		map[string]ConfigFieldValueToV1ModelValue{
			"FailsafeInboundHostPorts":  protoPortSliceToString,
			"FailsafeOutboundHostPorts": protoPortSliceToString,
			"RouteTableRange":           routeTableRangeToString,
			"RouteTableRanges":          routeTableRangeListToString,
		},
	)
}

// Convert a slice of ProtoPorts to the string representation required by Felix.
var protoPortSliceToString = func(value interface{}) interface{} {
	pps := value.([]apiv3.ProtoPort)
	if len(pps) == 0 {
		return "none"
	}
	parts := make([]string, len(pps))
	for i, pp := range pps {
		if pp.Net != "" {
			ip, _, err := cnet.ParseCIDROrIP(pp.Net)
			if err != nil {
				log.WithError(err).Error("Unable to parse CIDR to sync FelixConfiguration data in v1 format")
			}
			if ip.Version() == 6 {
				parts[i] = fmt.Sprintf("%s:[%s]:%d", strings.ToLower(pp.Protocol), pp.Net, pp.Port)
			} else {
				parts[i] = fmt.Sprintf("%s:%s:%d", strings.ToLower(pp.Protocol), pp.Net, pp.Port)
			}
		} else {
			parts[i] = fmt.Sprintf("%s:%d", strings.ToLower(pp.Protocol), pp.Port)
		}
	}
	return strings.Join(parts, ",")
}

// Converts multiple route table ranges to its string config representation.
// e.g. RouteTableRanges{{Min: 0, Max: 250}, {Min: 255, Max: 3000}} => "0-250,255-3000"
var routeTableRangeListToString = func(value interface{}) interface{} {
	ranges := value.(apiv3.RouteTableRanges)
	rangesStr := make([]string, 0)
	for _, r := range ranges {
		rangesStr = append(rangesStr, fmt.Sprintf("%d-%d", r.Min, r.Max))
	}
	return strings.Join(rangesStr, ",")
}

// Converts a route table range to its string config representation.
// e.g. RouteTableRange{Min: 0, Max: 250} => "0-250"
var routeTableRangeToString = func(value interface{}) interface{} {
	r := value.(apiv3.RouteTableRange)
	return fmt.Sprintf("%d-%d", r.Min, r.Max)
}
