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

package updateprocessors

import (
	"fmt"
	"reflect"
	"strings"

	apiv3 "github.com/projectcalico/libcalico-go/lib/apis/v3"
	"github.com/projectcalico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/libcalico-go/lib/backend/watchersyncer"
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
		parts[i] = fmt.Sprintf("%s:%d", strings.ToLower(pp.Protocol), pp.Port)
	}
	return strings.Join(parts, ",")
}
