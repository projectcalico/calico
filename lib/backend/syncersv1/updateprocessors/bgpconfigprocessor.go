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
	"reflect"
	"strings"

	apiv3 "github.com/projectcalico/libcalico-go/lib/apis/v3"
	"github.com/projectcalico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/libcalico-go/lib/backend/watchersyncer"
)

// Create a new SyncerUpdateProcessor to sync BGPConfiguration data in v1 format for
// consumption by the BGP daemon.
func NewBGPConfigUpdateProcessor() watchersyncer.SyncerUpdateProcessor {
	return NewConfigUpdateProcessor(
		reflect.TypeOf(apiv3.BGPConfigurationSpec{}),
		AllowAnnotations,
		func(node, name string) model.Key { return model.NodeBGPConfigKey{Nodename: node, Name: name} },
		func(name string) model.Key { return model.GlobalBGPConfigKey{Name: name} },
		map[string]ConfigFieldValueToV1ModelValue{
			"loglevel":  logLevelToBirdLogLevel,
			"node_mesh": nodeMeshToString,
		},
	)
}

// Bird log level currently only supports granularity of none, debug and info.  Debug/Info are
// left unchanged, all others treated as none.
var logLevelToBirdLogLevel = func(value interface{}) interface{} {
	l := strings.ToLower(value.(string))
	switch l {
	case "", "debug", "info":
	default:
		l = "none"
	}
	return l
}

var nodeToNodeMeshEnabled = "{\"enabled\":true}"
var nodeToNodeMeshDisabled = "{\"enabled\":false}"

// In v1, the node mesh enabled field was wrapped up in some JSON - wrap up the value to
// return via the syncer.
var nodeMeshToString = func(value interface{}) interface{} {
	enabled := value.(bool)
	if enabled {
		return nodeToNodeMeshEnabled
	}
	return nodeToNodeMeshDisabled
}
