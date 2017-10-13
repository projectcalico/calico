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
	"github.com/projectcalico/libcalico-go/lib/apiv2"
	"github.com/projectcalico/libcalico-go/lib/backend/watchersyncer"
	"github.com/projectcalico/libcalico-go/lib/converter/modelv2v1"
)

// Create a new SyncerUpdateProcessor to sync IPPool data in v1 format for
// consumption by both Felix and the BGP daemon.
func NewBGPPeerUpdateProcessor() watchersyncer.SyncerUpdateProcessor {
	ipc := modelv2v1.BGPPeerConverter{}
	return NewConflictResolvingCacheUpdateProcessor(apiv2.KindBGPPeer, ipc.ConvertV2ToV1)
}
