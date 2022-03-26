// Copyright (c) 2021 Tigera, Inc. All rights reserved.
//
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

package tcdefs

const (
	MarkSeen                         = 0x01000000
	MarkSeenMask                     = MarkSeen
	MarkSeenBypass                   = MarkSeen | 0x02000000
	MarkSeenBypassMask               = MarkSeenMask | MarkSeenBypass
	MarkSeenFallThrough              = MarkSeen | 0x04000000
	MarkSeenFallThroughMask          = MarkSeenMask | MarkSeenFallThrough
	MarkSeenBypassForward            = MarkSeenBypass | 0x00300000
	MarkSeenBypassForwardSourceFixup = MarkSeenBypass | 0x00500000
	MarkSeenBypassSkipRPF            = MarkSeenBypass | 0x00400000
	MarkSeenBypassSkipRPFMask        = MarkSeenBypassMask | 0x00f00000
	MarkSeenNATOutgoing              = MarkSeenBypass | 0x00800000
	MarkSeenNATOutgoingMask          = MarkSeenBypassMask | 0x00f00000
	MarkSeenMASQ                     = MarkSeenBypass | 0x00600000
	MarkSeenMASQMask                 = MarkSeenBypassMask | 0x00f00000

	MarkLinuxConntrackEstablished     = 0x08000000
	MarkLinuxConntrackEstablishedMask = 0x08000000

	MarksMask uint32 = 0x1ff00000
)
