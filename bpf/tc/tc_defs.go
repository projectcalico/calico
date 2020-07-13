// Copyright (c) 2020 Tigera, Inc. All rights reserved.
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

package tc

const (
	MarkSeen                        = 0xca100000
	MarkSeenMask                    = 0xfff00000
	MarkSeenAndFlagsMask            = 0xfffe0000
	MarkSeenBypass                  = MarkSeen | 0x10000
	MarkSeenBypassMask              = 0xffff0000
	MarkSeenBypassForward           = MarkSeen | 0x30000
	MarkSeenBypassForwadSourceFixup = MarkSeen | 0x50000
	MarkSeenBypassSkipRPF           = MarkSeen | 0x40000
	MarkSeenBypassSkipRPFMask       = 0xffff0000
	MarkSeenNATOutgoing             = MarkSeen | 0x80000
	MarkSeenNATOutgoingMask         = 0xfff80000
)
