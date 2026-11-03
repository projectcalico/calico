// Copyright (c) 2026 Tigera, Inc. All rights reserved.
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

package utils

import (
	"time"

	"github.com/projectcalico/calico/libcalico-go/lib/ipam"
)

// AllocationTimestampLayout is the layout of an allocation's timestamp attribute. It matches
// time.Time's String output for a UTC time, which older releases and other IPAM clients write, so
// their stamps parse too.
const AllocationTimestampLayout = "2006-01-02 15:04:05.999999999 -0700 MST"

// ClaimedAfter reports whether an allocation was stamped later than t. Every claim, including a
// transfer, restamps the address. A missing or unparsable stamp counts as earlier, so the
// check never protects an allocation it can't date: callers go ahead and transfer or release it.
func ClaimedAfter(attrs map[string]string, t time.Time) bool {
	claimed, err := time.Parse(AllocationTimestampLayout, attrs[ipam.AttributeTimestamp])
	return err == nil && claimed.After(t)
}
