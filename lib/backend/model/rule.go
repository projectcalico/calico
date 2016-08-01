// Copyright (c) 2016 Tigera, Inc. All rights reserved.

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

package model

import (
	. "github.com/tigera/libcalico-go/lib/net"
	. "github.com/tigera/libcalico-go/lib/numorstring"
)

type Rule struct {
	Action string `json:"action,omitempty" validate:"backendaction"`

	Protocol    *Protocol `json:"protocol,omitempty" validate:"omitempty"`
	SrcTag      string    `json:"src_tag,omitempty" validate:"omitempty,tag"`
	SrcNet      *IPNet    `json:"src_net,omitempty" validate:"omitempty"`
	SrcSelector string    `json:"src_selector,omitempty" validate:"omitempty,selector"`
	SrcPorts    []Port    `json:"src_ports,omitempty" validate:"omitempty"`
	DstTag      string    `json:"dst_tag,omitempty" validate:"omitempty,tag"`
	DstSelector string    `json:"dst_selector,omitempty" validate:"omitempty,selector"`
	DstNet      *IPNet    `json:"dst_net,omitempty" validate:"omitempty"`
	DstPorts    []Port    `json:"dst_ports,omitempty" validate:"omitempty"`
	ICMPType    *int      `json:"icmp_type,omitempty" validate:"omitempty,gte=1,lte=255"`
	ICMPCode    *int      `json:"icmp_code,omitempty" validate:"omitempty,gte=1,lte=255"`

	NotProtocol    *Protocol `json:"!protocol,omitempty" validate:"omitempty"`
	NotSrcTag      string    `json:"!src_tag,omitempty" validate:"omitempty,tag"`
	NotSrcNet      *IPNet    `json:"!src_net,omitempty" validate:"omitempty"`
	NotSrcSelector string    `json:"!src_selector,omitempty" validate:"omitempty,selector"`
	NotSrcPorts    []Port    `json:"!src_ports,omitempty" validate:"omitempty"`
	NotDstTag      string    `json:"!dst_tag,omitempty" validate:"omitempty"`
	NotDstSelector string    `json:"!dst_selector,omitempty" validate:"omitempty,selector"`
	NotDstNet      *IPNet    `json:"!dst_net,omitempty" validate:"omitempty"`
	NotDstPorts    []Port    `json:"!dst_ports,omitempty" validate:"omitempty"`
	NotICMPType    *int      `json:"!icmp_type,omitempty" validate:"omitempty,gte=1,lte=255"`
	NotICMPCode    *int      `json:"!icmp_code,omitempty" validate:"omitempty,gte=1,lte=255"`
}
