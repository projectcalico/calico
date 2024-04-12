// Copyright (c) 2021-2022 Tigera, Inc. All rights reserved.
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

package libbpf

type TcGlobalData struct {
	IfaceName      string
	HostIPv4       [16]byte
	IntfIPv4       [16]byte
	ExtToSvcMark   uint32
	Tmtu           uint16
	VxlanPort      uint16
	PSNatStart     uint16
	PSNatLen       uint16
	HostTunnelIPv4 [16]byte
	Flags          uint32
	WgPort         uint16
	Wg6Port        uint16
	NatIn          uint32
	NatOut         uint32
	LogFilterJmp   uint32
	Jumps          [40]uint32

	HostIPv6       [16]byte
	IntfIPv6       [16]byte
	HostTunnelIPv6 [16]byte
	JumpsV6        [40]uint32
}

type XDPGlobalData struct {
	IfaceName string
	Jumps     [16]uint32
	JumpsV6   [16]uint32
}
