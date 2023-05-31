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
	IfaceName    string
	HostIP       uint32
	IntfIP       uint32
	ExtToSvcMark uint32
	Tmtu         uint16
	VxlanPort    uint16
	PSNatStart   uint16
	PSNatLen     uint16
	HostTunnelIP uint32
	Flags        uint32
	WgPort       uint16
	NatIn        uint32
	NatOut       uint32
	LogFilterJmp uint32
	Jumps        [32]uint32
}

type TcGlobalData6 struct {
	IfaceName    string
	HostIP       [16]byte
	IntfIP       [16]byte
	ExtToSvcMark uint32
	Tmtu         uint16
	VxlanPort    uint16
	PSNatStart   uint16
	PSNatLen     uint16
	HostTunnelIP [16]byte
	Flags        uint32
	WgPort       uint16
	NatIn        uint32
	NatOut       uint32
	LogFilterJmp uint32
	Jumps        [32]uint32
}

type XDPGlobalData struct {
	IfaceName string
	Jumps     [32]uint32
}
