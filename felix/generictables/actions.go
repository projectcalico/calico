// Copyright (c) 2016-2024 Tigera, Inc. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package generictables

import "github.com/projectcalico/calico/felix/environment"

type ActionFactory interface {
	Allow() Action
	Drop() Action
	GoTo(target string) Action
	Return() Action
	SetMark(mark uint32) Action
	SetMaskedMark(mark, mask uint32) Action
	ClearMark(mark uint32) Action
	Jump(target string) Action
	NoTrack() Action
	Log(prefix string) Action
	SNAT(ip string) Action
	DNAT(ip string, port uint16) Action
	Masq(toPorts string) Action
	SetConnmark(mark, mask uint32) Action
	Reject(with RejectWith) Action
}

type RejectWith string

const RejectWithTCPReset RejectWith = "tcp-reset"

type Action interface {
	ToFragment(features *environment.Features) string
	String() string
}

// ReturnActionMarker is a marker interface for actions that return from a chain.
type ReturnActionMarker interface {
	IsReturnAction()
}
