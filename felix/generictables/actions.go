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

type ActionSet interface {
	AllowAction() Action
	DropAction() Action
	GoToAction(target string) Action
	ReturnAction() Action
	SetMarkAction(mark uint32) Action
	SetMaskedMarkAction(mark, mask uint32) Action
	ClearMarkAction(mark uint32) Action
	JumpAction(target string) Action
	NoTrackAction() Action
	LogAction(prefix string) Action
	SNATAction(ip string) Action
	DNATAction(ip string, port uint16) Action
	MasqAction(toPorts string) Action
	SetConnmarkAction(mark, mask uint32) Action
}

type Action interface {
	ToFragment(features *environment.Features) string
	String() string
}
