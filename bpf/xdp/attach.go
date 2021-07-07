// Copyright (c) 2020-2021 Tigera, Inc. All rights reserved.
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

package xdp

type AttachPoint struct {
	Iface string
}

func (ap *AttachPoint) IfaceName() string {
	return ap.Iface
}

func (ap *AttachPoint) JumpMapFDMapKey() string {
	return "xdp"
}

func (ap *AttachPoint) IsAttached() (bool, error) {
	return false, nil
}

func (ap *AttachPoint) AttachProgram() error {
	return nil
}

func (ap *AttachPoint) ProgramID() (string, error) {
	return "", nil
}
