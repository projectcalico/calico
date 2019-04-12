// Copyright (c) 2019 Tigera, Inc. All rights reserved.
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

package intdataplane

import (
	"github.com/projectcalico/felix/proto"

	"github.com/projectcalico/libcalico-go/lib/set"
)

type callbacks struct {
	UpdatePolicyV4       *UpdatePolicyDataFuncs
	RemovePolicyV4       *RemovePolicyDataFuncs
	AddMembersIPSetV4    *AddMembersIPSetFuncs
	RemoveMembersIPSetV4 *RemoveMembersIPSetFuncs
	ReplaceIPSetV4       *ReplaceIPSetFuncs
	RemoveIPSetV4        *RemoveIPSetFuncs
	AddInterfaceV4       *AddInterfaceFuncs
	RemoveInterfaceV4    *RemoveInterfaceFuncs
	UpdateInterfaceV4    *UpdateInterfaceFuncs
	UpdateHostEndpointV4 *UpdateHostEndpointFuncs
	RemoveHostEndpointV4 *RemoveHostEndpointFuncs
}

func newCallbacks() *callbacks {
	return &callbacks{
		UpdatePolicyV4:       &UpdatePolicyDataFuncs{},
		RemovePolicyV4:       &RemovePolicyDataFuncs{},
		AddMembersIPSetV4:    &AddMembersIPSetFuncs{},
		RemoveMembersIPSetV4: &RemoveMembersIPSetFuncs{},
		ReplaceIPSetV4:       &ReplaceIPSetFuncs{},
		RemoveIPSetV4:        &RemoveIPSetFuncs{},
		AddInterfaceV4:       &AddInterfaceFuncs{},
		RemoveInterfaceV4:    &RemoveInterfaceFuncs{},
		UpdateInterfaceV4:    &UpdateInterfaceFuncs{},
		UpdateHostEndpointV4: &UpdateHostEndpointFuncs{},
		RemoveHostEndpointV4: &RemoveHostEndpointFuncs{},
	}
}

func (c *callbacks) Drop(id *CbID) {
	if id.dropper != nil {
		id.dropper()
		id.dropper = nil
	}
}

type CbID struct {
	dropper func()
}

type UpdatePolicyDataFunc func(policyID proto.PolicyID, policy *proto.Policy)

type UpdatePolicyDataFuncs struct {
	fs UpdatePolicyDataFunc
}

func (fs *UpdatePolicyDataFuncs) Invoke(policyID proto.PolicyID, policy *proto.Policy) {
	if fs.fs != nil {
		fs.fs(policyID, policy)
	}
}

func (fs *UpdatePolicyDataFuncs) Append(f UpdatePolicyDataFunc) *CbID {
	if f == nil {
		return &CbID{
			dropper: func() {},
		}
	}
	fs.fs = f
	return &CbID{
		dropper: func() {
			fs.fs = nil
		},
	}
}

type RemovePolicyDataFunc func(policyID proto.PolicyID)

type RemovePolicyDataFuncs struct {
	fs RemovePolicyDataFunc
}

func (fs *RemovePolicyDataFuncs) Invoke(policyID proto.PolicyID) {
	if fs.fs != nil {
		fs.fs(policyID)
	}
}

func (fs *RemovePolicyDataFuncs) Append(f RemovePolicyDataFunc) *CbID {
	if f == nil {
		return &CbID{
			dropper: func() {},
		}
	}
	fs.fs = f
	return &CbID{
		dropper: func() {
			fs.fs = nil
		},
	}
}

type AddMembersIPSetFunc func(setID string, members set.Set)

type AddMembersIPSetFuncs struct {
	fs AddMembersIPSetFunc
}

func (fs *AddMembersIPSetFuncs) Invoke(setID string, members set.Set) {
	if fs.fs != nil {
		fs.fs(setID, members)
	}
}

func (fs *AddMembersIPSetFuncs) Append(f AddMembersIPSetFunc) *CbID {
	if f == nil {
		return &CbID{
			dropper: func() {},
		}
	}
	fs.fs = f
	return &CbID{
		dropper: func() {
			fs.fs = nil
		},
	}
}

type RemoveMembersIPSetFunc func(setID string, members set.Set)

type RemoveMembersIPSetFuncs struct {
	fs RemoveMembersIPSetFunc
}

func (fs *RemoveMembersIPSetFuncs) Invoke(setID string, members set.Set) {
	if fs.fs != nil {
		fs.fs(setID, members)
	}
}

func (fs *RemoveMembersIPSetFuncs) Append(f RemoveMembersIPSetFunc) *CbID {
	if f == nil {
		return &CbID{
			dropper: func() {},
		}
	}
	fs.fs = f
	return &CbID{
		dropper: func() {
			fs.fs = nil
		},
	}
}

type ReplaceIPSetFunc func(setID string, members set.Set)

type ReplaceIPSetFuncs struct {
	fs ReplaceIPSetFunc
}

func (fs *ReplaceIPSetFuncs) Invoke(setID string, members set.Set) {
	if fs.fs != nil {
		fs.fs(setID, members)
	}
}

func (fs *ReplaceIPSetFuncs) Append(f ReplaceIPSetFunc) *CbID {
	if f == nil {
		return &CbID{
			dropper: func() {},
		}
	}
	fs.fs = f
	return &CbID{
		dropper: func() {
			fs.fs = nil
		},
	}
}

type RemoveIPSetFunc func(setID string)

type RemoveIPSetFuncs struct {
	fs RemoveIPSetFunc
}

func (fs *RemoveIPSetFuncs) Invoke(setID string) {
	if fs.fs != nil {
		fs.fs(setID)
	}
}

func (fs *RemoveIPSetFuncs) Append(f RemoveIPSetFunc) *CbID {
	if f == nil {
		return &CbID{
			dropper: func() {},
		}
	}
	fs.fs = f
	return &CbID{
		dropper: func() {
			fs.fs = nil
		},
	}
}

type AddInterfaceFunc func(ifaceName string, hostEPID proto.HostEndpointID)

type AddInterfaceFuncs struct {
	fs AddInterfaceFunc
}

func (fs *AddInterfaceFuncs) Invoke(ifaceName string, hostEPID proto.HostEndpointID) {
	if fs.fs != nil {
		fs.fs(ifaceName, hostEPID)
	}
}

func (fs *AddInterfaceFuncs) Append(f AddInterfaceFunc) *CbID {
	if f == nil {
		return &CbID{
			dropper: func() {},
		}
	}
	fs.fs = f
	return &CbID{
		dropper: func() {
			fs.fs = nil
		},
	}
}

type RemoveInterfaceFunc func(ifaceName string)

type RemoveInterfaceFuncs struct {
	fs RemoveInterfaceFunc
}

func (fs *RemoveInterfaceFuncs) Invoke(ifaceName string) {
	if fs.fs != nil {
		fs.fs(ifaceName)
	}
}

func (fs *RemoveInterfaceFuncs) Append(f RemoveInterfaceFunc) *CbID {
	if f == nil {
		return &CbID{
			dropper: func() {},
		}
	}
	fs.fs = f
	return &CbID{
		dropper: func() {
			fs.fs = nil
		},
	}
}

type UpdateInterfaceFunc func(ifaceName string, newHostEPID proto.HostEndpointID)

type UpdateInterfaceFuncs struct {
	fs UpdateInterfaceFunc
}

func (fs *UpdateInterfaceFuncs) Invoke(ifaceName string, newHostEPID proto.HostEndpointID) {
	if fs.fs != nil {
		fs.fs(ifaceName, newHostEPID)
	}
}

func (fs *UpdateInterfaceFuncs) Append(f UpdateInterfaceFunc) *CbID {
	if f == nil {
		return &CbID{
			dropper: func() {},
		}
	}
	fs.fs = f
	return &CbID{
		dropper: func() {
			fs.fs = nil
		},
	}
}

type UpdateHostEndpointFunc func(hostEPID proto.HostEndpointID)

type UpdateHostEndpointFuncs struct {
	fs UpdateHostEndpointFunc
}

func (fs *UpdateHostEndpointFuncs) Invoke(hostEPID proto.HostEndpointID) {
	if fs.fs != nil {
		fs.fs(hostEPID)
	}
}

func (fs *UpdateHostEndpointFuncs) Append(f UpdateHostEndpointFunc) *CbID {
	if f == nil {
		return &CbID{
			dropper: func() {},
		}
	}
	fs.fs = f
	return &CbID{
		dropper: func() {
			fs.fs = nil
		},
	}
}

type RemoveHostEndpointFunc func(hostEPID proto.HostEndpointID)

type RemoveHostEndpointFuncs struct {
	fs RemoveHostEndpointFunc
}

func (fs *RemoveHostEndpointFuncs) Invoke(hostEPID proto.HostEndpointID) {
	if fs.fs != nil {
		fs.fs(hostEPID)
	}
}

func (fs *RemoveHostEndpointFuncs) Append(f RemoveHostEndpointFunc) *CbID {
	if f == nil {
		return &CbID{
			dropper: func() {},
		}
	}
	fs.fs = f
	return &CbID{
		dropper: func() {
			fs.fs = nil
		},
	}
}
