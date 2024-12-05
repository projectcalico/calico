// Copyright (c) 2019-2021 Tigera, Inc. All rights reserved.
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

package common

import (
	"github.com/projectcalico/calico/felix/proto"
	"github.com/projectcalico/calico/felix/types"
)

type Callbacks struct {
	AddInterfaceV4           *AddInterfaceFuncs
	RemoveInterfaceV4        *RemoveInterfaceFuncs
	UpdateInterfaceV4        *UpdateInterfaceFuncs
	UpdateHostEndpointV4     *UpdateHostEndpointFuncs
	RemoveHostEndpointV4     *RemoveHostEndpointFuncs
	UpdateWorkloadEndpointV4 *UpdateWorkloadEndpointFuncs
	RemoveWorkloadEndpointV4 *RemoveWorkloadEndpointFuncs
}

func NewCallbacks() *Callbacks {
	return &Callbacks{
		AddInterfaceV4:           &AddInterfaceFuncs{},
		RemoveInterfaceV4:        &RemoveInterfaceFuncs{},
		UpdateInterfaceV4:        &UpdateInterfaceFuncs{},
		UpdateHostEndpointV4:     &UpdateHostEndpointFuncs{},
		RemoveHostEndpointV4:     &RemoveHostEndpointFuncs{},
		UpdateWorkloadEndpointV4: &UpdateWorkloadEndpointFuncs{},
		RemoveWorkloadEndpointV4: &RemoveWorkloadEndpointFuncs{},
	}
}

func (c *Callbacks) Drop(id *CbID) {
	if id.dropper != nil {
		id.dropper()
		id.dropper = nil
	}
}

type CbID struct {
	dropper func()
}

type AddInterfaceFunc func(ifaceName string, hostEPID types.HostEndpointID)

type AddInterfaceFuncs struct {
	fs AddInterfaceFunc
}

func (fs *AddInterfaceFuncs) Invoke(ifaceName string, hostEPID types.HostEndpointID) {
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

type UpdateInterfaceFunc func(ifaceName string, newHostEPID types.HostEndpointID)

type UpdateInterfaceFuncs struct {
	fs UpdateInterfaceFunc
}

func (fs *UpdateInterfaceFuncs) Invoke(ifaceName string, newHostEPID types.HostEndpointID) {
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

type UpdateHostEndpointFunc func(hostEPID types.HostEndpointID)

type UpdateHostEndpointFuncs struct {
	fs UpdateHostEndpointFunc
}

func (fs *UpdateHostEndpointFuncs) Invoke(hostEPID types.HostEndpointID) {
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

type RemoveHostEndpointFunc func(hostEPID types.HostEndpointID)

type RemoveHostEndpointFuncs struct {
	fs RemoveHostEndpointFunc
}

func (fs *RemoveHostEndpointFuncs) Invoke(hostEPID types.HostEndpointID) {
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

type UpdateWorkloadEndpointFunc func(old, new *proto.WorkloadEndpoint)

type UpdateWorkloadEndpointFuncs struct {
	fs UpdateWorkloadEndpointFunc
}

func (fs *UpdateWorkloadEndpointFuncs) Invoke(old, new *proto.WorkloadEndpoint) {
	if fs.fs != nil {
		fs.fs(old, new)
	}
}

func (fs *UpdateWorkloadEndpointFuncs) Append(f UpdateWorkloadEndpointFunc) *CbID {
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

type RemoveWorkloadEndpointFunc func(old *proto.WorkloadEndpoint)

type RemoveWorkloadEndpointFuncs struct {
	fs RemoveWorkloadEndpointFunc
}

func (fs *RemoveWorkloadEndpointFuncs) Invoke(old *proto.WorkloadEndpoint) {
	if fs.fs != nil {
		fs.fs(old)
	}
}

func (fs *RemoveWorkloadEndpointFuncs) Append(f RemoveWorkloadEndpointFunc) *CbID {
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
