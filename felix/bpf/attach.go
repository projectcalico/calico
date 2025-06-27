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

package bpf

import (
	"strings"

	"github.com/projectcalico/calico/felix/bpf/hook"
	"github.com/projectcalico/calico/felix/proto"
)

// AttachPointInfo describes what we need to know about an attach point
type AttachPointInfo interface {
	IfaceName() string
	HookName() hook.Hook
	Config() string
}

type AttachPoint struct {
	Hook        hook.Hook
	PolicyIdxV4 int
	PolicyIdxV6 int
	Iface       string
	LogLevel    string
	Profiling   string
	IfIndex     int
}

func (ap *AttachPoint) LogVal() string {
	return ap.LogLevel
}

func (ap *AttachPoint) IfaceName() string {
	return ap.Iface
}

func (ap *AttachPoint) HookName() hook.Hook {
	return ap.Hook
}

func (ap *AttachPoint) PolicyJmp(ipFamily proto.IPVersion) int {
	if ipFamily == proto.IPVersion_IPV6 {
		return ap.PolicyIdxV6
	}
	return ap.PolicyIdxV4
}

func (ap *AttachPoint) IfaceIndex() int {
	return ap.IfIndex
}

// EPAttachInfo tells what programs are attached to an endpoint.
type EPAttachInfo struct {
	Ingress int
	Egress  int
	XDP     int
	XDPMode string
}

// ListCalicoAttached list all programs that are attached to TC or XDP and are
// related to Calico. That is, they have jumpmap pinned in our dir hierarchy.
func ListCalicoAttached() (map[string]EPAttachInfo, error) {
	aTC, aXDP, err := ListTcXDPAttachedProgs()
	if err != nil {
		return nil, err
	}

	ai := make(map[string]EPAttachInfo)

	for _, p := range aTC {
		if strings.HasPrefix(p.Name, "cali") {
			info := ai[p.DevName]
			if p.Kind == "tcx/egress" {
				info.Egress = p.ProgID
			} else if p.Kind == "tcx/ingress" {
				info.Ingress = p.ProgID
			} else if p.Kind == "clsact/egress" {
				info.Egress = p.ID
			} else {
				info.Ingress = p.ID
			}
			ai[p.DevName] = info
		}
	}

	for _, p := range aXDP {
		if strings.HasPrefix(p.Name, "cali") {
			info := ai[p.DevName]
			info.XDP = p.ID
			info.XDPMode = p.Mode
			ai[p.DevName] = info
		}
	}

	return ai, nil
}
