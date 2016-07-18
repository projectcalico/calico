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

package client

import (
	"net"

	"github.com/tigera/libcalico-go/lib/client/ipam"
)

// IPAMInterface has methods to perform IP address management.
type IPAMInterface interface {
	AssignIP(args ipam.AssignIPArgs) error
	AutoAssign(args ipam.AutoAssignArgs) ([]net.IP, []net.IP, error)
	ReleaseIPs(ips []net.IP) ([]net.IP, error)
	GetAssignmentAttributes(addr net.IP) (map[string]string, error)
	IPsByHandle(handleID string) ([]net.IP, error)
	ReleaseByHandle(handleID string) error
	ClaimAffinity(cidr net.IPNet, host *string) error
	ReleaseAffinity(cidr net.IPNet, host *string) error
	ReleaseHostAffinities(host *string) error
	ReleasePoolAffinities(pool net.IPNet) error
	GetIPAMConfig() (*ipam.IPAMConfig, error)
	SetIPAMConfig(cfg ipam.IPAMConfig) error
	RemoveIPAMHost(host *string) error
}

// ipamApi implements the IPAMInterface.
type ipamApi struct {
	c *ipam.IPAMClient
}

// NewIPAM returns a new ipamApi.
func NewIPAM(c *Client) *ipamApi {
	// CD4 TODO:
	// ic, _ := ipam.NewIPAMClient(c.backend.EtcdKeysAPI)
	return &ipamApi{nil}
}

func (i ipamApi) AssignIP(args ipam.AssignIPArgs) error {
	return i.c.AssignIP(args)
}

func (i ipamApi) AutoAssign(args ipam.AutoAssignArgs) ([]net.IP, []net.IP, error) {
	return i.c.AutoAssign(args)
}

func (i ipamApi) ReleaseIPs(ips []net.IP) ([]net.IP, error) {
	return i.c.ReleaseIPs(ips)
}

func (i ipamApi) GetAssignmentAttributes(addr net.IP) (map[string]string, error) {
	return i.c.GetAssignmentAttributes(addr)
}

func (i ipamApi) IPsByHandle(handleID string) ([]net.IP, error) {
	return i.c.IPsByHandle(handleID)
}

func (i ipamApi) ReleaseByHandle(handleID string) error {
	return i.c.ReleaseByHandle(handleID)
}

func (i ipamApi) ClaimAffinity(cidr net.IPNet, host *string) error {
	return i.c.ClaimAffinity(cidr, host)
}

func (i ipamApi) ReleaseAffinity(cidr net.IPNet, host *string) error {
	return i.c.ReleaseAffinity(cidr, host)
}

func (i ipamApi) ReleaseHostAffinities(host *string) error {
	return i.c.ReleaseHostAffinities(host)
}

func (i ipamApi) ReleasePoolAffinities(pool net.IPNet) error {
	return i.c.ReleasePoolAffinities(pool)
}

func (i ipamApi) GetIPAMConfig() (*ipam.IPAMConfig, error) {
	return i.c.GetIPAMConfig()
}

func (i ipamApi) SetIPAMConfig(cfg ipam.IPAMConfig) error {
	return i.c.SetIPAMConfig(cfg)
}

func (i ipamApi) RemoveIPAMHost(host *string) error {
	return i.c.RemoveIPAMHost(host)
}
