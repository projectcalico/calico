// Copyright (c) 2021 Tigera, Inc. All rights reserved.
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
package node

import (
	"context"
	"fmt"
	"strings"
	"sync"

	apiv3 "github.com/projectcalico/calico/libcalico-go/lib/apis/v3"
	bapi "github.com/projectcalico/calico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/calico/libcalico-go/lib/clientv3"
	cerrors "github.com/projectcalico/calico/libcalico-go/lib/errors"
	"github.com/projectcalico/calico/libcalico-go/lib/ipam"
	cnet "github.com/projectcalico/calico/libcalico-go/lib/net"
	"github.com/projectcalico/calico/libcalico-go/lib/options"
	"github.com/projectcalico/calico/libcalico-go/lib/watch"
)

func NewFakeCalicoClient() *FakeCalicoClient {
	nc := fakeNodeClient{
		nodes: make(map[string]*apiv3.Node),
	}
	ipamClient := fakeIPAMClient{
		affinitiesReleased: make(map[string]bool),
		handlesReleased:    make(map[string]bool),
	}
	return &FakeCalicoClient{
		nodeClient: &nc,
		ipamClient: &ipamClient,
	}
}

// FakeCalicoClient is a fake client for use in the IPAM tests.
type FakeCalicoClient struct {
	nodeClient clientv3.NodeInterface
	ipamClient ipam.Interface
}

func (f *FakeCalicoClient) Backend() bapi.Client {
	return nil
}

// Nodes returns an interface for managing node resources.
func (f *FakeCalicoClient) Nodes() clientv3.NodeInterface {
	return f.nodeClient
}

// GlobalNetworkPolicies returns an interface for managing global network policy resources.
func (f *FakeCalicoClient) GlobalNetworkPolicies() clientv3.GlobalNetworkPolicyInterface {
	panic("not implemented")
}

// NetworkPolicies returns an interface for managing namespaced network policy resources.
func (f *FakeCalicoClient) NetworkPolicies() clientv3.NetworkPolicyInterface {
	panic("not implemented")
}

// IPPools returns an interface for managing IP pool resources.
func (f *FakeCalicoClient) IPPools() clientv3.IPPoolInterface {
	panic("not implemented")
}

// Profiles returns an interface for managing profile resources.
func (f *FakeCalicoClient) Profiles() clientv3.ProfileInterface {
	panic("not implemented")
}

// GlobalNetworkSets returns an interface for managing global network sets resources.
func (f *FakeCalicoClient) GlobalNetworkSets() clientv3.GlobalNetworkSetInterface {
	panic("not implemented")
}

// NetworkSets returns an interface for managing network sets resources.
func (f *FakeCalicoClient) NetworkSets() clientv3.NetworkSetInterface {
	panic("not implemented")
}

// HostEndpoints returns an interface for managing host endpoint resources.
func (f *FakeCalicoClient) HostEndpoints() clientv3.HostEndpointInterface {
	panic("not implemented")
}

// WorkloadEndpoints returns an interface for managing workload endpoint resources.
func (f *FakeCalicoClient) WorkloadEndpoints() clientv3.WorkloadEndpointInterface {
	panic("not implemented")
}

// BGPPeers returns an interface for managing BGP peer resources.
func (f *FakeCalicoClient) BGPPeers() clientv3.BGPPeerInterface {
	panic("not implemented")
}

// IPAM returns an interface for managing IP address assignment and releasing.
func (f *FakeCalicoClient) IPAM() ipam.Interface {
	return f.ipamClient
}

// BGPConfigurations returns an interface for managing the BGP configuration resources.
func (f *FakeCalicoClient) BGPConfigurations() clientv3.BGPConfigurationInterface {
	panic("not implemented")
}

// FelixConfigurations returns an interface for managing the Felix configuration resources.
func (f *FakeCalicoClient) FelixConfigurations() clientv3.FelixConfigurationInterface {
	panic("not implemented")
}

// ClusterInformation returns an interface for managing the cluster information resource.
func (f *FakeCalicoClient) ClusterInformation() clientv3.ClusterInformationInterface {
	panic("not implemented")
}

// KubeControllersConfiguration returns an interface for managing the
// KubeControllersConfiguration resource.
func (f *FakeCalicoClient) KubeControllersConfiguration() clientv3.KubeControllersConfigurationInterface {
	panic("not implemented")
}

func (f *FakeCalicoClient) CalicoNodeStatus() clientv3.CalicoNodeStatusInterface {
	panic("not implemented")
}

func (f *FakeCalicoClient) IPReservations() clientv3.IPReservationInterface {
	panic("not implemented")
}

// EnsureInitialized is used to ensure the backend datastore is correctly
// initialized for use by Calico.  This method may be called multiple times, and
// will have no effect if the datastore is already correctly initialized.
// Most Calico deployment scenarios will automatically implicitly invoke this
// method and so a general consumer of this API can assume that the datastore
// is already initialized.
func (f *FakeCalicoClient) EnsureInitialized(ctx context.Context, calicoVersion string, clusterType string) error {
	panic("not implemented")
}

// fakeNodeClient implements the clientv3 NodeInterface for testing purposes.
type fakeNodeClient struct {
	sync.Mutex
	nodes map[string]*apiv3.Node
}

func (f *fakeNodeClient) Create(ctx context.Context, res *apiv3.Node, opts options.SetOptions) (*apiv3.Node, error) {
	f.Lock()
	defer f.Unlock()

	if _, ok := f.nodes[res.Name]; ok {
		return nil, cerrors.ErrorResourceAlreadyExists{Identifier: res.Name}
	}
	f.nodes[res.Name] = res
	return res, nil
}

func (f *fakeNodeClient) Update(ctx context.Context, res *apiv3.Node, opts options.SetOptions) (*apiv3.Node, error) {
	panic("not implemented") // TODO: Implement
}

func (f *fakeNodeClient) Delete(ctx context.Context, name string, opts options.DeleteOptions) (*apiv3.Node, error) {
	panic("not implemented") // TODO: Implement
}

func (f *fakeNodeClient) Get(ctx context.Context, name string, opts options.GetOptions) (*apiv3.Node, error) {
	f.Lock()
	defer f.Unlock()

	if _, ok := f.nodes[name]; !ok {
		return nil, cerrors.ErrorResourceDoesNotExist{Identifier: name}
	}
	return f.nodes[name], nil
}

func (f *fakeNodeClient) List(ctx context.Context, opts options.ListOptions) (*apiv3.NodeList, error) {
	panic("not implemented") // TODO: Implement
}

func (f *fakeNodeClient) Watch(ctx context.Context, opts options.ListOptions) (watch.Interface, error) {
	panic("not implemented") // TODO: Implement
}

// fakeIPAMClient implements ipam.Interface for testing purposes.
type fakeIPAMClient struct {
	sync.Mutex
	affinitiesReleased map[string]bool
	handlesReleased    map[string]bool
}

func (f *fakeIPAMClient) affinityReleased(aff string) bool {
	f.Lock()
	defer f.Unlock()
	if v, ok := f.affinitiesReleased[aff]; ok {
		return v
	}
	return false
}

// AssignIP assigns the provided IP address to the provided host.  The IP address
// must fall within a configured pool.  AssignIP will claim block affinity as needed
// in order to satisfy the assignment.  An error will be returned if the IP address
// is already assigned, or if StrictAffinity is enabled and the address is within
// a block that does not have affinity for the given host.
func (f *fakeIPAMClient) AssignIP(ctx context.Context, args ipam.AssignIPArgs) error {
	panic("not implemented") // TODO: Implement
}

// AutoAssign automatically assigns one or more IP addresses as specified by the
// provided AutoAssignArgs.  AutoAssign returns the list of the assigned IPv4 addresses,
// and the list of the assigned IPv6 addresses in IPNet format.
// The returned IPNet represents the allocation block from which the IP was allocated,
// which is useful for dataplanes that need to know the subnet (such as Windows).
//
// In case of error, returns the IPs allocated so far along with the error.
func (f *fakeIPAMClient) AutoAssign(ctx context.Context, args ipam.AutoAssignArgs) (*ipam.IPAMAssignments, *ipam.IPAMAssignments, error) {
	panic("not implemented") // TODO: Implement
}

// ReleaseIPs releases any of the given IP addresses that are currently assigned,
// so that they are available to be used in another assignment.
func (f *fakeIPAMClient) ReleaseIPs(ctx context.Context, opts ...ipam.ReleaseOptions) ([]cnet.IP, error) {
	f.Lock()
	defer f.Unlock()

	for _, opt := range opts {
		f.handlesReleased[opt.Handle] = true
	}
	return nil, nil
}

// GetAssignmentAttributes returns the attributes stored with the given IP address
// upon assignment, as well as the handle used for assignment (if any).
func (f *fakeIPAMClient) GetAssignmentAttributes(ctx context.Context, addr cnet.IP) (map[string]string, *string, error) {
	panic("not implemented") // TODO: Implement
}

// IPsByHandle returns a list of all IP addresses that have been
// assigned using the provided handle.
func (f *fakeIPAMClient) IPsByHandle(ctx context.Context, handleID string) ([]cnet.IP, error) {
	panic("not implemented") // TODO: Implement
}

// ReleaseByHandle releases all IP addresses that have been assigned
// using the provided handle.  Returns an error if no addresses
// are assigned with the given handle.
func (f *fakeIPAMClient) ReleaseByHandle(ctx context.Context, handleID string) error {
	f.Lock()
	defer f.Unlock()

	f.handlesReleased[handleID] = true
	return nil
}

// ClaimAffinity claims affinity to the given host for all blocks
// within the given CIDR.  The given CIDR must fall within a configured
// pool. If an empty string is passed as the host, then the value returned by os.Hostname is used.
func (f *fakeIPAMClient) ClaimAffinity(ctx context.Context, cidr cnet.IPNet, host string) ([]cnet.IPNet, []cnet.IPNet, error) {
	panic("not implemented") // TODO: Implement
}

// ReleaseAffinity releases affinity for all blocks within the given CIDR
// on the given host.  If an empty string is passed as the host, then the
// value returned by os.Hostname will be used. If mustBeEmpty is true, then an error
// will be returned if any blocks within the CIDR are not empty - in this case, this
// function may release some but not all blocks within the given CIDR.
func (f *fakeIPAMClient) ReleaseAffinity(ctx context.Context, cidr cnet.IPNet, host string, mustBeEmpty bool) error {
	f.Lock()
	defer f.Unlock()

	f.affinitiesReleased[fmt.Sprintf("%s/%s", cidr.String(), host)] = true
	return nil
}

// ReleaseBlockAffinity releases the affinity of the exact block provided.
func (f *fakeIPAMClient) ReleaseBlockAffinity(ctx context.Context, block *model.AllocationBlock, mustBeEmpty bool) error {
	f.Lock()
	defer f.Unlock()

	cidr := block.CIDR.String()
	host := strings.TrimPrefix(*block.Affinity, "host:")
	key := fmt.Sprintf("%s/%s", cidr, host)
	f.affinitiesReleased[key] = true
	return nil
}

// ReleaseHostAffinities releases affinity for all blocks that are affine
// to the given host.  If an empty string is passed as the host, the value returned by
// os.Hostname will be used. If mustBeEmpty is true, then an error
// will be returned if any blocks within the CIDR are not empty - in this case, this
// function may release some but not all blocks attached to this host.
func (f *fakeIPAMClient) ReleaseHostAffinities(ctx context.Context, host string, mustBeEmpty bool) error {
	f.Lock()
	defer f.Unlock()

	f.affinitiesReleased[host] = true
	return nil
}

// ReleasePoolAffinities releases affinity for all blocks within
// the specified pool across all hosts.
func (f *fakeIPAMClient) ReleasePoolAffinities(ctx context.Context, pool cnet.IPNet) error {
	panic("not implemented") // TODO: Implement
}

// GetIPAMConfig returns the global IPAM configuration.  If no IPAM configuration
// has been set, returns a default configuration with StrictAffinity disabled
// and AutoAllocateBlocks enabled.
func (f *fakeIPAMClient) GetIPAMConfig(ctx context.Context) (*ipam.IPAMConfig, error) {
	panic("not implemented") // TODO: Implement
}

// SetIPAMConfig sets global IPAM configuration.  This can only
// be done when there are no allocated blocks and IP addresses.
func (f *fakeIPAMClient) SetIPAMConfig(ctx context.Context, cfg ipam.IPAMConfig) error {
	panic("not implemented") // TODO: Implement
}

// RemoveIPAMHost releases affinity for all blocks on the given host,
// and removes all host-specific IPAM data from the datastore.
// RemoveIPAMHost does not release any IP addresses claimed on the given host.
// If an empty string is passed as the host then the value returned by os.Hostname is used.
func (f *fakeIPAMClient) RemoveIPAMHost(ctx context.Context, host string) error {
	panic("not implemented") // TODO: Implement
}

// GetUtilization returns IP utilization info for the specified pools, or for all pools.
func (f *fakeIPAMClient) GetUtilization(ctx context.Context, args ipam.GetUtilizationArgs) ([]*ipam.PoolUtilization, error) {
	panic("not implemented") // TODO: Implement
}

// EnsureBlock returns single IPv4/IPv6 IPAM block for a host as specified by the provided BlockArgs.
// If there is no block allocated already for this host, allocate one and return its' CIDR.
// Otherwise, return the CIDR of the IPAM block allocated for this host.
// It returns IPv4, IPv6 block CIDR and any error encountered.
func (f *fakeIPAMClient) EnsureBlock(ctx context.Context, args ipam.BlockArgs) (*cnet.IPNet, *cnet.IPNet, error) {
	panic("not implemented") // TODO: Implement
}
