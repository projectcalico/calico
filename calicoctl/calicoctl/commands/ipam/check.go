// Copyright (c) 2016-2026 Tigera, Inc. All rights reserved.

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

package ipam

import (
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"net"
	"os"
	"slices"
	"sort"
	"strings"
	"time"

	apiv3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/rest"
	kubevirtv1 "kubevirt.io/api/core/v1"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/projectcalico/calico/kube-controllers/pkg/controllers/loadbalancer"
	bapi "github.com/projectcalico/calico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/calico/libcalico-go/lib/clientv3"
	"github.com/projectcalico/calico/libcalico-go/lib/ipam/accounting"
	"github.com/projectcalico/calico/libcalico-go/lib/ipam/vmipam"
	cnet "github.com/projectcalico/calico/libcalico-go/lib/net"
	"github.com/projectcalico/calico/libcalico-go/lib/options"
	"github.com/projectcalico/calico/libcalico-go/lib/set"
)

// NewKubeClient reads the Kubernetes types that check cross-references with IPAM.
func NewKubeClient(cfg *rest.Config) (ctrlclient.Client, error) {
	scheme, err := newScheme()
	if err != nil {
		return nil, err
	}
	return ctrlclient.New(cfg, ctrlclient.Options{Scheme: scheme})
}

func newScheme() (*runtime.Scheme, error) {
	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		return nil, err
	}
	if err := kubevirtv1.AddToScheme(scheme); err != nil {
		return nil, err
	}
	return scheme, nil
}

func NewIPAMChecker(
	k8sClient ctrlclient.Client,
	v3Client clientv3.Interface,
	backendClient bapi.Client,
	showAllIPs bool,
	showProblemIPs bool,
	outFile string,
	version string,
) *IPAMChecker {
	return &IPAMChecker{
		allocations: map[string][]*Allocation{},
		tracker:     accounting.NewTracker(),

		k8sClient:     k8sClient,
		v3Client:      v3Client,
		backendClient: backendClient,

		showAllIPs:     showAllIPs,
		showProblemIPs: showProblemIPs,

		version: version,
		outFile: outFile,
	}
}

type IPAMChecker struct {
	// The report: every allocation by address, and the handles no allocation names.
	allocations   map[string][]*Allocation
	leakedHandles []HandleInfo

	// tracker holds the blocks, pools, nodes and live references, and decides what is leaked.
	tracker *accounting.Tracker

	clusterType         string
	clusterInfoRevision string
	datastoreLocked     bool
	clusterGUID         string

	k8sClient     ctrlclient.Client
	backendClient bapi.Client
	v3Client      clientv3.Interface

	showAllIPs     bool
	showProblemIPs bool

	version string
	outFile string
}

func (c *IPAMChecker) CheckIPAM(ctx context.Context) error {
	fmt.Println("Checking IPAM for inconsistencies...")
	fmt.Println()

	// First, query ClusterInformation and extract some important metadata to use in the report.
	clusterInfo, err := c.v3Client.ClusterInformation().Get(ctx, "default", options.GetOptions{})
	if err != nil {
		return err
	}
	c.clusterType = clusterInfo.Spec.ClusterType
	c.clusterInfoRevision = clusterInfo.ResourceVersion
	c.datastoreLocked = clusterInfo.Spec.DatastoreReady != nil && !*clusterInfo.Spec.DatastoreReady
	c.clusterGUID = clusterInfo.Spec.ClusterGUID

	var numAllocs int
	var blocks *model.KVPairList
	{
		fmt.Println("Loading all IPAM blocks...")
		var err error
		blocks, err = c.backendClient.List(ctx, model.BlockListOptions{}, "")
		if err != nil {
			return fmt.Errorf("failed to list IPAM blocks: %w", err)
		}
		fmt.Printf("Found %d IPAM blocks.\n", len(blocks.KVPairs))

		for _, kvp := range blocks.KVPairs {
			b := kvp.Value.(*model.AllocationBlock)
			affinity := "<none>"
			if b.Affinity != nil {
				affinity = *b.Affinity
			}
			fmt.Printf(" IPAM block %s affinity=%s:\n", b.CIDR, affinity)
			for ord, attrIdx := range b.Allocations {
				if attrIdx == nil {
					continue // IP is not allocated
				}
				numAllocs++
				c.recordAllocation(b, ord)
			}
			c.tracker.AddBlocks(b)
		}
		fmt.Printf("IPAM blocks record %d allocations.\n", numAllocs)
		fmt.Println()
	}
	var activeIPPools []*cnet.IPNet
	var poolNames []string
	{
		fmt.Println("Loading all IPAM pools...")
		ipPools, err := c.v3Client.IPPools().List(ctx, options.ListOptions{})
		if err != nil {
			return fmt.Errorf("failed to load IP pools: %w", err)
		}
		for i, p := range ipPools.Items {
			// Disabled pools still own their blocks.
			c.tracker.AddPools(&ipPools.Items[i])
			poolNames = append(poolNames, p.Name)
			if p.Spec.Disabled {
				continue
			}
			fmt.Printf("  %s\n", p.Spec.CIDR)
			_, cidr, err := cnet.ParseCIDR(p.Spec.CIDR)
			if err != nil {
				return fmt.Errorf("failed to parse IP pool CIDR: %w", err)
			}
			activeIPPools = append(activeIPPools, cidr)
		}
		fmt.Printf("Found %d active IP pools.\n", len(activeIPPools))
		fmt.Println()
	}

	{
		fmt.Println("Loading all nodes.")
		nodes, err := c.v3Client.Nodes().List(ctx, options.ListOptions{})
		if err != nil {
			return fmt.Errorf("failed to list nodes: %w", err)
		}
		numNodeIPs := 0

		// An empty list still tells the tracker which nodes exist.
		c.tracker.AddNodes()
		for _, n := range nodes.Items {
			c.tracker.AddNodes(n.Name)
			addressRefs, err := accounting.NodeAddressRefs(&n)
			if err != nil {
				return err
			}
			c.recordRefs(addressRefs...)
			numNodeIPs += len(addressRefs)
		}
		fmt.Printf("Found %d node tunnel IPs.\n", numNodeIPs)
		fmt.Println()
	}

	{
		fmt.Println("Loading all service load balancer IPs.")
		var services corev1.ServiceList
		if err := c.k8sClient.List(ctx, &services); err != nil {
			return fmt.Errorf("failed to list services: %w", err)
		}

		kubeControllerConfig, err := c.v3Client.KubeControllersConfiguration().Get(ctx, "default", options.GetOptions{})
		if err != nil {
			return err
		}

		lbConfig := kubeControllerConfig.Spec.Controllers.LoadBalancer
		if lbConfig == nil {
			// Without the controller's config there is no telling which services Calico manages, so count them all.
			fmt.Println("No configuration for LoadBalancer kubecontroller found, counting every LoadBalancer service")
		}
		var numLoadBalancers int
		for _, svc := range services.Items {
			if svc.Spec.Type != corev1.ServiceTypeLoadBalancer {
				continue
			}
			if lbConfig != nil && !loadbalancer.IsCalicoManagedLoadBalancer(&svc, lbConfig.AssignIPs) {
				continue
			}
			numLoadBalancers++
			addressRefs, err := accounting.ServiceAddressRefs(&svc)
			if err != nil {
				return err
			}
			c.recordRefs(addressRefs...)
		}
		fmt.Printf("Found %d service load balancer(s).\n", numLoadBalancers)
		fmt.Println()
	}

	{
		fmt.Println("Loading all KubeVirt VMs.")
		vms, err := c.liveVMs(ctx)
		if err != nil {
			return err
		}
		if vms == nil {
			fmt.Println("KubeVirt is not installed, skipping VM check.")
		} else {
			fmt.Printf("Found %d VM IPs.\n", c.recordVMRefs(vms))
		}
		fmt.Println()
	}

	{
		fmt.Println("Loading all workload endpoints.")
		weps, err := c.v3Client.WorkloadEndpoints().List(ctx, options.ListOptions{})
		if err != nil {
			return fmt.Errorf("failed to list workload endpoints: %w", err)
		}
		numWEPIPs := 0
		for _, w := range weps.Items {
			addressRefs, err := accounting.WorkloadEndpointAddressRefs(&w)
			if err != nil {
				return err
			}
			c.recordRefs(addressRefs...)
			numWEPIPs += len(addressRefs)
		}
		fmt.Printf("Found %d workload IPs.\n", numWEPIPs)
		fmt.Printf("Workloads and nodes are using %d IPs.\n", len(c.refsByIP()))
		fmt.Println()
	}

	handles := map[string]HandleInfo{}
	{
		fmt.Println("Loading all handles")
		handleList, err := c.backendClient.List(ctx, model.IPAMHandleListOptions{}, "")
		if err != nil {
			return fmt.Errorf("failed to list handles: %w", err)
		}
		for _, kv := range handleList.KVPairs {
			handleKey := kv.Key.(model.IPAMHandleKey)
			handles[handleKey.HandleID] = HandleInfo{
				ID:       handleKey.HandleID,
				UID:      kv.UID,
				Revision: kv.Revision,
			}
		}
	}

	{
		const numNodesToPrint = 20
		fmt.Printf("Looking for top (up to %d) nodes by allocations...\n", numNodesToPrint)
		numAllocationsByNode := map[string]int{}
		for _, allocs := range c.allocations {
			for _, a := range allocs {
				numAllocationsByNode[a.Node]++
			}
		}
		allNodes := slices.Collect(maps.Keys(numAllocationsByNode))
		sort.Slice(allNodes, func(i, j int) bool {
			// Reverse order
			return numAllocationsByNode[allNodes[i]] > numAllocationsByNode[allNodes[j]]
		})
		for i, n := range allNodes {
			if i >= numNodesToPrint {
				break
			}
			fmt.Printf("  %s has %d allocations\n", n, numAllocationsByNode[n])
		}
		if len(allNodes) > 0 {
			most := numAllocationsByNode[allNodes[0]]
			median := numAllocationsByNode[allNodes[len(allNodes)/2]]
			fmt.Printf("Node with most allocations has %d; median is %d\n", most, median)
		}
		fmt.Println()
	}

	numProblems := 0
	{
		fmt.Printf("Scanning for IPs with unknown types...\n")
		numUnknowns := 0
		for _, allocs := range c.allocations {
			for _, a := range allocs {
				if !a.tracked() || a.accountingAlloc.Kind() != accounting.KindUnknown || len(c.tracker.Refs(a.accountingAlloc.IP)) > 0 {
					continue
				}

				// A type we don't know about and nothing holds. Have to assume it's in use.
				if c.showProblemIPs {
					fmt.Printf("  %s allocation has unknown type (%s) Assuming IP is still in use.\n", a.IP, a.Type)
				}
				numUnknowns++
			}
		}
		if numUnknowns > 0 {
			fmt.Printf("Warning: found %d IPs with unknown allocation types. Perhaps a new version of this tool is needed?\n", numUnknowns)
			numProblems += numUnknowns
		} else {
			fmt.Print("Found 0 IPs with unknown allocation types.\n")
		}
	}

	var allocatedButNotInUseIPs []string
	{
		fmt.Printf("Scanning for IPs that are allocated but not actually in use...\n")
		leaked := c.leakedIPs(poolNames)
		for _, ip := range slices.Sorted(maps.Keys(c.allocations)) {
			allocs := c.allocations[ip]
			c.markInUse(ip, allocs, leaked)
			c.recordOwners(allocs)

			// Leaked means none of the address's allocations is in use or cooling down.
			if slices.ContainsFunc(allocs, func(a *Allocation) bool { return a.InUse || a.CoolingDown }) {
				continue
			}
			if c.showProblemIPs {
				for _, alloc := range allocs {
					fmt.Printf("  %s leaked; attrs %v\n", ip, alloc.GetAttrString())
				}
			}
			allocatedButNotInUseIPs = append(allocatedButNotInUseIPs, ip)
		}
		numProblems += len(allocatedButNotInUseIPs)
		fmt.Printf("Found %d IPs that are allocated in IPAM but not actually in use.\n", len(allocatedButNotInUseIPs))
	}

	var inUseButNotAllocatedIPs []string
	var nonCalicoIPs []string
	{
		fmt.Printf("Scanning for IPs that are in use by a workload or node but not allocated in IPAM...\n")
		for ip, addressRefs := range c.refsByIP() {
			if c.showProblemIPs && len(addressRefs) > 1 {
				fmt.Printf("  %s has multiple owners.\n", ip)
			}
			if _, ok := c.allocations[ip]; !ok {
				// The IP is being used, but is not allocated within Calico IPAM!

				// Found indicates whether the IP falls within an active IP pool.
				found := false
				parsedIP := net.ParseIP(ip)
				for _, cidr := range activeIPPools {
					if cidr.Contains(parsedIP) {
						found = true
						break
					}
				}
				if !found {
					if c.showProblemIPs {
						for _, r := range addressRefs {
							fmt.Printf("  %s in use by %v is not in any active IP pool.\n", ip, r.Referrer)
						}
					}
					nonCalicoIPs = append(nonCalicoIPs, ip)
					continue
				}
				if c.showProblemIPs {
					for _, r := range addressRefs {
						fmt.Printf("  %s in use by %v and in active IPAM pool but has no IPAM allocation.\n", ip, r.Referrer)
					}
				}
				inUseButNotAllocatedIPs = append(inUseButNotAllocatedIPs, ip)
			}
		}
		numProblems += len(nonCalicoIPs)
		numProblems += len(inUseButNotAllocatedIPs)
		fmt.Printf("Found %d in-use IPs that are not in active IP pools.\n", len(nonCalicoIPs))
		fmt.Printf("Found %d in-use IPs that are in active IP pools but have no corresponding IPAM allocation.\n",
			len(inUseButNotAllocatedIPs))
		fmt.Println()
	}

	inUseHandles := set.New[string]()
	for _, allocs := range c.allocations {
		for _, a := range allocs {
			if a.Handle != "" {
				inUseHandles.Add(a.Handle)
			}
		}
	}
	{
		fmt.Printf("Scanning for IPAM handles with no matching IPs...\n")
		goodHandles := 0
		var leakedHandles []HandleInfo
		for handleID, handleInfo := range handles {
			if inUseHandles.Contains(handleID) {
				goodHandles++
				continue
			}
			if c.showAllIPs {
				fmt.Printf("  %s doesn't have any active IPs.\n", handleID)
			}
			numProblems++
			leakedHandles = append(leakedHandles, handleInfo)
		}
		fmt.Printf("Found %d handles with no matching IPs (and %d handles with matches).\n",
			len(leakedHandles), goodHandles)
		c.leakedHandles = leakedHandles
	}

	var missingHandles []string
	{
		fmt.Printf("Scanning for IPs with missing handle...\n")
		for handleID := range inUseHandles.All() {
			if _, ok := handles[handleID]; ok {
				continue
			}
			if c.showProblemIPs {
				fmt.Printf("  %s is in use in a block but doesn't exist.\n", handleID)
			}
			missingHandles = append(missingHandles, handleID)
		}
		fmt.Printf("Found %d handles mentioned in blocks with no matching handle resource.\n", len(missingHandles))
	}

	var invalidBlocks []string
	{
		fmt.Printf("Validating IPAMBlock structures...\n")
		for _, kvp := range blocks.KVPairs {
			b := kvp.Value.(*model.AllocationBlock)
			if err := validateBlock(b); err != nil {
				fmt.Printf("  IPAMBlock %s is invalid: %s\n", kvp.Key, err)
				numProblems++
				invalidBlocks = append(invalidBlocks, kvp.Key.String())
			}
		}
		fmt.Printf("Found %d invalid IPAMBlocks.\n", len(invalidBlocks))
	}

	fmt.Printf("Check complete; found %d problems.\n", numProblems)

	if c.outFile != "" {
		// Print out a machine readable report.
		c.printReport()
	}
	return nil
}

func validateBlock(b *model.AllocationBlock) error {
	// Check that all non-nil Allocations point to valid attributes.
	seenAttribs := set.New[int]()
	seenOrdinals := set.New[int]()
	var o int
	for o = 0; o < b.NumAddresses(); o++ {
		if b.Allocations[o] == nil {
			continue
		}
		attrIdx := *b.Allocations[o]
		if attrIdx < 0 || attrIdx >= len(b.Attributes) {
			return fmt.Errorf("allocation %d indexes a nonexistent attribute %d", o, attrIdx)
		}
		seenAttribs.Add(attrIdx)
		seenOrdinals.Add(o)
	}

	// Check that all attributes are pointed to
	for i := range b.Attributes {
		if !seenAttribs.Contains(i) {
			return fmt.Errorf("attribute index %d exists but is not indexed by an allocation", i)
		}
		releasedAt := b.Attributes[i].ReleasedAt
		if releasedAt != nil && releasedAt.After(time.Now()) {
			return fmt.Errorf("attribute index %d has releasedAt in the future, suggesting clock skew", i)
		}
	}

	// Check that all unallocated ordinals are unique and not seen.
	for i, o := range b.Unallocated {
		if o < 0 || o >= len(b.Allocations) {
			return fmt.Errorf("ordinal %d appears in the Unallocated array but is out of the block", o)
		}
		if slices.Contains(b.Unallocated[:i], o) {
			return fmt.Errorf("ordinal %d appears more than once in Unallocated array", o)
		}
		if seenOrdinals.Contains(o) {
			return fmt.Errorf("ordinal %d is allocated but appears in Unallocated", o)
		}
	}

	if len(b.Unallocated)+seenOrdinals.Len() != b.NumAddresses() {
		return fmt.Errorf("expected %d addresses in this block, but Unallocated (%d) + Allocated (%d) = %d",
			b.NumAddresses(), len(b.Unallocated), seenOrdinals.Len(), len(b.Unallocated)+seenOrdinals.Len())
	}

	return nil
}

type CheckReport struct {
	// Version of the code that produced the report.
	Version string `json:"version"`

	// Important metadata.
	ClusterGUID         string `json:"clusterGUID"`
	DatastoreLocked     bool   `json:"datastoreLocked"`
	ClusterInfoRevision string `json:"clusterInformationRevision"`
	ClusterType         string `json:"clusterType"`

	// Allocations is a map of IP address to list of allocation data.
	Allocations   map[string][]*Allocation `json:"allocations"`
	LeakedHandles []HandleInfo             `json:"leakedHandles,omitempty"`
}

func (c *IPAMChecker) printReport() {
	r := CheckReport{
		Version:             c.version,
		ClusterGUID:         c.clusterGUID,
		ClusterType:         c.clusterType,
		ClusterInfoRevision: c.clusterInfoRevision,
		DatastoreLocked:     c.datastoreLocked,
		Allocations:         c.allocations,
		LeakedHandles:       c.leakedHandles,
	}
	bytes, _ := json.MarshalIndent(r, "", "  ")
	_ = os.WriteFile(c.outFile, bytes, 0o777)
}

// recordAllocation takes a block and ordinal within that block and adds the
// allocation to the report.
func (c *IPAMChecker) recordAllocation(b *model.AllocationBlock, ord int) {
	ip := b.OrdinalToIP(ord)
	alloc := Allocation{
		IP:              ip.String(),
		accountingAlloc: accounting.Allocation{IP: ip.IP, Ordinal: ord, Block: b},
	}
	alloc.Node, _ = accounting.NodeAffinity(b)

	// A deleted block still names its allocations' owners, so read the attributes whether or not the tracker saw it.
	if attrIdx := *b.Allocations[ord]; attrIdx >= 0 && attrIdx < len(b.Attributes) {
		acct := &alloc.accountingAlloc
		acct.Attr = &b.Attributes[attrIdx]

		// The Windows reserved handle has no handle resource behind it.
		if !acct.IsWindowsHandle() {
			alloc.Handle = acct.Handle()
		}

		// We do not have the IPAMConfig here to tell whether a cooling address could be deallocated yet.
		alloc.CoolingDown = acct.IsCooling()
		alloc.Node = acct.Node()
		alloc.Borrowed = acct.IsBorrowed()
		alloc.Pod = acct.Attr.ActiveOwnerAttrs[model.IPAMBlockAttributePod]
		alloc.Namespace = acct.Attr.ActiveOwnerAttrs[model.IPAMBlockAttributeNamespace]
		alloc.Type = acct.Attr.ActiveOwnerAttrs[model.IPAMBlockAttributeType]
		alloc.CreationTimestamp = acct.Attr.ActiveOwnerAttrs[model.IPAMBlockAttributeTimestamp]
	}

	// Fill in the sequence number for the allocation.
	s := b.GetSequenceNumberForOrdinal(ord)
	alloc.SequenceNumber = &s

	c.allocations[alloc.IP] = append(c.allocations[alloc.IP], &alloc)
	if c.showAllIPs {
		fmt.Printf("  %s allocated; attrs %s\n", alloc.IP, alloc.GetAttrString())
	}
}

// leakedIPs is every unreferenced address, in any pool or none. Check has no grace period, so each one is a leak.
func (c *IPAMChecker) leakedIPs(poolNames []string) set.Set[string] {
	leaked := set.New[string]()
	for _, name := range poolNames {
		for _, a := range c.tracker.Unreferenced(name) {
			leaked.Add(a.IP.String())
		}
	}
	for _, a := range c.tracker.NoPoolUnreferenced() {
		leaked.Add(a.IP.String())
	}
	return leaked
}

// markInUse marks each of ip's allocations in use or not. The tracker judges the ones it saw, and whether anything
// references the address decides the rest.
func (c *IPAMChecker) markInUse(ip string, allocs []*Allocation, leaked set.Set[string]) {
	referenced := len(c.tracker.Refs(net.ParseIP(ip))) > 0
	for _, a := range allocs {
		if a.tracked() {
			a.InUse = !a.CoolingDown && !leaked.Contains(ip)
		} else {
			a.InUse = !a.CoolingDown && referenced
		}
	}
}

// recordOwners fills in each allocation's report owners: whatever references the address, or the rule that keeps an unreferenced one in use.
func (c *IPAMChecker) recordOwners(allocs []*Allocation) {
	for _, a := range allocs {
		for _, r := range c.tracker.Refs(net.ParseIP(a.IP)) {
			a.Owners = append(a.Owners, r.Referrer.String())
		}
		if !a.tracked() || !a.InUse {
			continue
		}
		switch a.accountingAlloc.Kind() {
		case accounting.KindWindowsReserved:
			a.Owners = append(a.Owners, "Reserved for Windows")
		case accounting.KindUnknown:
			a.Owners = append(a.Owners, fmt.Sprintf("UnknownType(%s)", a.Type))
		}
	}
}

// refsByIP groups the tracker's references by address.
func (c *IPAMChecker) refsByIP() map[string][]accounting.AddressRef {
	out := map[string][]accounting.AddressRef{}
	for _, r := range c.tracker.AllRefs() {
		ip := r.IP.String()
		out[ip] = append(out[ip], r)
	}
	return out
}

// liveVMs names every VirtualMachine and VMI, or is nil when KubeVirt is not installed. A VMI owned by a VM shares
// its name, so the set holds each VM once.
func (c *IPAMChecker) liveVMs(ctx context.Context) (set.Set[types.NamespacedName], error) {
	out := set.New[types.NamespacedName]()
	var vms kubevirtv1.VirtualMachineList
	if err := c.k8sClient.List(ctx, &vms); meta.IsNoMatchError(err) || runtime.IsNotRegisteredError(err) {
		return nil, nil
	} else if err != nil {
		return nil, fmt.Errorf("failed to list VirtualMachines: %w", err)
	}
	for _, vm := range vms.Items {
		out.Add(types.NamespacedName{Namespace: vm.Namespace, Name: vm.Name})
	}
	var vmis kubevirtv1.VirtualMachineInstanceList
	if err := c.k8sClient.List(ctx, &vmis); err != nil {
		return nil, fmt.Errorf("failed to list VirtualMachineInstances: %w", err)
	}
	for _, vmi := range vmis.Items {
		out.Add(types.NamespacedName{Namespace: vmi.Namespace, Name: vmi.Name})
	}
	return out, nil
}

// recordVMRefs references each allocation on a live VM's handle. A stopped VM keeps its address with no owner
// attributes, so the handle is all that ties the address to the VM.
func (c *IPAMChecker) recordVMRefs(vms set.Set[types.NamespacedName]) int {
	networks := set.New[string]()
	for _, allocs := range c.allocations {
		for _, a := range allocs {
			// A network name may itself contain the infix, so every prefix before one is a candidate.
			for i := 0; ; i++ {
				j := strings.Index(a.Handle[i:], vmipam.VMHandleInfix)
				if j < 0 {
					break
				}
				i += j
				networks.Add(a.Handle[:i])
			}
		}
	}

	// Rebuilding each live VM's handle, rather than parsing handles, also matches the hashed form of a long name.
	vmByHandle := map[string]types.NamespacedName{}
	for network := range networks.All() {
		for vm := range vms.All() {
			vmByHandle[vmipam.CreateVMHandleID(network, vm.Namespace, vm.Name)] = vm
		}
	}

	numVMIPs := 0
	for ip, allocs := range c.allocations {
		for _, a := range allocs {
			if vm, ok := vmByHandle[a.Handle]; ok {
				c.recordRefs(accounting.AddressRef{
					IP:       net.ParseIP(ip),
					Kind:     apiv3.IPPoolAllowedUseWorkload,
					Referrer: accounting.Referrer{Kind: accounting.ReferrerVirtualMachine, Namespace: vm.Namespace, Name: vm.Name},
				})
				numVMIPs++
			}
		}
	}
	return numVMIPs
}

// recordRefs tells the tracker about live references.
func (c *IPAMChecker) recordRefs(refs ...accounting.AddressRef) {
	if c.showAllIPs {
		for _, r := range refs {
			fmt.Printf("  %s belongs to %s\n", r.IP, r.Referrer)
		}
	}
	c.tracker.AddRefs(refs...)
}

// Allocation represents an IP that is allocated in Calico IPAM, augmented with data
// from cross referencing with WorkloadEndpoints, etc.
type Allocation struct {
	// The actual address.
	IP string `json:"ip"`

	// accountingAlloc is the block and ordinal behind the address. Its Attr is nil when the allocation indexes an
	// attribute that does not exist.
	accountingAlloc accounting.Allocation

	Handle         string  `json:"handle,omitempty"`
	SequenceNumber *uint64 `json:"sequenceNumber,omitempty"`

	// Metadata for the Allocation.
	Pod               string `json:"pod,omitempty"`
	Namespace         string `json:"namespace,omitempty"`
	Node              string `json:"node,omitempty"`
	Type              string `json:"type,omitempty"`
	CreationTimestamp string `json:"creationTimestamp,omitempty"`

	// InUse is true when this Allocation is currently being used by a running
	// workload / node / etc. It is false if this address is not active and should be cleaned up.
	InUse bool `json:"inUse"`

	// Borrowed is true if this IP is from a block that is not affine to the node.
	Borrowed bool `json:"borrowed,omitempty"`

	// CoolingDown is true if this IP is still allocatd but in its cooldown period.
	CoolingDown bool `json:"coolingDown,omitempty"`

	// List of objects which are using this IP.
	Owners []string `json:"owners"`
}

func (a *Allocation) GetAttrString() string {
	if a.accountingAlloc.Attr == nil {
		return "<missing>"
	}
	return formatAttrs(*a.accountingAlloc.Attr)
}

// tracked is whether the tracker judged the allocation. It skips deleted blocks and missing attributes.
func (a *Allocation) tracked() bool {
	return a.accountingAlloc.Attr != nil && !a.accountingAlloc.Block.Deleted
}

type HandleInfo struct {
	ID       string
	UID      *types.UID
	Revision string
}

func formatAttrs(attribute model.AllocationAttribute) string {
	primary := "<none>"
	if attribute.HandleID != nil {
		primary = *attribute.HandleID
	}

	result := fmt.Sprintf("Main:%s Extra:%s", primary, kvsFormat(attribute.ActiveOwnerAttrs))

	if len(attribute.AlternateOwnerAttrs) > 0 {
		result = fmt.Sprintf("%s Alternate:%s", result, kvsFormat(attribute.AlternateOwnerAttrs))
	}

	return result
}

// kvsFormat formats a map as a sorted, comma-separated list of key=value pairs.
func kvsFormat(m map[string]string) string {
	var keys []string
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var kvs []string
	for _, k := range keys {
		kvs = append(kvs, fmt.Sprintf("%s=%s", k, m[k]))
	}
	return strings.Join(kvs, ",")
}
