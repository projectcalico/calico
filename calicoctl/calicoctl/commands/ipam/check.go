// Copyright (c) 2016-2020 Tigera, Inc. All rights reserved.

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
	"io/ioutil"
	"net"
	"sort"
	"strings"

	docopt "github.com/docopt/docopt-go"
	"k8s.io/client-go/kubernetes"

	"github.com/projectcalico/calico/libcalico-go/lib/set"

	"github.com/projectcalico/calico/libcalico-go/lib/ipam"

	apiv3 "github.com/projectcalico/calico/libcalico-go/lib/apis/v3"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/k8s"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/calico/libcalico-go/lib/clientv3"
	cnet "github.com/projectcalico/calico/libcalico-go/lib/net"

	bapi "github.com/projectcalico/calico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/calico/libcalico-go/lib/options"

	"github.com/projectcalico/calico/calicoctl/calicoctl/commands/common"
	"github.com/projectcalico/calico/calicoctl/calicoctl/commands/constants"
	"github.com/projectcalico/calico/calicoctl/calicoctl/util"

	"github.com/projectcalico/calico/calicoctl/calicoctl/commands/clientmgr"
)

// IPAM takes keyword with an IP address then calls the subcommands.
func Check(args []string, version string) error {
	doc := constants.DatastoreIntro + `Usage:
  <BINARY_NAME> ipam check [--config=<CONFIG>] [--show-all-ips] [--show-problem-ips] [-o <FILE>] [--allow-version-mismatch]

Options:
  -h --help                    Show this screen.
  -o --output=<FILE>           Path to output report file.
     --show-all-ips            Print all IPs that are checked.
     --show-problem-ips        Print all IPs that are leaked or not allocated properly.
  -c --config=<CONFIG>         Path to the file containing connection configuration in
                               YAML or JSON format.
                               [default: ` + constants.DefaultConfigPath + `]
     --allow-version-mismatch  Allow client and cluster versions mismatch.

Description:
  The ipam check command checks the integrity of the IPAM datastructures against Kubernetes.
`
	// Replace all instances of BINARY_NAME with the name of the binary.
	name, _ := util.NameAndDescription()
	doc = strings.ReplaceAll(doc, "<BINARY_NAME>", name)

	parsedArgs, err := docopt.ParseArgs(doc, args, version)
	if err != nil {
		return fmt.Errorf("Invalid option: 'calicoctl %s'. Use flag '--help' to read about a specific subcommand.", strings.Join(args, " "))
	}
	if len(parsedArgs) == 0 {
		return nil
	}

	err = common.CheckVersionMismatch(parsedArgs["--config"], parsedArgs["--allow-version-mismatch"])
	if err != nil {
		return err
	}

	ctx := context.Background()

	// Create a new backend client from env vars.
	cf := parsedArgs["--config"].(string)
	client, err := clientmgr.NewClient(cf)
	if err != nil {
		return err
	}

	// Get the backend client.
	type accessor interface {
		Backend() bapi.Client
	}
	bc := client.(accessor).Backend()

	// Get a kube-client. If this is a kdd cluster, we can pull this from the backend.
	// Otherwise, we need to build one ourselves.
	var kubeClient *kubernetes.Clientset
	if kc, ok := bc.(*k8s.KubeClient); ok {
		// Pull from the kdd client.
		kubeClient = kc.ClientSet
	}
	// TODO: Support etcd mode. For now, this is OK since we don't actually
	// use the kubeClient yet. But we will do so eventually.

	// Pull out CLI args.
	showAllIPs := parsedArgs["--show-all-ips"].(bool)
	showProblemIPs := showAllIPs || parsedArgs["--show-problem-ips"].(bool)
	var outFile string = ""
	if arg := parsedArgs["--output"]; arg != nil {
		outFile = arg.(string)
	}

	// Build the checker.
	checker := NewIPAMChecker(kubeClient, client, bc, showAllIPs, showProblemIPs, outFile, version)
	return checker.checkIPAM(ctx)
}

func NewIPAMChecker(k8sClient kubernetes.Interface,
	v3Client clientv3.Interface,
	backendClient bapi.Client,
	showAllIPs bool,
	showProblemIPs bool,
	outFile string,
	version string) *IPAMChecker {
	return &IPAMChecker{
		allocations:       map[string][]*Allocation{},
		allocationsByNode: map[string][]*Allocation{},
		allocationsByPod:  map[string][]*Allocation{},

		inUseIPs:     map[string][]ownerRecord{},
		inUseHandles: set.New(),

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
	allocations       map[string][]*Allocation
	allocationsByNode map[string][]*Allocation
	allocationsByPod  map[string][]*Allocation
	leakedHandles     []string
	inUseIPs          map[string][]ownerRecord
	inUseHandles      set.Set

	clusterType         string
	clusterInfoRevision string
	datastoreLocked     bool
	clusterGUID         string

	k8sClient     kubernetes.Interface
	backendClient bapi.Client
	v3Client      clientv3.Interface

	showAllIPs     bool
	showProblemIPs bool

	version string
	outFile string
}

func (c *IPAMChecker) checkIPAM(ctx context.Context) error {
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
	{
		fmt.Println("Loading all IPAM blocks...")
		blocks, err := c.backendClient.List(ctx, model.BlockListOptions{}, "")
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
		}
		fmt.Printf("IPAM blocks record %d allocations.\n", numAllocs)
		fmt.Println()
	}
	var activeIPPools []*cnet.IPNet
	{
		fmt.Println("Loading all IPAM pools...")
		ipPools, err := c.v3Client.IPPools().List(ctx, options.ListOptions{})
		if err != nil {
			return fmt.Errorf("failed to load IP pools: %w", err)
		}
		for _, p := range ipPools.Items {
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
		for _, n := range nodes.Items {
			ips, err := getNodeIPs(n)
			if err != nil {
				return err
			}
			for _, ip := range ips {
				c.recordInUseIP(ip, n, fmt.Sprintf("Node(%s)", n.Name))
				numNodeIPs++
			}
		}
		fmt.Printf("Found %d node tunnel IPs.\n", numNodeIPs)
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
			ips, err := getWEPIPs(w)
			if err != nil {
				return err
			}
			for _, ip := range ips {
				c.recordInUseIP(ip, w, fmt.Sprintf("Workload(%s/%s)", w.Namespace, w.Name))
				numWEPIPs++
			}
		}
		fmt.Printf("Found %d workload IPs.\n", numWEPIPs)
		fmt.Printf("Workloads and nodes are using %d IPs.\n", len(c.inUseIPs))
		fmt.Println()
	}

	handles := map[string]model.IPAMHandle{}
	{
		fmt.Println("Loading all handles")
		handleList, err := c.backendClient.List(ctx, model.IPAMHandleListOptions{}, "")
		if err != nil {
			return fmt.Errorf("failed to list handles: %w", err)
		}
		for _, kv := range handleList.KVPairs {
			handleKey := kv.Key.(model.IPAMHandleKey)
			handleVal := kv.Value.(model.IPAMHandle)
			handles[handleKey.HandleID] = handleVal
		}
	}

	{
		const numNodesToPrint = 20
		fmt.Printf("Looking for top (up to %d) nodes by allocations...\n", numNodesToPrint)
		var allNodes []string
		for n := range c.allocationsByNode {
			allNodes = append(allNodes, n)
		}
		sort.Slice(allNodes, func(i, j int) bool {
			// Reverse order
			return len(c.allocationsByNode[allNodes[i]]) > len(c.allocationsByNode[allNodes[j]])
		})
		for i, n := range allNodes {
			if i >= numNodesToPrint {
				break
			}
			fmt.Printf("  %s has %d allocations\n", n, len(c.allocationsByNode[n]))
		}
		if len(allNodes) > 0 {
			max := len(c.allocationsByNode[allNodes[0]])
			median := len(c.allocationsByNode[allNodes[len(allNodes)/2]])
			fmt.Printf("Node with most allocations has %d; median is %d\n", max, median)
		}
		fmt.Println()
	}

	numProblems := 0
	var allocatedButNotInUseIPs []string
	{
		fmt.Printf("Scanning for IPs that are allocated but not actually in use...\n")
		for ip, allocs := range c.allocations {
			if _, ok := c.inUseIPs[ip]; !ok {
				if c.showProblemIPs {
					for _, alloc := range allocs {
						fmt.Printf("  %s leaked; attrs %v\n", ip, alloc.GetAttrString())
					}
				}
				allocatedButNotInUseIPs = append(allocatedButNotInUseIPs, ip)
			}
		}
		numProblems += len(allocatedButNotInUseIPs)
		fmt.Printf("Found %d IPs that are allocated in IPAM but not actually in use.\n", len(allocatedButNotInUseIPs))
	}

	var inUseButNotAllocatedIPs []string
	var nonCalicoIPs []string
	{
		fmt.Printf("Scanning for IPs that are in use by a workload or node but not allocated in IPAM...\n")
		for ip, owners := range c.inUseIPs {
			if c.showProblemIPs && len(owners) > 1 {
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
						for _, owner := range owners {
							fmt.Printf("  %s in use by %v is not in any active IP pool.\n", ip, owner.FriendlyName)
						}
					}
					nonCalicoIPs = append(nonCalicoIPs, ip)
					continue
				}
				if c.showProblemIPs {
					for _, owner := range owners {
						fmt.Printf("  %s in use by %v and in active IPAM pool but has no IPAM allocation.\n", ip, owner.FriendlyName)
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

	{
		fmt.Printf("Scanning for IPAM handles with no matching IPs...\n")
		goodHandles := 0
		var leakedHandles []string
		for handleID := range handles {
			if c.inUseHandles.Contains(handleID) {
				goodHandles++
				continue
			}
			if c.showAllIPs {
				fmt.Printf("  %s doesn't have any active IPs.\n", handleID)
			}
			numProblems++
			leakedHandles = append(leakedHandles, handleID)
		}
		fmt.Printf("Found %d handles with no matching IPs (and %d handles with matches).\n",
			len(leakedHandles), goodHandles)
		c.leakedHandles = leakedHandles
	}

	var missingHandles []string
	{
		fmt.Printf("Scanning for IPs with missing handle...\n")
		c.inUseHandles.Iter(func(item interface{}) error {
			handleID := item.(string)
			if _, ok := handles[handleID]; ok {
				return nil
			}
			if c.showProblemIPs {
				fmt.Printf("  %s is in use in a block but doesn't exist.\n", handleID)
			}
			missingHandles = append(missingHandles, handleID)
			return nil
		})
		fmt.Printf("Found %d handles mentioned in blocks with no matching handle resource.\n", len(missingHandles))
	}

	fmt.Printf("Check complete; found %d problems.\n", numProblems)

	if c.outFile != "" {
		// Print out a machine readable report.
		c.printReport()
	}
	return nil
}

func getWEPIPs(w apiv3.WorkloadEndpoint) ([]string, error) {
	var ips []string
	for _, a := range w.Spec.IPNetworks {
		ip, err := normaliseIP(a)
		if err != nil {
			return nil, fmt.Errorf("failed to parse IP (%s) of workload %s/%s: %w",
				a, w.Namespace, w.Name, err)
		}
		ips = append(ips, ip)
	}
	return ips, nil
}

type Report struct {
	// Version of the code that produced the report.
	Version string `json:"version"`

	// Important metadata.
	ClusterGUID         string `json:"clusterGUID"`
	DatastoreLocked     bool   `json:"datastoreLocked"`
	ClusterInfoRevision string `json:"clusterInformationRevision"`
	ClusterType         string `json:"clusterType"`

	// Allocations is a map of IP address to list of allocation data.
	Allocations   map[string][]*Allocation `json:"allocations"`
	LeakedHandles []string                 `json:"leakedHandles"`
}

func (c *IPAMChecker) printReport() {
	r := Report{
		Version:             c.version,
		ClusterGUID:         c.clusterGUID,
		ClusterType:         c.clusterType,
		ClusterInfoRevision: c.clusterInfoRevision,
		DatastoreLocked:     c.datastoreLocked,
		Allocations:         c.allocations,
		LeakedHandles:       c.leakedHandles,
	}
	bytes, _ := json.MarshalIndent(r, "", "  ")
	_ = ioutil.WriteFile(c.outFile, bytes, 0777)
}

// recordAllocation takes a block and ordinal within that block and updates
// the IPAMChecker's internal state to track the allocation.
func (c *IPAMChecker) recordAllocation(b *model.AllocationBlock, ord int) {
	ip := b.OrdinalToIP(ord).String()
	alloc := Allocation{IP: ip, Block: b, Ordinal: ord}

	node := ""
	blockAffinity := ""
	if b.Affinity != nil {
		affinity := *b.Affinity
		if strings.HasPrefix(affinity, "host:") {
			node = affinity[5:]
			blockAffinity = affinity[5:]
		}
	}

	attrIdx := *b.Allocations[ord]
	if len(b.Attributes) > attrIdx {
		attrs := b.Attributes[attrIdx]
		if attrs.AttrPrimary != nil && *attrs.AttrPrimary == ipam.WindowsReservedHandle {
			c.recordInUseIP(ip, b, "Reserved for Windows")
		} else if attrs.AttrPrimary != nil {
			alloc.Handle = *attrs.AttrPrimary
			c.recordInUseHandle(alloc.Handle)
		}
		if n := attrs.AttrSecondary["node"]; n != "" {
			node = n
		}
		if p := attrs.AttrSecondary["pod"]; p != "" {
			alloc.Pod = p
		}
		if n := attrs.AttrSecondary["namespace"]; n != "" {
			alloc.Namespace = n
		}
		if t := attrs.AttrSecondary["type"]; t != "" {
			alloc.Type = t
		}
		if t := attrs.AttrSecondary["timestamp"]; t != "" {
			alloc.CreationTimestamp = t
		}
	}

	// Fill in the sequence number for the allocation.
	s := b.GetSequenceNumberForOrdinal(ord)
	alloc.SequenceNumber = &s

	// Fill in the node for the allocation.
	alloc.Node = node

	// Determine if this is a borrowed address, and mark it as such if so.
	if node != blockAffinity {
		alloc.Borrowed = true
	}

	// Store the allocation in internal state.
	c.allocations[ip] = append(c.allocations[ip], &alloc)
	c.allocationsByNode[node] = append(c.allocationsByNode[node], &alloc)
	if alloc.Pod != "" {
		pod := fmt.Sprintf("%s/%s", alloc.Namespace, alloc.Pod)
		c.allocationsByPod[pod] = append(c.allocationsByPod[pod], &alloc)
	}

	if c.showAllIPs {
		fmt.Printf("  %s allocated; attrs %s\n", ip, alloc.GetAttrString())
	}
}

// recordInUseIP records that the given IP is currently being used by the given resource (i.e., pod, node, etc).
func (c *IPAMChecker) recordInUseIP(ip string, referrer interface{}, friendlyName string) {
	if c.showAllIPs {
		fmt.Printf("  %s belongs to %s\n", ip, friendlyName)
	}

	c.inUseIPs[ip] = append(c.inUseIPs[ip], ownerRecord{
		FriendlyName: friendlyName,
		Resource:     referrer,
	})

	// Mark the corresponding allocation as in use.
	for _, a := range c.allocations[ip] {
		a.InUse = true
		a.Owners = append(a.Owners, friendlyName)
	}
}

func (c *IPAMChecker) recordInUseHandle(handle string) {
	c.inUseHandles.Add(handle)
}

func getNodeIPs(n apiv3.Node) ([]string, error) {
	var ips []string
	if n.Spec.IPv4VXLANTunnelAddr != "" {
		ip, err := normaliseIP(n.Spec.IPv4VXLANTunnelAddr)
		if err != nil {
			return nil, fmt.Errorf("failed to parse IPv4VXLANTunnelAddr (%s) of node %s: %w",
				n.Spec.IPv4VXLANTunnelAddr, n.Name, err)
		}
		ips = append(ips, ip)
	}
	if n.Spec.Wireguard != nil && n.Spec.Wireguard.InterfaceIPv4Address != "" {
		ip, err := normaliseIP(n.Spec.Wireguard.InterfaceIPv4Address)
		if err != nil {
			return nil, fmt.Errorf("failed to parse Wireguard.InterfaceIPv4Address (%s) of node %s: %w",
				n.Spec.Wireguard.InterfaceIPv4Address, n.Name, err)
		}
		ips = append(ips, ip)
	}
	if n.Spec.BGP != nil && n.Spec.BGP.IPv4IPIPTunnelAddr != "" {
		ip, err := normaliseIP(n.Spec.BGP.IPv4IPIPTunnelAddr)
		if err != nil {
			return nil, fmt.Errorf("failed to parse IPv4IPIPTunnelAddr (%s) of node %s: %w",
				n.Spec.BGP.IPv4IPIPTunnelAddr, n.Name, err)
		}
		ips = append(ips, ip)
	}
	return ips, nil
}

func normaliseIP(addr string) (string, error) {
	ip, _, err := cnet.ParseCIDROrIP(addr)
	if err != nil {
		return "", err
	}
	return ip.String(), nil
}

// Allocation represents an IP that is allocated in Calico IPAM, augmented with data
// from cross referencing with WorkloadEndpoints, etc.
type Allocation struct {
	// The actual address.
	IP string `json:"ip"`

	// Access to the block.
	Block   *model.AllocationBlock `json:"-"`
	Ordinal int                    `json:"-"`

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

	// List of objects which are using this IP.
	Owners []string `json:"owners"`
}

func (a *Allocation) GetAttrString() string {
	attrIdx := *a.Block.Allocations[a.Ordinal]
	if len(a.Block.Attributes) > attrIdx {
		return formatAttrs(a.Block.Attributes[attrIdx])
	}
	return "<missing>"
}

func formatAttrs(attribute model.AllocationAttribute) string {
	primary := "<none>"
	if attribute.AttrPrimary != nil {
		primary = *attribute.AttrPrimary
	}
	var keys []string
	for k := range attribute.AttrSecondary {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var kvs []string
	for _, k := range keys {
		kvs = append(kvs, fmt.Sprintf("%s=%s", k, attribute.AttrSecondary[k]))
	}
	return fmt.Sprintf("Main:%s Extra:%s", primary, strings.Join(kvs, ","))
}

type ownerRecord struct {
	FriendlyName string
	Resource     interface{}
}
