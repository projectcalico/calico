// Copyright (c) 2025 Tigera, Inc. All rights reserved.

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

package commands

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/docopt/docopt-go"
	"github.com/olekukonko/tablewriter"
	log "github.com/sirupsen/logrus"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"github.com/projectcalico/calico/calicoctl/calicoctl/commands/clientmgr"
	"github.com/projectcalico/calico/calicoctl/calicoctl/commands/common"
	"github.com/projectcalico/calico/calicoctl/calicoctl/commands/constants"
	"github.com/projectcalico/calico/calicoctl/calicoctl/util"
	"github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	"github.com/projectcalico/calico/libcalico-go/lib/clientv3"
	cerrors "github.com/projectcalico/calico/libcalico-go/lib/errors"
	"github.com/projectcalico/calico/libcalico-go/lib/options"
)

func Status(args []string) error {
	doc := constants.DatastoreIntro + `Usage:
  <BINARY_NAME> status [--config=<CONFIG>] [--allow-version-mismatch]

Options:
  -h --help                    Show this screen.
  -c --config=<CONFIG>         Path to the file containing connection configuration in
                              YAML or JSON format.
                              [default: ` + constants.DefaultConfigPath + `]
     --allow-version-mismatch  Allow client and cluster versions mismatch.

Description:
  Display Calico cluster status including networking, security, and observability configuration.
`
	name, _ := util.NameAndDescription()
	doc = strings.ReplaceAll(doc, "<BINARY_NAME>", name)

	parsedArgs, err := docopt.ParseArgs(doc, args, "")
	if err != nil {
		return fmt.Errorf("invalid option: 'calicoctl status'. Use flag '--help' to read about this command")
	}
	if len(parsedArgs) == 0 {
		return nil
	}

	if err := common.CheckVersionMismatch(parsedArgs["--config"], parsedArgs["--allow-version-mismatch"]); err != nil {
		return err
	}

	cf, _ := parsedArgs["--config"].(string)
	kubeClient, calicoClient, _, err := clientmgr.GetClients(cf)
	if err != nil {
		return fmt.Errorf("failed to create clients: %w", err)
	}

	ctx := context.Background()

	// Fetch resources with graceful error handling
	calicoCli := calicoClient.(clientv3.Interface)
	ci, _ := fetchClusterInformation(ctx, calicoCli)
	felixConfig, _ := fetchFelixConfiguration(ctx, calicoCli)
	ippools, _ := fetchIPPools(ctx, calicoCli)
	bgpConfig, _ := fetchBGPConfiguration(ctx, calicoCli)
	ipamConfig, _ := fetchIPAMConfiguration(ctx, calicoCli)
	goldmaneStatus, whiskerStatus := fetchGoldmaneWhiskerStatus(ctx, kubeClient)

	// Inference helpers
	dpType := inferDataplaneType(felixConfig)
	overlayStatus := inferOverlayStatus(ippools, felixConfig)
	bgpMeshEnabled := inferBGPMeshEnabled(bgpConfig)
	bgpStatus := inferBGPStatus(bgpConfig)

	printStatus(ci, felixConfig, ippools, bgpConfig, ipamConfig, dpType, overlayStatus, bgpMeshEnabled, bgpStatus, goldmaneStatus, whiskerStatus)

	return nil
}

func stringOrDefault(s, def string) string {
	if s == "" {
		return def
	}
	return s
}

func fetchClusterInformation(ctx context.Context, client clientv3.Interface) (*v3.ClusterInformation, error) {
	ci, err := client.ClusterInformation().Get(ctx, "default", options.GetOptions{})
	if err != nil {
		if _, ok := err.(cerrors.ErrorResourceDoesNotExist); ok {
			log.Debugf("ClusterInformation not found: %v", err)
			return nil, nil
		}
		log.Debugf("Failed to fetch ClusterInformation: %v", err)
		return nil, err
	}
	return ci, nil
}

func fetchFelixConfiguration(ctx context.Context, client clientv3.Interface) (*v3.FelixConfiguration, error) {
	fc, err := client.FelixConfigurations().Get(ctx, "default", options.GetOptions{})
	if err != nil {
		if _, ok := err.(cerrors.ErrorResourceDoesNotExist); ok {
			log.Debugf("FelixConfiguration not found: %v", err)
			return nil, nil
		}
		log.Debugf("Failed to fetch FelixConfiguration: %v", err)
		return nil, err
	}
	return fc, nil
}

func fetchIPPools(ctx context.Context, client clientv3.Interface) (*v3.IPPoolList, error) {
	pools, err := client.IPPools().List(ctx, options.ListOptions{})
	if err != nil {
		log.Debugf("Failed to fetch IPPools: %v", err)
		return &v3.IPPoolList{Items: []v3.IPPool{}}, err
	}
	return pools, nil
}

func fetchBGPConfiguration(ctx context.Context, client clientv3.Interface) (*v3.BGPConfiguration, error) {
	bgp, err := client.BGPConfigurations().Get(ctx, "default", options.GetOptions{})
	if err != nil {
		if _, ok := err.(cerrors.ErrorResourceDoesNotExist); ok {
			log.Debugf("BGPConfiguration not found: %v", err)
			return nil, nil
		}
		log.Debugf("Failed to fetch BGPConfiguration: %v", err)
		return nil, err
	}
	return bgp, nil
}

func fetchIPAMConfiguration(ctx context.Context, client clientv3.Interface) (*v3.IPAMConfiguration, error) {
	ipam, err := client.IPAMConfiguration().Get(ctx, "default", options.GetOptions{})
	if err != nil {
		if _, ok := err.(cerrors.ErrorResourceDoesNotExist); ok {
			log.Debugf("IPAMConfiguration not found: %v", err)
			return nil, nil
		}
		log.Debugf("Failed to fetch IPAMConfiguration: %v", err)
		return nil, err
	}
	return ipam, nil
}

func fetchGoldmaneWhiskerStatus(ctx context.Context, kubeClient *kubernetes.Clientset) (goldmaneStatus, whiskerStatus string) {
	if kubeClient == nil {
		return "Disabled", "Disabled"
	}

	goldmaneStatus = "Disabled"
	whiskerStatus = "Disabled"

	nsl, err := kubeClient.CoreV1().Namespaces().List(ctx, metav1.ListOptions{})
	if err != nil {
		log.Debugf("Failed to list namespaces: %v", err)
		return goldmaneStatus, whiskerStatus
	}

	for _, ns := range nsl.Items {
		if !strings.Contains(ns.Name, "calico") && !strings.Contains(ns.Name, "tigera") {
			continue
		}

		dl, err := kubeClient.AppsV1().Deployments(ns.Name).List(ctx, metav1.ListOptions{})
		if err != nil {
			log.Debugf("Failed to list deployments in %s: %v", ns.Name, err)
			continue
		}

		for _, d := range dl.Items {
			name := d.Name
			ready := d.Status.ReadyReplicas
			total := d.Status.Replicas
			statusStr := "Not ready"
			if ready > 0 && ready == total {
				statusStr = "Running"
			} else if ready > 0 {
				statusStr = fmt.Sprintf("Running (%d/%d)", ready, total)
			}

			if name == "goldmane" || (d.Labels != nil && d.Labels["k8s-app"] == "goldmane") {
				goldmaneStatus = statusStr
			}
			if name == "whisker" || name == "whisker-backend" || (d.Labels != nil && d.Labels["k8s-app"] == "whisker") {
				whiskerStatus = statusStr
			}
		}
	}

	return goldmaneStatus, whiskerStatus
}

func inferDataplaneType(fc *v3.FelixConfiguration) string {
	if fc == nil {
		return "iptables"
	}
	// External/pluggable dataplane (e.g. Windows, custom driver)
	if fc.Spec.UseInternalDataplaneDriver != nil && !*fc.Spec.UseInternalDataplaneDriver {
		if fc.Spec.DataplaneDriver != "" {
			return "external (" + fc.Spec.DataplaneDriver + ")"
		}
		return "external"
	}
	if fc.Spec.BPFEnabled != nil && *fc.Spec.BPFEnabled {
		return "eBPF"
	}
	if fc.Spec.IptablesBackend != nil && *fc.Spec.IptablesBackend == v3.IptablesBackendNFTables {
		return "nftables"
	}
	return "iptables"
}

func inferOverlayStatus(pools *v3.IPPoolList, fc *v3.FelixConfiguration) string {
	if pools == nil || len(pools.Items) == 0 {
		return "-"
	}
	var modes []string
	for _, p := range pools.Items {
		if p.Spec.VXLANMode != "" && p.Spec.VXLANMode != v3.VXLANModeNever {
			modes = append(modes, "VXLAN")
			break
		}
	}
	for _, p := range pools.Items {
		if p.Spec.IPIPMode != "" && p.Spec.IPIPMode != v3.IPIPModeNever {
			modes = append(modes, "IPIP")
			break
		}
	}
	if fc != nil {
		if fc.Spec.VXLANEnabled != nil && *fc.Spec.VXLANEnabled {
			modes = append(modes, "VXLAN")
		}
		if fc.Spec.IPIPEnabled != nil && *fc.Spec.IPIPEnabled {
			modes = append(modes, "IPIP")
		}
	}
	if len(modes) == 0 {
		return "None (BGP)"
	}
	return strings.Join(modes, ", ")
}

func inferBGPMeshEnabled(bgp *v3.BGPConfiguration) string {
	if bgp == nil || bgp.Spec.NodeToNodeMeshEnabled == nil {
		return "Enabled"
	}
	if *bgp.Spec.NodeToNodeMeshEnabled {
		return "Enabled"
	}
	return "Disabled"
}

func inferBGPStatus(bgp *v3.BGPConfiguration) string {
	if bgp == nil {
		return "Disabled"
	}
	parts := []string{"Configured"}
	if bgp.Spec.ASNumber != nil {
		parts = append(parts, fmt.Sprintf("AS %s", fmt.Sprint(*bgp.Spec.ASNumber)))
	}
	if bgp.Spec.ListenPort != 0 {
		parts = append(parts, fmt.Sprintf("port %d", bgp.Spec.ListenPort))
	}
	return strings.Join(parts, ", ")
}

// printDataplaneSection outputs dataplane-specific insights from FelixConfiguration.
// Calico has a pluggable dataplane; the section content varies by dataplane type.
func printDataplaneSection(fc *v3.FelixConfiguration, dpType string) {
	fmt.Println("Dataplane")
	fmt.Println("==========")
	t := tablewriter.NewWriter(os.Stdout)
	t.SetHeader([]string{"Setting", "Value", "Notes"})

	if fc == nil {
		t.Append([]string{"(no FelixConfiguration)", "-", "Using defaults"})
		t.Render()
		return
	}

	// Common: IPv6 (supported by dataplanes that implement it)
	if fc.Spec.IPv6Support != nil {
		ipv6 := "Disabled"
		if *fc.Spec.IPv6Support {
			ipv6 = "Enabled"
		}
		t.Append([]string{"IPv6 support", ipv6, "If supported by dataplane"})
	}

	// Common: Wireguard encryption (overlay, applies to iptables/nftables/eBPF)
	wireguard := "Disabled"
	if fc.Spec.WireguardEnabled != nil && *fc.Spec.WireguardEnabled {
		wireguard = "Enabled (IPv4)"
	}
	if fc.Spec.WireguardEnabledV6 != nil && *fc.Spec.WireguardEnabledV6 {
		if wireguard != "Disabled" {
			wireguard += ", IPv6"
		} else {
			wireguard = "Enabled (IPv6)"
		}
	}
	t.Append([]string{"Wireguard encryption", wireguard, "Overlay encryption"})

	// Common: VXLAN port (overlay, default 4789)
	vxlanPort := "4789"
	if fc.Spec.VXLANPort != nil {
		vxlanPort = fmt.Sprintf("%d", *fc.Spec.VXLANPort)
	}
	t.Append([]string{"VXLAN port", vxlanPort, "UDP port for VXLAN overlay"})

	// Common: routing and overlay settings
	allowIPIP := "Disabled"
	if fc.Spec.AllowIPIPPacketsFromWorkloads != nil && *fc.Spec.AllowIPIPPacketsFromWorkloads {
		allowIPIP = "Enabled"
	}
	t.Append([]string{"Allow IPIP from workloads", allowIPIP, "-"})
	if fc.Spec.ExternalNodesCIDRList != nil && len(*fc.Spec.ExternalNodesCIDRList) > 0 {
		t.Append([]string{"External nodes list", strings.Join(*fc.Spec.ExternalNodesCIDRList, ", "), "CIDRs for overlay traffic"})
	} else {
		t.Append([]string{"External nodes list", "Disabled", "No external CIDRs"})
	}
	routeSource := "CalicoIPAM"
	if fc.Spec.RouteSource != "" {
		routeSource = fc.Spec.RouteSource
	}
	t.Append([]string{"Route source", routeSource, "WorkloadIPs or CalicoIPAM"})
	programClusterRoutes := "Disabled"
	if fc.Spec.ProgramClusterRoutes != nil && *fc.Spec.ProgramClusterRoutes == "Enabled" {
		programClusterRoutes = "Enabled"
	}
	t.Append([]string{"Program cluster routes", programClusterRoutes, "IPIP routes vs BIRD"})
	removeExternalRoutes := "Enabled"
	if fc.Spec.RemoveExternalRoutes != nil && !*fc.Spec.RemoveExternalRoutes {
		removeExternalRoutes = "Disabled"
	}
	t.Append([]string{"Remove external routes", removeExternalRoutes, "Clean up unexpected routes"})

	// Dataplane-specific rows
	switch {
	case strings.HasPrefix(dpType, "external"):
		if fc.Spec.DataplaneDriver != "" {
			t.Append([]string{"External driver", fc.Spec.DataplaneDriver, "Pluggable dataplane"})
		}
		t.Append([]string{"Internal driver", "Disabled", "Using external dataplane"})

	case dpType == "eBPF":
		// CTLB (Connect-Time Load Balancer) insights
		ctlb := "TCP"
		if fc.Spec.BPFConnectTimeLoadBalancing != nil {
			ctlb = string(*fc.Spec.BPFConnectTimeLoadBalancing)
		}
		t.Append([]string{"Connect-time LB", ctlb, "Service load balancing (CTLB)"})
		hostNAT := "Enabled"
		if fc.Spec.BPFHostNetworkedNATWithoutCTLB != nil && *fc.Spec.BPFHostNetworkedNATWithoutCTLB == v3.BPFHostNetworkedNATDisabled {
			hostNAT = "Disabled"
		}
		t.Append([]string{"Host networked NAT (no CTLB)", hostNAT, "NAT without CTLB"})
		// BPF attach type
		attach := "TCX"
		if fc.Spec.BPFAttachType != nil {
			attach = string(*fc.Spec.BPFAttachType)
		}
		t.Append([]string{"BPF attach type", attach, "TC or TCX"})
		// RPF enforcement
		rpf := "Loose"
		if fc.Spec.BPFEnforceRPF != "" {
			rpf = fc.Spec.BPFEnforceRPF
		}
		t.Append([]string{"BPF enforce RPF", rpf, "Reverse path filtering"})
		bypass := "Enabled"
		if fc.Spec.BPFHostConntrackBypass != nil && !*fc.Spec.BPFHostConntrackBypass {
			bypass = "Disabled"
		}
		t.Append([]string{"Host conntrack bypass", bypass, "Bypass Linux conntrack"})
		// XDP can be used with eBPF for acceleration
		xdp := "Enabled"
		if fc.Spec.XDPEnabled != nil && !*fc.Spec.XDPEnabled {
			xdp = "Disabled"
		}
		t.Append([]string{"XDP acceleration", xdp, "Untracked deny rules"})

	case dpType == "nftables":
		mode := "Auto"
		if fc.Spec.NFTablesMode != nil {
			mode = string(*fc.Spec.NFTablesMode)
		}
		t.Append([]string{"NFTables mode", mode, "-"})
		backend := "Auto"
		if fc.Spec.IptablesBackend != nil {
			backend = string(*fc.Spec.IptablesBackend)
		}
		t.Append([]string{"Backend", backend, "Legacy/NFT/Auto"})
		xdp := "Enabled"
		if fc.Spec.XDPEnabled != nil && !*fc.Spec.XDPEnabled {
			xdp = "Disabled"
		}
		t.Append([]string{"XDP acceleration", xdp, "For iptables-compat deny rules"})

	case dpType == "iptables":
		backend := "Auto"
		if fc.Spec.IptablesBackend != nil {
			backend = string(*fc.Spec.IptablesBackend)
		}
		t.Append([]string{"Iptables backend", backend, "Legacy/NFT/Auto"})
		xdp := "Enabled"
		if fc.Spec.XDPEnabled != nil && !*fc.Spec.XDPEnabled {
			xdp = "Disabled"
		}
		t.Append([]string{"XDP acceleration", xdp, "Untracked incoming deny rules"})
		genericXDP := "Disabled"
		if fc.Spec.GenericXDPEnabled != nil && *fc.Spec.GenericXDPEnabled {
			genericXDP = "Enabled"
		}
		t.Append([]string{"Generic XDP", genericXDP, "Fallback when driver XDP unavailable"})
	}

	t.Render()
}

func printStatus(ci *v3.ClusterInformation, felixConfig *v3.FelixConfiguration, pools *v3.IPPoolList,
	bgpConfig *v3.BGPConfiguration, ipamConfig *v3.IPAMConfiguration,
	dpType, overlayStatus, bgpMeshEnabled, bgpStatus, goldmaneStatus, whiskerStatus string) {

	// Overview
	fmt.Println("Overview")
	fmt.Println("=======")
	calicoVersion := "-"
	clusterType := "-"
	if ci != nil {
		calicoVersion = stringOrDefault(ci.Spec.CalicoVersion, "-")
		clusterType = stringOrDefault(ci.Spec.ClusterType, "-")
	}
	fmt.Printf("  Calico version:    %s\n", calicoVersion)
	fmt.Printf("  Cluster type:      %s\n", clusterType)
	fmt.Printf("  Dataplane:         %s\n", dpType)
	if dpType == "iptables" || dpType == "nftables" {
		fmt.Println("  \U0001F41D consider using Calico eBPF dataplane for better performance. \U0001F41D")
	}
	fmt.Println()

	// Dataplane (pluggable - output varies by dataplane type)
	printDataplaneSection(felixConfig, dpType)
	fmt.Println()

	// Networking
	fmt.Println("Networking")
	fmt.Println("==========")
	t := tablewriter.NewWriter(os.Stdout)
	t.SetHeader([]string{"Setting", "Value", "Notes"})
	t.Append([]string{"BGP status", bgpStatus, "-"})
	t.Append([]string{"BGP mesh", bgpMeshEnabled, "Node-to-node mesh"})
	t.Append([]string{"Overlay", overlayStatus, "-"})
	if pools != nil && len(pools.Items) > 0 {
		var cidrs []string
		for _, p := range pools.Items {
			cidrs = append(cidrs, p.Spec.CIDR)
		}
		t.Append([]string{"IP pools", strings.Join(cidrs, ", "), "-"})
	} else {
		t.Append([]string{"IP pools", "-", "-"})
	}
	t.Render()
	fmt.Println()

	// Observability (includes Goldmane, Whisker, Prometheus, BPFProfiling)
	fmt.Println("Observability")
	fmt.Println("=============")
	t2 := tablewriter.NewWriter(os.Stdout)
	t2.SetHeader([]string{"Component", "Status", "Notes"})
	t2.Append([]string{"Goldmane", goldmaneStatus, "-"})
	t2.Append([]string{"Whisker", whiskerStatus, "-"})
	prometheus := "Disabled"
	if felixConfig != nil && felixConfig.Spec.PrometheusMetricsEnabled != nil && *felixConfig.Spec.PrometheusMetricsEnabled {
		prometheus = "Enabled"
	}
	t2.Append([]string{"Prometheus metrics", prometheus, "-"})
	bpfProfiling := "Disabled"
	if felixConfig != nil {
		bpfProfiling = stringOrDefault(felixConfig.Spec.BPFProfiling, "Disabled")
	}
	t2.Append([]string{"eBPF Profiling", bpfProfiling, "-"})
	t2.Render()
	fmt.Println()

	// Advanced Config (optional section)
	if ipamConfig != nil || (felixConfig != nil && felixConfig.Spec.IPForwarding != "") {
		fmt.Println("Advanced Config")
		fmt.Println("===============")
		t3 := tablewriter.NewWriter(os.Stdout)
		t3.SetHeader([]string{"Setting", "Value", "Notes"})
		if ipamConfig != nil {
			strictAffinity := "Disabled"
			if ipamConfig.Spec.StrictAffinity {
				strictAffinity = "Enabled"
			}
			t3.Append([]string{"Strict affinity", strictAffinity, "-"})
		}
		if felixConfig != nil && felixConfig.Spec.IPForwarding != "" {
			t3.Append([]string{"IP forwarding", felixConfig.Spec.IPForwarding, "-"})
		}
		t3.Render()
	}
}
