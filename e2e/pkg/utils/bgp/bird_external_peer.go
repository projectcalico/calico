// Copyright (c) 2026 Tigera, Inc. All rights reserved.
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

// Package bgp provides reusable BIRD BGP peer utilities for e2e tests.
// It supports two transports: local Docker containers (ContainerBIRDPeer)
// and SSH-based external nodes (SSHBIRDPeer). Both implement the BIRDPeer
// interface so test setup code can be transport-agnostic.
package bgp

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"time"

	//nolint:staticcheck // Ignore ST1001: should not use dot imports
	. "github.com/onsi/ginkgo/v2"
	//nolint:staticcheck // Ignore ST1001: should not use dot imports
	. "github.com/onsi/gomega"
	"github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/e2e/pkg/utils/externalnode"
	"github.com/projectcalico/calico/e2e/pkg/utils/images"
)

// birdHeaderTemplate is the static header of the BIRD peers config.
// The %s placeholder is the cluster's IPv4 IPPool CIDR, used to gate the
// import filter so only pod-network routes are accepted. Filter shape mirrors
// confd's communities_and_operations bird.cfg.
const birdHeaderTemplate = `function import_community_lp() {
  if ((65000, 100) ~ bgp_community) then { bgp_local_pref = 2147483135; accept; }
  accept;
}

filter import_community_priority {
  # Only accept routes within the pod CIDR. Reject kernel/direct routes
  # (0.0.0.0/0, 10.x, 169.254.x, 172.16.x) that would break TOR routing.
  if (net !~ %s) then reject;

  import_community_lp();
  if (defined(bgp_local_pref)&&(bgp_local_pref > 2147482623)) then
    preference = 200;
  accept;
}

template bgp bgp_template {
  debug { states };
  description "BGP peer";
  local as 65001;
  multihop;
  gateway recursive;
  import filter import_community_priority;
  export none;
  source address ip@local;
  add paths on;
  graceful restart;
  connect delay time 2;
  connect retry time 5;
  error wait time 5,30;
}

`

// birdPeerTemplate is the per-peer block format. Args: index, peer IP.
const birdPeerTemplate = `protocol bgp node_%d from bgp_template {
  neighbor %s as 64512;
  passive on;
}

`

// BIRDRoute represents a single BIRD route entry for a /32 prefix.
type BIRDRoute struct {
	NextHop   string `json:"nextHop"`
	LocalPref int    `json:"localPref"`
	Community string `json:"community"`
	Best      bool   `json:"best"`
}

// PrefixState captures whether a prefix is present in BIRD and its routes.
type PrefixState struct {
	Present bool        `json:"present"`
	Routes  []BIRDRoute `json:"routes"`
}

// RouteState captures the parsed state of a /32 route on an external BIRD
// peer's routing table, including all candidate routes and the kernel next hop.
type RouteState struct {
	Has32         bool        `json:"has32"`
	Routes        []BIRDRoute `json:"routes"`
	KernelNextHop string      `json:"kernelNextHop"`
}

// RouteSnapshot captures the full route picture at a point in time:
// the /32 host route (elevated during migration), the /26 block route
// (steady-state subnet route), and the kernel next-hop for the VM IP.
type RouteSnapshot struct {
	Host32    PrefixState `json:"host32"`
	Block26   PrefixState `json:"block26"`
	KernelVia string      `json:"kernelVia"`
}

// BIRDPeer abstracts the transport layer for an external BIRD peer used in
// eBGP live migration tests. Both ContainerBIRDPeer (local Docker) and
// SSHBIRDPeer (SSH to an external node) implement this interface.
type BIRDPeer interface {
	// PeerIP returns the IP address to use in the Calico BGPPeer resource.
	PeerIP() string
	// ConfigureBIRD applies the BIRD peers configuration and ensures BIRD is
	// running with the new config. Implementations handle ip@local substitution,
	// merge-paths enablement, and BIRD reload internally.
	ConfigureBIRD(peersConf string)
	// CheckBGPSession returns the output of "birdcl show protocols" for
	// verifying BGP session establishment.
	CheckBGPSession() (string, error)
	// QueryRoute queries the BIRD routing table for a /32 route and returns
	// the parsed route state.
	QueryRoute(vmIP string) RouteState
	// QuerySnapshot queries the BIRD routing table for both the /32 host
	// route and the /26 block route.
	QuerySnapshot(vmIP string) RouteSnapshot
}

// ParseBIRDRouteOutput parses the output of "birdcl show route <prefix> all"
// and returns the list of routes. Returns nil if the output contains
// "Network not in table" or is empty.
func ParseBIRDRouteOutput(output string) []BIRDRoute {
	if strings.Contains(output, "Network not in table") {
		return nil
	}

	var routes []BIRDRoute
	var current *BIRDRoute
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimRight(line, "\r")
		trimmed := strings.TrimSpace(line)

		if trimmed == "" || strings.HasPrefix(trimmed, "BIRD") {
			continue
		}

		// Route line: contains "via" but is not a BGP attribute.
		if strings.Contains(line, " via ") && !strings.HasPrefix(trimmed, "BGP.") {
			r := BIRDRoute{}
			if idx := strings.Index(line, " via "); idx >= 0 {
				fields := strings.Fields(line[idx+5:])
				if len(fields) > 0 {
					r.NextHop = fields[0]
				}
			}
			// BIRD marks the active/best route with " * " (space-asterisk-space)
			// in the output line, e.g.:
			//   10.244.0.64/32     via 172.16.8.2 on eth0 * [bgp_node0 16:22:38] (100/0) [AS65000i]
			//                      via 172.16.8.4 on eth0 [bgp_node2 16:21:49] (100/0) [AS65000i]
			// Match the standalone token rather than substring " * " elsewhere
			// in the line (e.g. interface names containing "*" or AS-path
			// expressions) so we never wrongly mark a non-best route as best.
			r.Best = false
			for _, tok := range strings.Fields(line) {
				if tok == "*" {
					r.Best = true
					break
				}
			}
			routes = append(routes, r)
			current = &routes[len(routes)-1]
			continue
		}

		// BGP attribute lines.
		if current != nil {
			if strings.HasPrefix(trimmed, "BGP.local_pref:") {
				val := strings.TrimSpace(strings.TrimPrefix(trimmed, "BGP.local_pref:"))
				if _, err := fmt.Sscanf(val, "%d", &current.LocalPref); err != nil {
					logrus.Warnf("ParseBIRDRouteOutput: failed to parse BGP.local_pref %q: %v", val, err)
				}
			} else if strings.HasPrefix(trimmed, "BGP.community:") {
				current.Community = strings.TrimSpace(strings.TrimPrefix(trimmed, "BGP.community:"))
			}
		}
	}
	return routes
}

// GenerateBIRDPeersConf renders a BIRD 1.x peers config. podCIDR gates the
// import filter; pass the cluster's IPv4 IPPool CIDR.
func GenerateBIRDPeersConf(podCIDR string, nodeIPs []string) string {
	var sb strings.Builder
	fmt.Fprintf(&sb, birdHeaderTemplate, podCIDR)
	for i, nodeIP := range nodeIPs {
		sb.WriteString(fmt.Sprintf(birdPeerTemplate, i, nodeIP))
	}
	return sb.String()
}

// ---------------------------------------------------------------------------
// ContainerBIRDPeer — local Docker container transport
// ---------------------------------------------------------------------------

// ContainerBIRDPeer interacts with a pre-existing BIRD 1.x Docker container.
// The container is created by infrastructure setup (e.g. make e2e-test-mockvirt)
// and its name is passed via the BIRD_BGPPEER_CONTAINER_NAME environment variable.
// Uses local Docker commands so no external node or SSH credentials are required.
type ContainerBIRDPeer struct {
	containerName string
	containerIP   string
}

// NewContainerBIRDPeer discovers a pre-existing BIRD container by name from the
// BIRD_BGPPEER_CONTAINER_NAME environment variable and returns a handle for interacting
// with it. The container must already be running; infrastructure setup (e.g.
// make e2e-test-mockvirt) is responsible for creating and destroying it.
func NewContainerBIRDPeer() *ContainerBIRDPeer {
	GinkgoHelper()

	name := os.Getenv("BIRD_BGPPEER_CONTAINER_NAME")
	Expect(name).NotTo(BeEmpty(),
		"BIRD_BGPPEER_CONTAINER_NAME must be set to the name of a running BIRD container")

	// Verify the container is running.
	out, err := exec.Command("docker", "inspect", "-f", "{{.State.Running}}", name).CombinedOutput()
	Expect(err).NotTo(HaveOccurred(),
		"BIRD container %s not found: %s", name, string(out))
	Expect(strings.TrimSpace(string(out))).To(Equal("true"),
		"BIRD container %s is not running", name)

	// Get the container IP.
	ipOut, err := exec.Command("docker", "inspect", "-f",
		"{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}", name).CombinedOutput()
	Expect(err).NotTo(HaveOccurred(), "failed to get IP of container %s", name)
	containerIP := strings.TrimSpace(string(ipOut))
	Expect(containerIP).NotTo(BeEmpty(), "container %s has no IP address", name)

	logrus.Infof("Using pre-existing BIRD container %s with IP %s", name, containerIP)
	return &ContainerBIRDPeer{containerName: name, containerIP: containerIP}
}

// PeerIP returns the container IP for the Calico BGPPeer resource.
func (p *ContainerBIRDPeer) PeerIP() string { return p.containerIP }

// CheckBGPSession returns the output of "birdcl show protocols".
func (p *ContainerBIRDPeer) CheckBGPSession() (string, error) {
	return p.exec("birdcl", "show", "protocols")
}

// ConfigureBIRD writes the peers config, enables merge paths, and reloads BIRD.
func (p *ContainerBIRDPeer) ConfigureBIRD(peersConf string) {
	GinkgoHelper()

	// Enable merge paths in the kernel protocol for ECMP support.
	out, err := p.exec("sed", "-i", "/protocol kernel {/a merge paths on;", "/etc/bird.conf")
	Expect(err).NotTo(HaveOccurred(),
		"failed to enable merge paths in BIRD: %s", out)

	// Replace the source address placeholder with the container's actual IP.
	peersConf = strings.ReplaceAll(peersConf, "ip@local", p.containerIP)
	p.writeFile("/etc/bird/peers.conf", peersConf)

	By("Reloading BIRD config")
	out, err = p.exec("birdcl", "configure")
	Expect(err).NotTo(HaveOccurred(), "birdcl configure failed: %s", out)
	logrus.Infof("birdcl configure: %s", out)
}

// QueryRoute queries the BIRD routing table for a /32 route and returns
// the parsed route state.
func (p *ContainerBIRDPeer) QueryRoute(vmIP string) RouteState {
	ip := strings.Split(vmIP, "/")[0]

	out, err := p.exec("birdcl", "show", "route", ip+"/32", "all")
	if err != nil {
		logrus.Warnf("ContainerBIRDPeer.QueryRoute: exec error: %v", err)
		return RouteState{}
	}

	var state RouteState
	state.Routes = ParseBIRDRouteOutput(out)
	state.Has32 = len(state.Routes) > 0
	return state
}

// QuerySnapshot queries the BIRD routing table for both the /32 host route
// and the /26 block route via local docker exec.
func (p *ContainerBIRDPeer) QuerySnapshot(vmIP string) RouteSnapshot {
	ip := strings.Split(vmIP, "/")[0]

	parsed := net.ParseIP(ip).To4()
	if parsed == nil {
		return RouteSnapshot{}
	}
	blockIP := net.IPv4(parsed[0], parsed[1], parsed[2], parsed[3]&0xC0)
	block26 := fmt.Sprintf("%s/26", blockIP)

	// Query /32 route.
	out32, _ := p.exec("birdcl", "show", "route", ip+"/32", "all")
	routes32 := ParseBIRDRouteOutput(out32)

	// Query /26 route.
	out26, _ := p.exec("birdcl", "show", "route", block26, "all")
	routes26 := ParseBIRDRouteOutput(out26)

	snap := RouteSnapshot{
		Host32:  PrefixState{Present: len(routes32) > 0, Routes: routes32},
		Block26: PrefixState{Present: len(routes26) > 0, Routes: routes26},
	}

	logrus.Infof("ContainerBIRDPeer.QuerySnapshot(%s): /32=%v(%d) /26=%v(%d)",
		ip, snap.Host32.Present, len(snap.Host32.Routes),
		snap.Block26.Present, len(snap.Block26.Routes))
	return snap
}

// exec runs a command inside the BIRD container and returns stdout+stderr.
func (p *ContainerBIRDPeer) exec(args ...string) (string, error) {
	cmdArgs := append([]string{"exec", p.containerName}, args...)
	out, err := exec.Command("docker", cmdArgs...).CombinedOutput()
	return string(out), err
}

// writeFile writes content to a file inside the container via docker exec.
func (p *ContainerBIRDPeer) writeFile(path, content string) {
	GinkgoHelper()
	cmdArgs := []string{"exec", "-i", p.containerName, "sh", "-c", fmt.Sprintf("cat > %s", path)}
	cmd := exec.Command("docker", cmdArgs...)
	cmd.Stdin = strings.NewReader(content)
	out, err := cmd.CombinedOutput()
	Expect(err).NotTo(HaveOccurred(),
		"failed to write %s in container %s: %s", path, p.containerName, string(out))
}

// ---------------------------------------------------------------------------
// SSHBIRDPeer — SSH-based external node transport
// ---------------------------------------------------------------------------

// SSHBIRDPeer wraps an externalnode.Client to implement BIRDPeer for
// SSH-based external nodes (e.g. a TOR switch).
type SSHBIRDPeer struct {
	node   *externalnode.Client
	peerIP string // IP on the BGP subnet (e.g. L2TP IP)
}

// NewSSHBIRDPeer creates an SSHBIRDPeer for the given external node client
// and peer IP address.
func NewSSHBIRDPeer(node *externalnode.Client, peerIP string) *SSHBIRDPeer {
	return &SSHBIRDPeer{node: node, peerIP: peerIP}
}

func (a *SSHBIRDPeer) PeerIP() string { return a.peerIP }

func (a *SSHBIRDPeer) ConfigureBIRD(peersConf string) {
	a.startBIRD(peersConf)
}

func (a *SSHBIRDPeer) CheckBGPSession() (string, error) {
	return a.node.RunInContainer("tor-bird", "birdcl", "show", "protocols")
}

// QueryRoute returns the /32 BIRD route state plus the kernel next-hop.
// Called from polling loops, so it does not log per-call: callers log
// snapshots themselves.
func (a *SSHBIRDPeer) QueryRoute(vmIP string) RouteState {
	ip := strings.Split(vmIP, "/")[0]

	out, err := a.runCmd(fmt.Sprintf(
		"sudo docker exec tor-bird birdcl show route %s/32 all 2>&1", ip))
	if err != nil {
		logrus.Warnf("SSHBIRDPeer.QueryRoute: SSH error: %v", err)
		return RouteState{}
	}

	var state RouteState
	state.Routes = ParseBIRDRouteOutput(out)
	state.Has32 = len(state.Routes) > 0

	// Query kernel route for the active next hop.
	kernOut, _ := a.runCmd(fmt.Sprintf("ip route get %s 2>&1", ip))
	if idx := strings.Index(kernOut, "via "); idx >= 0 {
		fields := strings.Fields(kernOut[idx+4:])
		if len(fields) > 0 {
			state.KernelNextHop = fields[0]
		}
	}

	return state
}

// QuerySnapshot queries the BIRD routing table for both the /32 host route
// and the /26 block route, plus the kernel next-hop. This captures the full
// route picture at a point in time with a single SSH call.
func (a *SSHBIRDPeer) QuerySnapshot(vmIP string) RouteSnapshot {
	ip := strings.Split(vmIP, "/")[0]

	parsed := net.ParseIP(ip).To4()
	if parsed == nil {
		return RouteSnapshot{}
	}
	blockIP := net.IPv4(parsed[0], parsed[1], parsed[2], parsed[3]&0xC0)
	block26 := fmt.Sprintf("%s/26", blockIP)

	// Single SSH call with section markers.
	cmd := fmt.Sprintf(
		"echo '=== /32 ==='; sudo docker exec tor-bird birdcl show route %s/32 all 2>&1; "+
			"echo '=== /26 ==='; sudo docker exec tor-bird birdcl show route %s all 2>&1; "+
			"echo '=== kernel ==='; ip route get %s 2>&1",
		ip, block26, ip)
	out, err := a.runCmd(cmd)
	if err != nil {
		logrus.Warnf("SSHBIRDPeer.QuerySnapshot: SSH error: %v", err)
		return RouteSnapshot{}
	}

	var snap RouteSnapshot

	sections := strings.Split(out, "=== ")
	for _, sec := range sections {
		switch {
		case strings.HasPrefix(sec, "/32 ==="):
			body := strings.TrimPrefix(sec, "/32 ===")
			routes := ParseBIRDRouteOutput(body)
			snap.Host32 = PrefixState{Present: len(routes) > 0, Routes: routes}
		case strings.HasPrefix(sec, "/26 ==="):
			body := strings.TrimPrefix(sec, "/26 ===")
			routes := ParseBIRDRouteOutput(body)
			snap.Block26 = PrefixState{Present: len(routes) > 0, Routes: routes}
		case strings.HasPrefix(sec, "kernel ==="):
			body := strings.TrimPrefix(sec, "kernel ===")
			if idx := strings.Index(body, "via "); idx >= 0 {
				fields := strings.Fields(body[idx+4:])
				if len(fields) > 0 {
					snap.KernelVia = fields[0]
				}
			}
		}
	}

	logrus.Infof("SSHBIRDPeer.QuerySnapshot(%s): /32=%v(%d) /26=%v(%d) kernelVia=%s",
		ip, snap.Host32.Present, len(snap.Host32.Routes),
		snap.Block26.Present, len(snap.Block26.Routes), snap.KernelVia)
	return snap
}

// runCmd runs a shell command on the external node and returns stdout plus any
// wrapped error.
func (a *SSHBIRDPeer) runCmd(cmd string) (string, error) {
	out, err := a.node.Exec("sh", "-c", cmd)
	if err != nil {
		return out, fmt.Errorf("SSH cmd %q failed: %w (output=%q)", cmd, err, out)
	}
	return out, nil
}

// startBIRD launches a calico/bird container on the external node, applies the
// per-test peer config, and registers cleanup.
func (a *SSHBIRDPeer) startBIRD(peersConf string) {
	GinkgoHelper()
	By("Starting BIRD container on SSH node")

	_ = a.node.RemoveContainer("tor-bird")

	// The calico/bird image ships with a base bird.conf that defines router
	// id, protocol kernel, and protocol device, plus an include for
	// /etc/bird/*.conf so peers.conf is picked up on reload.
	_, err := a.node.RunContainer("tor-bird", images.CalicoBIRD,
		[]string{"-d", "--privileged", "--network", "host"})
	Expect(err).NotTo(HaveOccurred(), "failed to start BIRD container on SSH node")
	// Register cleanup before the readiness wait so a panic still removes
	// the container we just created.
	DeferCleanup(func() { a.stopBIRD() })

	Eventually(func() (bool, error) {
		return a.node.IsContainerRunning("tor-bird")
	}, 30*time.Second, 2*time.Second).Should(BeTrue(), "tor-bird container is not running")

	// Add "merge paths on" to the kernel protocol block for ECMP support.
	// With different BIRD preferences (200 for community-tagged, 100 for
	// default), merge paths only merges routes of equal preference, so the
	// higher-preference route wins during migration.
	_, err = a.node.RunInContainer("tor-bird", "sed", "-i",
		"'/protocol kernel {/a merge paths on;'", "/etc/bird.conf")
	Expect(err).NotTo(HaveOccurred(), "failed to enable merge paths in tor-bird")

	peersConf = strings.ReplaceAll(peersConf, "ip@local", a.peerIP)
	Expect(a.node.WriteFileInContainer("tor-bird", "/etc/bird/peers.conf", []byte(peersConf))).
		To(Succeed(), "failed to write BIRD peers config")

	By("Reloading BIRD config on SSH node")
	out, err := a.node.RunInContainer("tor-bird", "birdcl", "configure")
	Expect(err).NotTo(HaveOccurred(), "birdcl configure failed: %s", out)
	logrus.Infof("birdcl configure: %s", out)
}

// stopBIRD removes the BIRD container from the external node.
func (a *SSHBIRDPeer) stopBIRD() {
	By("Stopping BIRD on SSH node")
	_ = a.node.RemoveContainer("tor-bird")
}
