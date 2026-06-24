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

// Package iputils runs the `ip` utility somewhere a test can exec — a
// container, a workload netns, a calico-node pod — and parses its JSON output
// (`ip -j ...`) into typed structs.
//
// It is shared test tooling: anything that can run a command and return its
// stdout satisfies the one-method Runner interface, so the same helpers serve
// Felix FV (where *infrastructure.Felix / *workload.Workload are Runners) and
// node k8st (where a thin adapter over kubectl-exec is a Runner). The package
// itself depends only on the standard library.
//
// Tests historically shelled out to `ip` and scraped the human-readable output
// with strings.Fields / regexps / ContainSubstring matchers, which is brittle:
// the column layout changes between iproute2 versions and the same substring
// can match unrelated fields. Asking `ip` for JSON and decoding it into structs
// is stable and self-documenting.
//
// Typical use:
//
//	link, err := iputils.New(felix).Detailed().LinkShowDev("wireguard.cali")
//	addrs, err := iputils.New(felix).V6().AddrShow("dev", "eth0", "scope", "global")
//	routes, err := iputils.New(felix).Routes(iputils.WithTable("all"), iputils.WithDevice(iface))
package iputils

import (
	"encoding/json"
	"fmt"
	"net"
	"slices"
	"strconv"
	"strings"
)

// Runner executes a command and returns its stdout. The leading "ip" argument
// is supplied by this package, so a Runner only needs to prepend its own
// exec wrapper (docker exec, ip netns exec, ...) to the args.
//
// Both *containers.Container — and therefore *infrastructure.Felix, which
// embeds it — and *workload.Workload satisfy this via their ExecOutput method.
type Runner interface {
	ExecOutput(args ...string) (string, error)
}

// IP is a thin, JSON-parsing wrapper around the `ip` utility. Construct it with
// New; select an address family with V4/V6/Family and request verbose device
// details with Detailed. The selector methods return a copy, so a base IP can
// be reused:
//
//	ip := iputils.New(felix)
//	v4Addrs, _ := ip.V4().AddrShow("dev", "eth0")
//	v6Addrs, _ := ip.V6().AddrShow("dev", "eth0")
type IP struct {
	runner  Runner
	family  string // "", "-4" or "-6"
	details bool
}

// New returns an IP that runs commands via r.
func New(r Runner) *IP {
	return &IP{runner: r}
}

// V4 restricts subsequent commands to IPv4 (`ip -4 ...`).
func (i *IP) V4() *IP {
	c := *i
	c.family = "-4"
	return &c
}

// V6 restricts subsequent commands to IPv6 (`ip -6 ...`).
func (i *IP) V6() *IP {
	c := *i
	c.family = "-6"
	return &c
}

// Family selects IPv6 when v6 is true and IPv4 otherwise.
func (i *IP) Family(v6 bool) *IP {
	if v6 {
		return i.V6()
	}
	return i.V4()
}

// Detailed adds `-d` so that link output includes the linkinfo block (tunnel,
// WireGuard, bond, ... details).
func (i *IP) Detailed() *IP {
	c := *i
	c.details = true
	return &c
}

// run executes `ip -j [flags] <args...>` and decodes the JSON into out.
func (i *IP) run(out any, args ...string) error {
	full := []string{"ip", "-j"}
	if i.details {
		full = append(full, "-d")
	}
	if i.family != "" {
		full = append(full, i.family)
	}
	full = append(full, args...)

	s, err := i.runner.ExecOutput(full...)
	if err != nil {
		return fmt.Errorf("running %q: %w (output: %q)", strings.Join(full, " "), err, s)
	}
	s = strings.TrimSpace(s)
	if s == "" {
		// Some `ip` subcommands/versions print nothing rather than "[]" for an
		// empty result; treat that as a valid empty list and leave out as its
		// zero value.
		return nil
	}
	if err := json.Unmarshal([]byte(s), out); err != nil {
		return fmt.Errorf("parsing JSON output of %q (output: %q): %w", strings.Join(full, " "), s, err)
	}
	return nil
}

// AddrShow runs `ip addr show <args...>` (e.g. "dev", "eth0", "scope",
// "global") and returns the matching links, each with its AddrInfo populated.
func (i *IP) AddrShow(args ...string) ([]Link, error) {
	var links []Link
	err := i.run(&links, append([]string{"addr", "show"}, args...)...)
	return links, err
}

// AddrShowDev is shorthand for `ip addr show dev <dev>`, returning the single
// matching link. It errors if the device is not found.
func (i *IP) AddrShowDev(dev string) (Link, error) {
	links, err := i.AddrShow("dev", dev)
	if err != nil {
		return Link{}, err
	}
	if len(links) == 0 {
		return Link{}, fmt.Errorf("no link found for device %q", dev)
	}
	return links[0], nil
}

// LinkShow runs `ip link show <args...>` and returns the matching links.
func (i *IP) LinkShow(args ...string) ([]Link, error) {
	var links []Link
	err := i.run(&links, append([]string{"link", "show"}, args...)...)
	return links, err
}

// LinkShowDev is shorthand for `ip link show dev <dev>`, returning the single
// matching link. It errors if the device is not found.
func (i *IP) LinkShowDev(dev string) (Link, error) {
	links, err := i.LinkShow("dev", dev)
	if err != nil {
		return Link{}, err
	}
	if len(links) == 0 {
		return Link{}, fmt.Errorf("no link found for device %q", dev)
	}
	return links[0], nil
}

// Routes runs `ip route show`, narrowed by the given filters, and returns the
// matching routes. The filters map to the kernel-side selectors that
// `ip route show` understands, so the kernel does the filtering, e.g.:
//
//	routes, err := iputils.New(felix).Routes(
//		iputils.WithDestination("10.65.0.2/32"),
//		iputils.WithTable("all"),
//		iputils.WithDevice(iface),
//	)
func (i *IP) Routes(filters ...RouteFilter) ([]Route, error) {
	var f routeFilter
	for _, apply := range filters {
		apply(&f)
	}
	var routes []Route
	err := i.run(&routes, append([]string{"route", "show"}, f.args...)...)
	return routes, err
}

// RouteFilter narrows a Routes query to a subset of the routing table. Filters
// are applied in the order given; pass none to list every route.
type RouteFilter func(*routeFilter)

type routeFilter struct {
	args []string
}

// WithDestination filters to routes whose destination matches dst — an address
// or CIDR, e.g. "10.65.0.2" or "dead:beef::/64" — i.e. `ip route show to <dst>`.
func WithDestination(dst string) RouteFilter {
	return func(f *routeFilter) { f.args = append(f.args, "to", dst) }
}

// WithTable filters to routes in the named routing table: a numeric id or one
// of the reserved names "all", "main", "local", "default", i.e.
// `ip route show table <table>`.
func WithTable(table string) RouteFilter {
	return func(f *routeFilter) { f.args = append(f.args, "table", table) }
}

// WithDevice filters to routes whose output device is dev, i.e.
// `ip route show dev <dev>`.
func WithDevice(dev string) RouteFilter {
	return func(f *routeFilter) { f.args = append(f.args, "dev", dev) }
}

// WithArgs is an escape hatch for `ip route show` selectors that have no
// dedicated filter (e.g. "proto", "kernel" or "scope", "link"). The args are
// appended verbatim.
func WithArgs(args ...string) RouteFilter {
	return func(f *routeFilter) { f.args = append(f.args, args...) }
}

// RouteGet runs `ip route get <dst> <args...>` and returns the resolved
// route(s) the kernel would use to reach dst.
func (i *IP) RouteGet(dst string, args ...string) ([]Route, error) {
	var routes []Route
	err := i.run(&routes, append([]string{"route", "get", dst}, args...)...)
	return routes, err
}

// NeighShow runs `ip neigh show <args...>` and returns the neighbour entries.
func (i *IP) NeighShow(args ...string) ([]Neigh, error) {
	var neighs []Neigh
	err := i.run(&neighs, append([]string{"neigh", "show"}, args...)...)
	return neighs, err
}

// RuleShow runs `ip rule show <args...>` and returns the policy routing rules.
func (i *IP) RuleShow(args ...string) ([]Rule, error) {
	var rules []Rule
	err := i.run(&rules, append([]string{"rule", "show"}, args...)...)
	return rules, err
}

// Link is one entry of `ip link show` / `ip addr show` output.
type Link struct {
	IfIndex   int      `json:"ifindex"`
	IfName    string   `json:"ifname"`
	Flags     []string `json:"flags"`
	MTU       int      `json:"mtu"`
	Qdisc     string   `json:"qdisc"`
	OperState string   `json:"operstate"`
	Group     string   `json:"group"`
	TxQLen    int      `json:"txqlen"`
	LinkType  string   `json:"link_type"`
	Address   string   `json:"address"`
	Broadcast string   `json:"broadcast"`
	Master    string   `json:"master"`
	// AddrInfo is populated by `ip addr show`; it is empty for `ip link show`.
	AddrInfo []AddrInfo `json:"addr_info"`
	// LinkInfo is populated by `ip -d link show` for virtual devices (tunnels,
	// WireGuard, bonds, ...); nil otherwise. Use Detailed() to request it.
	LinkInfo *LinkInfo `json:"linkinfo"`
}

// HasFlag reports whether the link carries the named flag (e.g. "UP",
// "LOWER_UP", "NOARP").
func (l Link) HasFlag(flag string) bool {
	return slices.Contains(l.Flags, flag)
}

// Kind returns the device kind from the detailed linkinfo (e.g. "wireguard",
// "vxlan", "ipip", "bond"), or "" if no detail was requested or the device is
// a plain physical/veth device.
func (l Link) Kind() string {
	if l.LinkInfo == nil {
		return ""
	}
	return l.LinkInfo.InfoKind
}

// LinkInfo is the `linkinfo` block of a detailed link.
type LinkInfo struct {
	InfoKind string          `json:"info_kind"`
	InfoData json.RawMessage `json:"info_data,omitempty"`
}

// AddrInfo is one address of a link's `addr_info` array.
type AddrInfo struct {
	Family    string `json:"family"` // "inet" or "inet6"
	Local     string `json:"local"`
	PrefixLen int    `json:"prefixlen"`
	Broadcast string `json:"broadcast"`
	Scope     string `json:"scope"`
	Label     string `json:"label"`
}

// CIDR returns the address in "local/prefixlen" form, e.g. "172.17.0.3/16".
func (a AddrInfo) CIDR() string {
	return fmt.Sprintf("%s/%d", a.Local, a.PrefixLen)
}

// Network returns the network the address belongs to (the address masked to
// its prefix length), e.g. AddrInfo{Local: "172.17.0.3", PrefixLen: 16} ->
// 172.17.0.0/16.
func (a AddrInfo) Network() (*net.IPNet, error) {
	_, n, err := net.ParseCIDR(a.CIDR())
	if err != nil {
		return nil, fmt.Errorf("parsing address %q: %w", a.CIDR(), err)
	}
	return n, nil
}

// Route is one entry of `ip route show` / `ip route get` output.
type Route struct {
	Type     string   `json:"type"` // "local", "unicast", "blackhole", ...; often absent
	Dst      string   `json:"dst"`  // "default" or a CIDR / host address
	Gateway  string   `json:"gateway"`
	Dev      string   `json:"dev"`
	Protocol string   `json:"protocol"`
	Scope    string   `json:"scope"`
	PrefSrc  string   `json:"prefsrc"`
	Metric   int      `json:"metric"`
	Table    string   `json:"table"`
	Flags    []string `json:"flags"`
}

// Proto returns the netlink protocol that owns the route, parsed from its
// Protocol field. See ParseRouteProto for the string-to-RouteProto mapping.
func (r Route) Proto() RouteProto {
	return ParseRouteProto(r.Protocol)
}

// RouteProto identifies the netlink protocol that owns a kernel route. The
// numeric values match the kernel's RTPROT_* constants. Felix-programmed
// routes carry protocol 80 (felix/dataplane/linux/dataplanedefs.DefaultRouteProto);
// BIRD-programmed routes carry protocol 12 (RTPROT_BIRD).
type RouteProto int

const (
	RouteProtoUnknown RouteProto = -1
	RouteProtoBIRD    RouteProto = 12
	RouteProtoFelix   RouteProto = 80
)

func (p RouteProto) String() string {
	switch p {
	case RouteProtoBIRD:
		return "bird"
	case RouteProtoFelix:
		return "felix"
	case RouteProtoUnknown:
		return "unknown"
	}
	return fmt.Sprintf("proto-%d", int(p))
}

// ParseRouteProto maps the protocol string from `ip -j route show` to a
// RouteProto. Protocol is a string in iproute2's JSON output regardless of
// whether the kernel proto has a name in /etc/iproute2/rt_protos: named protos
// appear as e.g. "bird"; unnamed appear as the decimal value (e.g. "80").
func ParseRouteProto(s string) RouteProto {
	switch s {
	case "":
		return RouteProtoUnknown
	case "bird":
		return RouteProtoBIRD
	}
	if n, err := strconv.Atoi(s); err == nil {
		return RouteProto(n)
	}
	return RouteProtoUnknown
}

// Neigh is one entry of `ip neigh show` output.
type Neigh struct {
	Dst    string   `json:"dst"`
	Dev    string   `json:"dev"`
	LLAddr string   `json:"lladdr"`
	State  []string `json:"state"`
}

// Rule is one entry of `ip rule show` output.
type Rule struct {
	Priority int    `json:"priority"`
	Src      string `json:"src"`
	Dst      string `json:"dst"`
	Table    string `json:"table"`
	IIf      string `json:"iif"`
	OIf      string `json:"oif"`
	FwMark   string `json:"fwmark"`
}
