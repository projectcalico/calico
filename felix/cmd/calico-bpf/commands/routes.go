// Copyright (c) 2019-2020 Tigera, Inc. All rights reserved.
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

package commands

import (
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/projectcalico/calico/felix/bpf/maps"
	"github.com/projectcalico/calico/felix/bpf/routes"
	"github.com/projectcalico/calico/felix/ip"
)

func init() {
	// Register parent "routes" command and its subcommands.
	routesCmd.AddCommand(newAddCmd())
	routesCmd.AddCommand(newDelCmd())
	routesCmd.AddCommand(routesDumpCmd)
	rootCmd.AddCommand(routesCmd)
}

var routesDumpCmd = &cobra.Command{
	Use:   "dump",
	Short: "dumps routes",
	Run: func(cmd *cobra.Command, args []string) {
		// The existing code used the global 'ipv6' flag; preserve that behavior.
		if err := dumpRoutes(); err != nil {
			log.WithError(err).Error("Failed to dump routes map.")
		}
	},
}

// routesCmd represents the routes parent command
var routesCmd = &cobra.Command{
	Use:   "routes",
	Short: "Manipulates routes",
}

func dumpRoutes() error {
	var routesMap maps.Map

	if ipv6 != nil && *ipv6 {
		routesMap = routes.MapV6()
	} else {
		routesMap = routes.Map()
	}

	if err := routesMap.Open(); err != nil {
		return errors.WithMessage(err, "failed to open map")
	}
	defer routesMap.Close()

	var dests []ip.CIDR
	valueByDest := map[ip.CIDR]routes.ValueInterface{}

	err := routesMap.Iter(func(k, v []byte) maps.IteratorAction {
		var key routes.KeyInterface
		var value routes.ValueInterface

		if ipv6 != nil && *ipv6 {
			var kk routes.KeyV6
			var vv routes.ValueV6
			copy(kk[:], k)
			copy(vv[:], v)

			key = kk
			value = vv
		} else {
			var kk routes.Key
			var vv routes.Value
			copy(kk[:], k)
			copy(vv[:], v)

			key = kk
			value = vv
		}

		dest := key.Dest()
		valueByDest[dest] = value
		dests = append(dests, dest)
		return maps.IterNone
	})
	if err != nil {
		return err
	}

	if ipv6 != nil && *ipv6 {
		sortCIDRsV6(dests)
	} else {
		sortCIDRs(dests)
	}

	for _, dest := range dests {
		v := valueByDest[dest]
		fmt.Printf("%15v: %s\n", dest, v)
	}

	return nil
}

func sortCIDRs(cidrs []ip.CIDR) {
	sort.Slice(cidrs, func(i, j int) bool {
		addrA := cidrs[i].Addr().(ip.V4Addr)
		addrB := cidrs[j].Addr().(ip.V4Addr)
		for byteIdx := 0; byteIdx < 4; byteIdx++ {
			if addrA[byteIdx] < addrB[byteIdx] {
				return true
			}
			if addrA[byteIdx] > addrB[byteIdx] {
				return false
			}
		}
		return cidrs[i].Prefix() < cidrs[j].Prefix()
	})
}

func sortCIDRsV6(cidrs []ip.CIDR) {
	sort.Slice(cidrs, func(i, j int) bool {
		addrA := cidrs[i].Addr().(ip.V6Addr)
		addrB := cidrs[j].Addr().(ip.V6Addr)
		for byteIdx := 0; byteIdx < 16; byteIdx++ {
			if addrA[byteIdx] < addrB[byteIdx] {
				return true
			}
			if addrA[byteIdx] > addrB[byteIdx] {
				return false
			}
		}
		return cidrs[i].Prefix() < cidrs[j].Prefix()
	})
}

// routeCmd holds the parsed CLI args for add/del subcommands.
type routeCmd struct {
	IP      string
	NextHop string
	IfIndex string

	// Typed flags:
	WorkloadType string // "local" or "remote"
	HostType     string // "local" or "remote"
	Tunneled     bool

	// Parsed values
	cidr   ip.CIDR
	nexth  ip.Addr
	ifIdx  int
	isV6   bool
	flags  routes.Flags
	mapObj maps.Map
}

func newAddCmd() *cobra.Command {
	rc := &routeCmd{}
	cmd := &cobra.Command{
		Use:   "add <ip|cidr> [--nexthop <ip>] [--ifindex <idx>] [--workload <local|remote>|--host <local|remote>] [--tunneled]",
		Short: "Add an entry to the BPF routes map",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			rc.IP = args[0]
			return rc.run("add")
		},
	}

	// Flags for add
	cmd.Flags().StringVar(&rc.NextHop, "nexthop", "", "Next hop IP for route (remote routes)")
	cmd.Flags().StringVar(&rc.IfIndex, "ifindex", "", "Interface index for local routes")
	cmd.Flags().StringVar(&rc.WorkloadType, "workload", "", "Mark route as workload: specify 'local' or 'remote'")
	cmd.Flags().StringVar(&rc.HostType, "host", "", "Mark route as host: specify 'local' or 'remote'")
	cmd.Flags().BoolVar(&rc.Tunneled, "tunneled", false, "Mark route as tunneled")

	return cmd
}

func newDelCmd() *cobra.Command {
	rc := &routeCmd{}
	cmd := &cobra.Command{
		Use:   "del <ip|cidr>",
		Short: "Delete an entry from the BPF routes map (by CIDR only)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			rc.IP = args[0]
			// For delete we only accept IP/CIDR and ignore any additional flags.
			return rc.run("del")
		},
	}

	// Intentionally do NOT add flags for del: delete accepts only the IP/CIDR.
	return cmd
}

func (r *routeCmd) openMapForFamily(isV6 bool) error {
	if isV6 {
		r.mapObj = routes.MapV6()
	} else {
		r.mapObj = routes.Map()
	}
	if r.mapObj == nil {
		return fmt.Errorf("failed to create routes map object")
	}
	if err := r.mapObj.Open(); err != nil {
		return fmt.Errorf("failed to open routes map: %w", err)
	}
	return nil
}

// parseInputs validates and parses inputs. Behavior varies by op:
//   - op == "add": require at least one of --workload or --host and validate flags.
//   - op == "del": only parse IP/CIDR and family; ignore flags.
func (r *routeCmd) parseInputs(op string) error {
	// Parse CIDR/IP and set address family.
	cidr, err := ip.ParseCIDROrIP(r.IP)
	if err != nil {
		return fmt.Errorf("invalid ip/cidr %q: %w", r.IP, err)
	}
	r.cidr = cidr
	r.isV6 = (cidr.Version() == 6)

	// For delete, we only need the CIDR/family. Ignore flags.
	if op == "del" {
		return nil
	}

	// Next hop parse if provided.
	if r.NextHop != "" {
		nh := ip.FromString(r.NextHop)
		if nh == nil {
			return fmt.Errorf("invalid nexthop IP %q", r.NextHop)
		}
		r.nexth = nh
	}

	// IfIndex parse if provided.
	if r.IfIndex != "" {
		i, err := strconv.Atoi(r.IfIndex)
		if err != nil {
			return fmt.Errorf("invalid ifindex: %w", err)
		}
		r.ifIdx = i
	}

	normalize := func(s string) string { return strings.ToLower(strings.TrimSpace(s)) }

	if r.WorkloadType != "" {
		rt := normalize(r.WorkloadType)
		if rt != "local" && rt != "remote" {
			return fmt.Errorf("invalid --workload value %q; must be 'local' or 'remote'", r.WorkloadType)
		}
		r.WorkloadType = rt
	}
	if r.HostType != "" {
		rt := normalize(r.HostType)
		if rt != "local" && rt != "remote" {
			return fmt.Errorf("invalid --host value %q; must be 'local' or 'remote'", r.HostType)
		}
		r.HostType = rt
	}

	// For add, require at least one type specified.
	if op == "add" {
		if r.WorkloadType == "" && r.HostType == "" {
			return errors.New("for add: one of --workload or --host must be specified (use 'local' or 'remote')")
		}
	}

	// If either type is 'local', require ifindex.
	if r.WorkloadType == "local" || r.HostType == "local" {
		if r.ifIdx == 0 {
			return errors.New("local routes require --ifindex to be specified and non-zero")
		}
	}
	// If either type is 'remote', require nexthop.
	if r.WorkloadType == "remote" || r.HostType == "remote" {
		if r.nexth == nil {
			return errors.New("remote routes require --nexthop to be specified")
		}
	}

	// Build routes.Flags
	var f routes.Flags
	if r.WorkloadType != "" {
		f |= routes.FlagWorkload
		if r.WorkloadType == "local" {
			f |= routes.FlagLocal
		}
	}
	if r.HostType != "" {
		f |= routes.FlagHost
		if r.HostType == "local" {
			f |= routes.FlagLocal
		}
	}
	if r.Tunneled {
		f |= routes.FlagTunneled
	}
	r.flags = f

	return nil
}

func (r *routeCmd) makeKeyAndValue() (routes.KeyInterface, routes.ValueInterface, error) {
	// Select constructors for IPv4/IPv6
	var key routes.KeyInterface
	var val routes.ValueInterface

	if r.isV6 {
		key = routes.NewKeyV6Intf(r.cidr)
		// value constructors for v6
		if r.ifIdx != 0 {
			val = routes.NewValueV6IntfWithIfIndex(r.flags, r.ifIdx)
			return key, val, nil
		}
		if r.nexth != nil {
			val = routes.NewValueV6IntfWithNextHop(r.flags, r.nexth)
			return key, val, nil
		}
		val = routes.NewValueV6Intf(r.flags)
		return key, val, nil
	}

	// IPv4 path
	key = routes.NewKeyIntf(r.cidr)
	if r.ifIdx != 0 {
		val = routes.NewValueIntfWithIfIndex(r.flags, r.ifIdx)
		return key, val, nil
	}
	if r.nexth != nil {
		val = routes.NewValueIntfWithNextHop(r.flags, r.nexth)
		return key, val, nil
	}
	val = routes.NewValueIntf(r.flags)
	return key, val, nil
}

func (r *routeCmd) makeKey() routes.KeyInterface {
	if r.isV6 {
		return routes.NewKeyV6Intf(r.cidr)
	}
	return routes.NewKeyIntf(r.cidr)
}

func (r *routeCmd) run(op string) error {
	// Parse and validate inputs (for del we only parse IP/CIDR).
	if err := r.parseInputs(op); err != nil {
		return err
	}
	// Open appropriate map
	if err := r.openMapForFamily(r.isV6); err != nil {
		return err
	}
	defer func() {
		_ = r.mapObj.Close()
	}()

	// Build key (always) and value (for add)
	key := r.makeKey()

	switch op {
	case "add":
		// For add, build value and update.
		_, val, err := r.makeKeyAndValue()
		if err != nil {
			return err
		}
		if val == nil {
			return errors.New("failed to construct route value")
		}
		if err := r.mapObj.Update(key.AsBytes(), val.AsBytes()); err != nil {
			return fmt.Errorf("failed to update routes map: %w", err)
		}
		fmt.Fprintf(os.Stdout, "added route %s\n", r.cidr.String())
		return nil
	case "del", "delete", "remove":
		// For delete, only the key (CIDR) is used.
		if err := r.mapObj.Delete(key.AsBytes()); err != nil {
			return fmt.Errorf("failed to delete route from map: %w", err)
		}
		fmt.Fprintf(os.Stdout, "deleted route %s\n", r.cidr.String())
		return nil
	default:
		return fmt.Errorf("unknown op %q (use add|del|dump)", op)
	}
}
