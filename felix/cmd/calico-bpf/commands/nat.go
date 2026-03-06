// Copyright (c) 2020-2022 Tigera, Inc. All rights reserved.
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
	"bytes"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"

	"github.com/docopt/docopt-go"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/projectcalico/calico/felix/bpf/nat"
)

var natDumpGroupByService bool

func init() {
	natDumpCmd.Flags().BoolVar(&natDumpGroupByService, "group-by-service", false,
		"group frontends that share the same service ID and print their backends once per group")
	natCmd.AddCommand(natDumpCmd)
	natCmd.AddCommand(natAffDumpCmd)

	natSetCmd.AddCommand(newNatSetFrontend())
	natSetCmd.AddCommand(newNatSetBackend())
	natCmd.AddCommand(natSetCmd)

	natDelCmd.AddCommand(newNatDelFrontend())
	natDelCmd.AddCommand(newNatDelBackend())
	natCmd.AddCommand(natDelCmd)

	rootCmd.AddCommand(natCmd)
}

// conntrackCmd represents the conntrack command
var natCmd = &cobra.Command{
	Use:   "nat",
	Short: "Manipulates network address translation (nat)",
	Long: "nat manipulates network address translation (nat), " +
		"which implements the bpf-based replacement for kube-proxy",
}

var natDumpCmd = &cobra.Command{
	Use:   "dump [<ip> <port> <proto>]",
	Short: "dumps the nat tables",
	Args: func(cmd *cobra.Command, args []string) error {
		if len(args) != 0 && len(args) != 3 {
			return fmt.Errorf("accepts 0 or 3 args (<ip> <port> <proto>), received %d", len(args))
		}
		return nil
	},
	Run: func(cmd *cobra.Command, args []string) {
		if err := dump(cmd, args); err != nil {
			log.WithError(err).Error("Failed to dump NAT maps")
		}
	},
}

var natAffDumpCmd = &cobra.Command{
	Use:   "aff",
	Short: "dumps the affinity table",
	Run: func(cmd *cobra.Command, args []string) {
		if err := dumpAff(cmd); err != nil {
			log.WithError(err).Error("Failed to dump affinity map")
		}
	},
}

var natSetCmd = &cobra.Command{
	Use:   "set",
	Short: "sets an entry in the NAT tables",
}

var natDelCmd = &cobra.Command{
	Use:   "del",
	Short: "deletes an entry from the NAT tables",
}

func dumpAff(cmd *cobra.Command) (err error) {
	affMap, err := nat.LoadAffinityMap(nat.AffinityMap())
	if err != nil {
		return err
	}

	for k, v := range affMap {
		cmd.Printf("%-40s %s\n", k, v)
	}

	cmd.Printf("\n")

	return nil
}

func dump(cmd *cobra.Command, args []string) error {
	if ipv6 != nil && *ipv6 {
		natMap, err := nat.LoadFrontendMapV6(nat.FrontendMapV6())
		if err != nil {
			return err
		}

		back, err := nat.LoadBackendMapV6(nat.BackendMapV6())
		if err != nil {
			return err
		}

		filtered := map[nat.FrontendKeyV6]nat.FrontendValue(natMap)
		if len(args) == 3 {
			ip, port, proto, err := parseIPPortProto(args)
			if err != nil {
				return err
			}
			filtered, err = filterByServiceID(natMap, nat.NewNATKeyV6(ip, port, proto))
			if err != nil {
				return err
			}
		}

		dumpNice[nat.FrontendKeyV6, nat.BackendValueV6](cmd.Printf, filtered, back, natDumpGroupByService)
	} else {
		natMap, err := nat.LoadFrontendMap(nat.FrontendMap())
		if err != nil {
			return err
		}

		back, err := nat.LoadBackendMap(nat.BackendMap())
		if err != nil {
			return err
		}

		filtered := map[nat.FrontendKey]nat.FrontendValue(natMap)
		if len(args) == 3 {
			ip, port, proto, err := parseIPPortProto(args)
			if err != nil {
				return err
			}
			filtered, err = filterByServiceID(natMap, nat.NewNATKey(ip, port, proto))
			if err != nil {
				return err
			}
		}

		dumpNice[nat.FrontendKey, nat.BackendValue](cmd.Printf, filtered, back, natDumpGroupByService)
	}
	return nil
}

// parseIPPortProto parses a [<ip>, <port>, <proto>] slice into typed values.
// proto accepts "tcp", "udp", or a decimal/hex protocol number.
func parseIPPortProto(args []string) (net.IP, uint16, uint8, error) {
	ip := net.ParseIP(args[0])
	if ip == nil {
		return nil, 0, 0, fmt.Errorf("invalid IP address: %q", args[0])
	}

	portNum, err := strconv.ParseUint(args[1], 0, 16)
	if err != nil {
		return nil, 0, 0, fmt.Errorf("invalid port number: %q (must be 0-65535)", args[1])
	}

	var proto uint8
	switch strings.ToLower(args[2]) {
	case "udp":
		proto = 17
	case "tcp":
		proto = 6
	default:
		protoNum, err := strconv.ParseUint(args[2], 0, 8)
		if err != nil {
			return nil, 0, 0, fmt.Errorf("unknown protocol %q", args[2])
		}
		proto = uint8(protoNum)
	}

	return ip, uint16(portNum), proto, nil
}

// filterByServiceID returns all frontend entries whose service ID matches the
// service ID of the given filterKey.  This lets callers discover every virtual
// IP / port / protocol tuple that maps to the same set of backends.
func filterByServiceID[FK nat.FrontendKeyComparable](natMap map[FK]nat.FrontendValue, filterKey FK) (map[FK]nat.FrontendValue, error) {
	fv, ok := natMap[filterKey]
	if !ok {
		return nil, fmt.Errorf("frontend %v not found in NAT map", filterKey)
	}

	serviceID := fv.ID()

	result := make(map[FK]nat.FrontendValue)
	for k, v := range natMap {
		if v.ID() == serviceID {
			result[k] = v
		}
	}
	return result, nil
}

type printfFn func(format string, i ...any)

func dumpNice[FK nat.FrontendKeyComparable, BV nat.BackendValueInterface](printf printfFn,
	natMap map[FK]nat.FrontendValue, back map[nat.BackendKey]BV, groupByService bool) {
	if groupByService {
		dumpNiceGrouped(printf, natMap, back)
		return
	}

	for nk, nv := range natMap {
		valCount := nv.Count()
		count := int(valCount)
		if valCount == nat.BlackHoleCount {
			count = -1
		}
		local := nv.LocalCount()
		id := nv.ID()
		flags := nv.FlagsAsString()
		if flags != "" {
			flags = " flags " + flags
		}
		printf("%s port %d proto %d id %d count %d local %d%s",
			nk.Addr(), nk.Port(), nk.Proto(), id, count, local, flags)
		srcCIDR := nk.SrcCIDR()
		if srcCIDR.Prefix() != 0 {
			printf(" src %s", srcCIDR)
		}
		printf("\n")
		for i := 0; i < count; i++ {
			bk := nat.NewNATBackendKey(id, uint32(i))
			bv, ok := back[bk]
			printf("\t%d:%d\t ", id, i)
			if !ok {
				printf("is missing\n")
			} else {
				ep := net.JoinHostPort(bv.Addr().String(), fmt.Sprint(bv.Port()))
				printf("%s\n", ep)
			}
		}
	}
}

// dumpNiceGrouped groups frontends sharing the same service ID and prints their
// backends just once per group.  Frontend lines are printed first, then the
// indented backend list follows.
func dumpNiceGrouped[FK nat.FrontendKeyComparable, BV nat.BackendValueInterface](printf printfFn,
	natMap map[FK]nat.FrontendValue, back map[nat.BackendKey]BV) {
	// Group frontend keys by service ID so that siblings sharing the same
	// backend pool (e.g. ClusterIP + NodePort) are printed together and the
	// backend list is shown just once per group.
	byID := make(map[uint32][]FK)
	for nk := range natMap {
		id := natMap[nk].ID()
		byID[id] = append(byID[id], nk)
	}

	// Sort service IDs for deterministic output.
	ids := make([]uint32, 0, len(byID))
	for id := range byID {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })

	for _, id := range ids {
		keys := byID[id]
		// Sort frontend keys within the group for deterministic output.
		sort.Slice(keys, func(i, j int) bool {
			return bytes.Compare(keys[i].AsBytes(), keys[j].AsBytes()) < 0
		})

		// Print every frontend line in the group.
		var count int
		for _, nk := range keys {
			nv := natMap[nk]
			valCount := nv.Count()
			count = int(valCount)
			if valCount == nat.BlackHoleCount {
				count = -1
			}
			local := nv.LocalCount()
			flags := nv.FlagsAsString()
			if flags != "" {
				flags = " flags " + flags
			}
			printf("%s port %d proto %d id %d count %d local %d%s",
				nk.Addr(), nk.Port(), nk.Proto(), id, count, local, flags)
			srcCIDR := nk.SrcCIDR()
			if srcCIDR.Prefix() != 0 {
				printf(" src %s", srcCIDR)
			}
			printf("\n")
		}

		// Print the shared backend list once for the whole group.
		for i := 0; i < count; i++ {
			bk := nat.NewNATBackendKey(id, uint32(i))
			bv, ok := back[bk]
			printf("\t%d:%d\t ", id, i)
			if !ok {
				printf("is missing\n")
			} else {
				ep := net.JoinHostPort(bv.Addr().String(), fmt.Sprint(bv.Port()))
				printf("%s\n", ep)
			}
		}
	}
}

type natFrontend struct {
	*cobra.Command

	Proto string `docopt:"<proto>"`
	IP    string `docopt:"<ip>"`
	Port  string `docopt:"<port>"`
	ID    string `docopt:"<id>"`
	Count string `docopt:"<count>"`

	proto uint8
	ip    net.IP
	port  uint16
	id    uint32
	count uint32
}

func newNatSetFrontend() *cobra.Command {
	cmd := &natFrontend{
		Command: &cobra.Command{
			Use:   "front <ip> <port> <proto> <id> <count>",
			Short: "sets a NAT entry for frontend (virtual IP)",
		},
	}

	cmd.Args = cmd.ArgsSet
	cmd.Run = cmd.RunSet

	return cmd.Command
}

func (cmd *natFrontend) checkArgsCommon() error {
	switch proto := strings.ToLower(cmd.Proto); proto {
	case "udp":
		cmd.proto = 17
	case "tcp":
		cmd.proto = 6
	default:
		return fmt.Errorf("unknown protocol %s", proto)
	}

	cmd.ip = net.ParseIP(cmd.IP)
	if cmd.ip == nil {
		return fmt.Errorf("ip: %q is not an ip", cmd.IP)
	}

	port, err := strconv.ParseUint(cmd.Port, 0, 16)
	if err != nil {
		return fmt.Errorf("port: %q is not 16-bit uint", cmd.Port)
	}
	cmd.port = uint16(port)

	return nil
}

func (cmd *natFrontend) ArgsSet(c *cobra.Command, args []string) error {
	var err error

	a, err := docopt.ParseArgs(makeDocUsage(c), args, "")
	if err != nil {
		return err
	}

	err = a.Bind(cmd)
	if err != nil {
		return err
	}

	if err := cmd.checkArgsCommon(); err != nil {
		return err
	}

	id, err := strconv.ParseUint(cmd.ID, 0, 32)
	if err != nil {
		return fmt.Errorf("id: %q is not 32-bit uint", cmd.ID)
	}
	cmd.id = uint32(id)

	count, err := strconv.ParseUint(cmd.Count, 0, 16)
	if err != nil {
		return fmt.Errorf("count: %q is not 32-bit uint", cmd.Count)
	}
	cmd.count = uint32(count)

	return nil
}

func (cmd *natFrontend) RunSet(c *cobra.Command, _ []string) {
	natMap := nat.FrontendMap()
	if err := natMap.Open(); err != nil {
		log.WithError(err).Error("Failed to access NATMap")
	}
	k := nat.NewNATKey(cmd.ip, cmd.port, cmd.proto)
	v := nat.NewNATValue(cmd.id, cmd.count, 0, 0)
	if err := natMap.Update(k.AsBytes(), v.AsBytes()); err != nil {
		log.WithError(err).
			WithFields(log.Fields{
				"key":   k,
				"value": v,
			}).Error("Failed to update map entry")
	}
}

func newNatDelFrontend() *cobra.Command {
	cmd := &natFrontend{
		Command: &cobra.Command{
			Use:   "front <ip> <port> <proto>",
			Short: "deletes a NAT entry for frontend (virtual IP)",
		},
	}

	cmd.Args = cmd.ArgsDel
	cmd.Run = cmd.RunDel

	return cmd.Command
}

func (cmd *natFrontend) ArgsDel(c *cobra.Command, args []string) error {
	var err error

	a, err := docopt.ParseArgs(makeDocUsage(c), args, "")
	if err != nil {
		return err
	}

	err = a.Bind(cmd)
	if err != nil {
		return err
	}

	return cmd.checkArgsCommon()
}

func (cmd *natFrontend) RunDel(c *cobra.Command, _ []string) {
	natMap := nat.FrontendMap()
	if err := natMap.Open(); err != nil {
		log.WithError(err).Error("Failed to access NATMap")
	}
	k := nat.NewNATKey(cmd.ip, cmd.port, cmd.proto)
	if err := natMap.Delete(k.AsBytes()); err != nil {
		log.WithError(err).
			WithFields(log.Fields{
				"key": k,
			}).Error("Failed to delete map entry")
	}
}

type natBackend struct {
	*cobra.Command

	IP   string `docopt:"<ip>"`
	Port string `docopt:"<port>"`
	ID   string `docopt:"<id>"`
	Idx  string `docopt:"<idx>"`

	ip   net.IP
	port uint16
	id   uint32
	idx  uint32
}

func newNatSetBackend() *cobra.Command {
	cmd := &natBackend{
		Command: &cobra.Command{
			Use:   "back <id> <idx> <ip> <port>",
			Short: "sets a NAT backend for frontend id",
		},
	}

	cmd.Args = cmd.ArgsSet
	cmd.Run = cmd.RunSet

	return cmd.Command
}

func (cmd *natBackend) checkArgsCommon() error {
	id, err := strconv.ParseUint(cmd.ID, 0, 32)
	if err != nil {
		return fmt.Errorf("id: %q is not 32-bit uint", cmd.ID)
	}
	cmd.id = uint32(id)

	idx, err := strconv.ParseUint(cmd.Idx, 0, 32)
	if err != nil {
		return fmt.Errorf("idx: %q is not 32-bit uint", cmd.Idx)
	}
	cmd.idx = uint32(idx)

	return nil
}

func (cmd *natBackend) ArgsSet(c *cobra.Command, args []string) error {
	var err error

	a, err := docopt.ParseArgs(makeDocUsage(c), args, "")
	if err != nil {
		return err
	}

	err = a.Bind(cmd)
	if err != nil {
		return err
	}

	cmd.ip = net.ParseIP(cmd.IP)
	if cmd.ip == nil {
		return fmt.Errorf("ip: %q is not an ip", cmd.IP)
	}

	port, err := strconv.ParseUint(cmd.Port, 0, 16)
	if err != nil {
		return fmt.Errorf("port: %q is not 16-bit uint", cmd.Port)
	}
	cmd.port = uint16(port)

	return cmd.checkArgsCommon()
}

func (cmd *natBackend) RunSet(c *cobra.Command, _ []string) {
	m := nat.BackendMap()
	if err := m.Open(); err != nil {
		log.WithError(err).Error("Failed to access NATMap")
	}
	k := nat.NewNATBackendKey(cmd.id, cmd.idx)
	v := nat.NewNATBackendValue(cmd.ip, cmd.port)
	if err := m.Update(k.AsBytes(), v.AsBytes()); err != nil {
		log.WithError(err).
			WithFields(log.Fields{
				"key":   k,
				"value": v,
			}).Error("Failed to update map entry")
	}
}

func newNatDelBackend() *cobra.Command {
	cmd := &natBackend{
		Command: &cobra.Command{
			Use:   "back <id> <idx>",
			Short: "deletes a NAT backend for frontend id",
		},
	}

	cmd.Args = cmd.ArgsDel
	cmd.Run = cmd.RunDel

	return cmd.Command
}

func (cmd *natBackend) ArgsDel(c *cobra.Command, args []string) error {
	var err error

	a, err := docopt.ParseArgs(makeDocUsage(c), args, "")
	if err != nil {
		return err
	}

	err = a.Bind(cmd)
	if err != nil {
		return err
	}

	return cmd.checkArgsCommon()
}

func (cmd *natBackend) RunDel(c *cobra.Command, _ []string) {
	m := nat.BackendMap()
	if err := m.Open(); err != nil {
		log.WithError(err).Error("Failed to access NATMap")
	}
	k := nat.NewNATBackendKey(cmd.id, cmd.idx)
	if err := m.Delete(k.AsBytes()); err != nil {
		log.WithError(err).
			WithFields(log.Fields{
				"key": k,
			}).Error("Failed to delete map entry")
	}
}
