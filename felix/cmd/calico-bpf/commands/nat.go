// Copyright (c) 2020 Tigera, Inc. All rights reserved.
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
	"net"
	"strconv"
	"strings"

	"github.com/projectcalico/calico/felix/bpf"

	"github.com/docopt/docopt-go"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/projectcalico/calico/felix/bpf/nat"
)

func init() {
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
	Short: "Nanipulates network address translation (nat)",
	Long: "nat manipulates network address translation (nat), " +
		"which implements the bpf-based replacement for kube-proxy",
}

var natDumpCmd = &cobra.Command{
	Use:   "dump",
	Short: "dumps the nat tables",
	Run: func(cmd *cobra.Command, args []string) {
		if err := dump(cmd); err != nil {
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
	mc := &bpf.MapContext{}
	affMap, err := nat.LoadAffinityMap(nat.AffinityMap(mc))
	if err != nil {
		return err
	}

	for k, v := range affMap {
		cmd.Printf("%-40s %s", k, v)
	}

	cmd.Printf("\n")

	return nil
}

func dump(cmd *cobra.Command) error {
	mc := &bpf.MapContext{}
	natMap, err := nat.LoadFrontendMap(nat.FrontendMap(mc))
	if err != nil {
		return err
	}

	back, err := nat.LoadBackendMap(nat.BackendMap(mc))
	if err != nil {
		return err
	}

	dumpNice(cmd.Printf, natMap, back)
	return nil
}

type printfFn func(format string, i ...interface{})

func dumpNice(printf printfFn, natMap nat.MapMem, back nat.BackendMapMem) {
	for nk, nv := range natMap {
		count := nv.Count()
		local := nv.LocalCount()
		id := nv.ID()
		flags := nv.FlagsAsString()
		if flags != "" {
			flags = " flags " + flags
		}
		printf("%s port %d proto %d id %d count %d local %d%s\n",
			nk.Addr(), nk.Port(), nk.Proto(), id, count, local, flags)
		for i := uint32(0); i < count; i++ {
			bk := nat.NewNATBackendKey(id, uint32(i))
			bv, ok := back[bk]
			printf("\t%d:%d\t ", id, i)
			if !ok {
				printf("is missing\n")
			} else {
				printf("%s:%d\n", bv.Addr(), bv.Port())
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

	cmd.Command.Args = cmd.ArgsSet
	cmd.Command.Run = cmd.RunSet

	return cmd.Command
}

func (cmd *natFrontend) checkArgsCommon() error {
	switch proto := strings.ToLower(cmd.Proto); proto {
	case "udp":
		cmd.proto = 17
	case "tcp":
		cmd.proto = 6
	default:
		return errors.Errorf("unknown protocol %s", proto)
	}

	cmd.ip = net.ParseIP(cmd.IP)
	if cmd.ip == nil {
		return errors.Errorf("ip: %q is not an ip", cmd.IP)
	}

	port, err := strconv.ParseUint(cmd.Port, 0, 16)
	if err != nil {
		return errors.Errorf("port: %q is not 16-bit uint", cmd.Port)
	}
	cmd.port = uint16(port)

	return nil
}

func (cmd *natFrontend) ArgsSet(c *cobra.Command, args []string) error {
	var err error

	a, err := docopt.ParseArgs(makeDocUsage(c), args, "")
	if err != nil {
		return errors.New(err.Error())
	}

	err = a.Bind(cmd)
	if err != nil {
		return errors.New(err.Error())
	}

	if err := cmd.checkArgsCommon(); err != nil {
		return err
	}

	id, err := strconv.ParseUint(cmd.ID, 0, 32)
	if err != nil {
		return errors.Errorf("id: %q is not 32-bit uint", cmd.ID)
	}
	cmd.id = uint32(id)

	count, err := strconv.ParseUint(cmd.Count, 0, 16)
	if err != nil {
		return errors.Errorf("count: %q is not 32-bit uint", cmd.Count)
	}
	cmd.count = uint32(count)

	return nil
}

func (cmd *natFrontend) RunSet(c *cobra.Command, _ []string) {
	natMap := nat.FrontendMap(&bpf.MapContext{})
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

	cmd.Command.Args = cmd.ArgsDel
	cmd.Command.Run = cmd.RunDel

	return cmd.Command
}

func (cmd *natFrontend) ArgsDel(c *cobra.Command, args []string) error {
	var err error

	a, err := docopt.ParseArgs(makeDocUsage(c), args, "")
	if err != nil {
		return errors.New(err.Error())
	}

	err = a.Bind(cmd)
	if err != nil {
		return errors.New(err.Error())
	}

	return cmd.checkArgsCommon()
}

func (cmd *natFrontend) RunDel(c *cobra.Command, _ []string) {
	natMap := nat.FrontendMap(&bpf.MapContext{})
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

	cmd.Command.Args = cmd.ArgsSet
	cmd.Command.Run = cmd.RunSet

	return cmd.Command
}

func (cmd *natBackend) checkArgsCommon() error {
	id, err := strconv.ParseUint(cmd.ID, 0, 32)
	if err != nil {
		return errors.Errorf("id: %q is not 32-bit uint", cmd.ID)
	}
	cmd.id = uint32(id)

	idx, err := strconv.ParseUint(cmd.Idx, 0, 32)
	if err != nil {
		return errors.Errorf("idx: %q is not 32-bit uint", cmd.Idx)
	}
	cmd.idx = uint32(idx)

	return nil
}

func (cmd *natBackend) ArgsSet(c *cobra.Command, args []string) error {
	var err error

	a, err := docopt.ParseArgs(makeDocUsage(c), args, "")
	if err != nil {
		return errors.New(err.Error())
	}

	err = a.Bind(cmd)
	if err != nil {
		return errors.New(err.Error())
	}

	cmd.ip = net.ParseIP(cmd.IP)
	if cmd.ip == nil {
		return errors.Errorf("ip: %q is not an ip", cmd.IP)
	}

	port, err := strconv.ParseUint(cmd.Port, 0, 16)
	if err != nil {
		return errors.Errorf("port: %q is not 16-bit uint", cmd.Port)
	}
	cmd.port = uint16(port)

	return cmd.checkArgsCommon()
}

func (cmd *natBackend) RunSet(c *cobra.Command, _ []string) {
	mc := &bpf.MapContext{}
	m := nat.BackendMap(mc)
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

	cmd.Command.Args = cmd.ArgsDel
	cmd.Command.Run = cmd.RunDel

	return cmd.Command
}

func (cmd *natBackend) ArgsDel(c *cobra.Command, args []string) error {
	var err error

	a, err := docopt.ParseArgs(makeDocUsage(c), args, "")
	if err != nil {
		return errors.New(err.Error())
	}

	err = a.Bind(cmd)
	if err != nil {
		return errors.New(err.Error())
	}

	return cmd.checkArgsCommon()
}

func (cmd *natBackend) RunDel(c *cobra.Command, _ []string) {
	mc := &bpf.MapContext{}
	m := nat.BackendMap(mc)
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
