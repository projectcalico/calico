// Copyright (c) 2020-2021 Tigera, Inc. All rights reserved.
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
	"encoding/base64"
	"fmt"
	"net"
	"strings"
	"time"

	"golang.org/x/sys/unix"

	"github.com/projectcalico/calico/felix/bpf"
	"github.com/projectcalico/calico/felix/bpf/conntrack"
	"github.com/projectcalico/calico/felix/bpf/conntrack/v2"

	"github.com/docopt/docopt-go"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

func init() {
	conntrackCmd.AddCommand(newConntrackDumpCmd())
	conntrackCmd.AddCommand(newConntrackRemoveCmd())
	conntrackCmd.AddCommand(&cobra.Command{
		Use:   "clean",
		Short: "Clean all  conntrack entries",
		Run:   runClean,
	})
	conntrackCmd.AddCommand(newConntrackWriteCmd())
	conntrackCmd.AddCommand(newConntrackFillCmd())
	conntrackCmd.AddCommand(newConntrackCreateCmd())
	rootCmd.AddCommand(conntrackCmd)
}

// conntrackCmd represents the conntrack command
var conntrackCmd = &cobra.Command{
	Use:   "conntrack",
	Short: "Manipulates connection tracking",
}

type conntrackDumpCmd struct {
	*cobra.Command
	Version string `docopt:"<version>"`

	version  int
}

func newConntrackDumpCmd() *cobra.Command {
	cmd := &conntrackDumpCmd{
		Command: &cobra.Command{
			Use:   "dump [<version>]",
			Short: "Dumps connection tracking table",
		},
	}

	cmd.Command.Args = cmd.Args
	cmd.Command.Run = cmd.Run

	return cmd.Command
}

func (cmd *conntrackDumpCmd) Args(c *cobra.Command, args []string) error {
	a, err := docopt.ParseArgs(makeDocUsage(c), args, "")
	if err != nil {
		return errors.New(err.Error())
	}

	err = a.Bind(cmd)
	if err != nil {
		return errors.New(err.Error())
	}

	switch cmd.Version {
	case "2":
		cmd.version = 2
	default:
		cmd.version = 3
	}
	return nil
}

func dumpCtMapV2(ctMap bpf.Map) error {
	err := ctMap.Iter(func(k, v []byte) bpf.IteratorAction {
		var ctKey v2.Key
		if len(k) != len(ctKey) {
			log.Panic("Key has unexpected length")
		}
		copy(ctKey[:], k[:])

		var ctVal v2.Value
                if len(v) != len(ctVal) {
                        log.Panic("Value has unexpected length")
                }
                copy(ctVal[:], v[:])

                fmt.Printf("%v -> %v", ctKey, ctVal)
                dumpExtrav2(ctKey, ctVal)
                fmt.Printf("\n")
                return bpf.IterNone
	})
	return err
}

func (cmd *conntrackDumpCmd) Run(c *cobra.Command, _ []string) {
	var ctMap bpf.Map
	mc := &bpf.MapContext{}
	switch cmd.version {
	case 2:
		ctMap = conntrack.MapV2(mc)
	default:
		ctMap = conntrack.Map(mc)
	}
	if err := ctMap.Open(); err != nil {
		log.WithError(err).Fatal("Failed to access ConntrackMap")
	}
	if cmd.version == 2 {
		err := dumpCtMapV2(ctMap)
		if err != nil {
			log.WithError(err).Fatal("Failed to iterate over conntrack entries")
		}
		return
	}
	err := ctMap.Iter(func(k, v []byte) bpf.IteratorAction {
		var ctKey conntrack.Key
		if len(k) != len(ctKey) {
			log.Panic("Key has unexpected length")
		}
		copy(ctKey[:], k[:])

		var ctVal conntrack.Value
		if len(v) != len(ctVal) {
			log.Panic("Value has unexpected length")
		}
		copy(ctVal[:], v[:])

		fmt.Printf("%v -> %v", ctKey, ctVal)
		dumpExtra(ctKey, ctVal)
		fmt.Printf("\n")
		return bpf.IterNone
	})
	if err != nil {
		log.WithError(err).Fatal("Failed to iterate over conntrack entries")
	}
}

func dumpExtrav2(k v2.Key, v v2.Value) {
        now := bpf.KTimeNanos()

        fmt.Printf(" Age: %s Active ago %s",
                time.Duration(now-v.Created()), time.Duration(now-v.LastSeen()))

        if k.Proto() != conntrack.ProtoTCP {
                return
        }

        if v.Type() == conntrack.TypeNATForward {
                return
        }

        data := v.Data()

        if (v.IsForwardDSR() && data.FINsSeenDSR()) || data.FINsSeen() {
                fmt.Printf(" CLOSED")
                return
        }

        if data.Established() {
                fmt.Printf(" ESTABLISHED")
                return
        }

        fmt.Printf(" SYN-SENT")
}

func dumpExtra(k conntrack.Key, v conntrack.Value) {
	now := bpf.KTimeNanos()

	fmt.Printf(" Age: %s Active ago %s",
		time.Duration(now-v.Created()), time.Duration(now-v.LastSeen()))

	if k.Proto() != conntrack.ProtoTCP {
		return
	}

	if v.Type() == conntrack.TypeNATForward {
		return
	}

	data := v.Data()

	if (v.IsForwardDSR() && data.FINsSeenDSR()) || data.FINsSeen() {
		fmt.Printf(" CLOSED")
		return
	}

	if data.Established() {
		fmt.Printf(" ESTABLISHED")
		return
	}

	fmt.Printf(" SYN-SENT")
}

type conntrackRemoveCmd struct {
	*cobra.Command

	Proto string `docopt:"<proto>"`
	IP1   string `docopt:"<ip1>"`
	IP2   string `docopt:"<ip2>"`

	proto uint8
	ip1   net.IP
	ip2   net.IP
}

func newConntrackRemoveCmd() *cobra.Command {
	cmd := &conntrackRemoveCmd{
		Command: &cobra.Command{
			Use:   "remove <proto> <ip1> <ip2>",
			Short: "removes connection tracking",
		},
	}

	cmd.Command.Args = cmd.Args
	cmd.Command.Run = cmd.Run

	return cmd.Command
}

func (cmd *conntrackRemoveCmd) Args(c *cobra.Command, args []string) error {
	a, err := docopt.ParseArgs(makeDocUsage(c), args, "")
	if err != nil {
		return errors.New(err.Error())
	}

	err = a.Bind(cmd)
	if err != nil {
		return errors.New(err.Error())
	}

	switch proto := strings.ToLower(args[0]); proto {
	case "udp":
		cmd.proto = 17
	case "tcp":
		cmd.proto = 6
	default:
		return errors.Errorf("unknown protocol %s", proto)
	}

	cmd.ip1 = net.ParseIP(cmd.IP1)
	if cmd.ip1 == nil {
		return errors.Errorf("ip1: %q is not an ip", cmd.IP1)
	}

	cmd.ip2 = net.ParseIP(cmd.IP2)
	if cmd.ip2 == nil {
		return errors.Errorf("ip2: %q is not an ip", cmd.IP2)
	}

	return nil
}

func (cmd *conntrackRemoveCmd) Run(c *cobra.Command, _ []string) {
	mc := &bpf.MapContext{}
	ctMap := conntrack.Map(mc)
	if err := ctMap.Open(); err != nil {
		log.WithError(err).Error("Failed to access ConntrackMap")
	}
	err := ctMap.Iter(func(k, v []byte) bpf.IteratorAction {
		var ctKey conntrack.Key
		if len(k) != len(ctKey) {
			log.Panic("Key has unexpected length")
		}
		copy(ctKey[:], k[:])

		log.Infof("Examining conntrack key: %v", ctKey)

		if ctKey.Proto() != cmd.proto {
			return bpf.IterNone
		}

		if ctKey.AddrA().Equal(cmd.ip1) && ctKey.AddrB().Equal(cmd.ip2) {
			log.Info("Match")
			return bpf.IterDelete
		} else if ctKey.AddrB().Equal(cmd.ip1) && ctKey.AddrA().Equal(cmd.ip2) {
			log.Info("Match")
			return bpf.IterDelete
		}
		return bpf.IterNone
	})
	if err != nil {
		log.WithError(err).Fatal("Failed to iterate over conntrack entries")
	}
}

func runClean(c *cobra.Command, _ []string) {
	mc := &bpf.MapContext{}
	ctMap := conntrack.Map(mc)
	if err := ctMap.Open(); err != nil {
		log.WithError(err).Error("Failed to access ConntrackMap")
	}

	// Disable debug if set while deleting
	loglevel := log.GetLevel()
	log.SetLevel(log.WarnLevel)
	err := ctMap.Iter(func(k, v []byte) bpf.IteratorAction {
		return bpf.IterDelete
	})

	log.SetLevel(loglevel)
	if err != nil {
		log.WithError(err).Fatal("Failed to iterate over conntrack entries")
	}
}

type conntrackCreateCmd struct {
	*cobra.Command

	Version string `docopt:"<version>"`

	version int
}

func newConntrackCreateCmd() *cobra.Command {
	cmd := &conntrackCreateCmd{
		Command: &cobra.Command{
			Use: "create <version>",
			Short: "create a conntrack map of specified version",
		},
	}

	cmd.Command.Args = cmd.Args
	cmd.Command.Run = cmd.Run

	return cmd.Command
}

func (cmd *conntrackCreateCmd) Args(c *cobra.Command, args []string) error {
        a, err := docopt.ParseArgs(makeDocUsage(c), args, "")
        if err != nil {
                return errors.New(err.Error())
        }

        err = a.Bind(cmd)
        if err != nil {
                return errors.New(err.Error())
        }

	switch cmd.Version {
	case "2":
		cmd.version = 2
	default:
		cmd.version = 3
	}
        return nil
}

func (cmd *conntrackCreateCmd) Run(c *cobra.Command, _ []string) {
	var ctMap bpf.Map
        mc := &bpf.MapContext{}
	switch cmd.version {
	case 2:
		ctMap = conntrack.MapV2(mc)
	default:
		ctMap = conntrack.Map(mc)
	}
	if err := ctMap.EnsureExists(); err != nil {
		log.WithError(err).Errorf("Failed to create conntrackMap version %d", cmd.version)
	}
}

type conntrackWriteCmd struct {
	*cobra.Command

	Version string `docopt:"<version>"`
	Key   string `docopt:"<key>"`
	Value string `docopt:"<value>"`

	key []byte
	val []byte
	version int
}

func newConntrackWriteCmd() *cobra.Command {
	cmd := &conntrackWriteCmd{
		Command: &cobra.Command{
			Use:   "write [<version>] <key> <value>",
			Short: "write a key-value pair, each encoded in base64",
		},
	}

	cmd.Command.Args = cmd.Args
	cmd.Command.Run = cmd.Run

	return cmd.Command
}

func (cmd *conntrackWriteCmd) Args(c *cobra.Command, args []string) error {
	a, err := docopt.ParseArgs(makeDocUsage(c), args, "")
	if err != nil {
		return errors.New(err.Error())
	}

	err = a.Bind(cmd)
	if err != nil {
		return errors.New(err.Error())
	}

	switch cmd.Version {
	case "2":
		cmd.version = 2
	default:
		cmd.version = 3
	}

	cmd.key, err = base64.StdEncoding.DecodeString(cmd.Key)
	if err != nil {
		switch cmd.version {
		case 2:
			if len(cmd.key) != len(v2.Key{}) {
				return errors.Errorf("failed to decode key: %s", err)
			}
		default:
			if len(cmd.key) != len(conntrack.Key{}) {
				return errors.Errorf("failed to decode key: %s", err)
			}
		}
	}

	cmd.val, err = base64.StdEncoding.DecodeString(cmd.Value)
	if err != nil {
		switch cmd.version {
		case 2:
			if len(cmd.val) != len(v2.Value{}) {
				return errors.Errorf("failed to decode val: %s", err)
			}
		default:
			if len(cmd.val) != len(conntrack.Value{}) {
				return errors.Errorf("failed to decode val: %s", err)
			}
		}
	}
	return nil
}

func (cmd *conntrackWriteCmd) Run(c *cobra.Command, _ []string) {
	mc := &bpf.MapContext{}
	var ctMap bpf.Map
	if cmd.version == 2 {
		ctMap = conntrack.MapV2(mc)
	} else {
		ctMap = conntrack.Map(mc)
	}

	if err := ctMap.Open(); err != nil {
		log.WithError(err).Error("Failed to access ConntrackMap")
	}

	if err := ctMap.Update(cmd.key, cmd.val); err != nil {
		log.WithError(err).Error("Failed to update ConntrackMap")
	}
}

type conntrackFillCmd struct {
	conntrackWriteCmd
}

func newConntrackFillCmd() *cobra.Command {
	cmd := &conntrackFillCmd{
		conntrackWriteCmd: conntrackWriteCmd{
			Command: &cobra.Command{
				Use: "fill <key> <value>",
				Short: "fill the table with a key-value pair, each encoded in base64. " +
					"They prot-ip1-ip2 in the key are used as a start, ports are generated.",
			},
		},
	}

	cmd.Command.Args = cmd.Args
	cmd.Command.Run = cmd.Run

	return cmd.Command
}

func (cmd *conntrackFillCmd) Run(c *cobra.Command, _ []string) {
	mc := &bpf.MapContext{}
	ctMap := conntrack.Map(mc)

	var key conntrack.Key
	copy(key[:], cmd.key)

	ipA := key.AddrA()
	ipB := key.AddrB()
	proto := key.Proto()

	if err := ctMap.Open(); err != nil {
		log.WithError(err).Error("Failed to access ConntrackMap")
	}

	// Disable debug if set while writing
	loglevel := log.GetLevel()
	log.SetLevel(log.WarnLevel)

	for i := 1; ; i++ {
		portA := uint16(i >> 16)
		portB := uint16(i & 0xffff)

		key := conntrack.NewKey(proto, ipA, portA, ipB, portB)

		if err := ctMap.Update(key[:], cmd.val); err != nil {
			log.SetLevel(loglevel)
			fmt.Printf("i = %+v\n", i)
			log.Infof("Written %d entries", i-1)
			if err == unix.E2BIG {
				return
			}
			log.WithError(err).Fatal("Failed to update ConntrackMap")
		}
	}
}
