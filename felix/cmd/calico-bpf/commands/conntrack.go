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
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/docopt/docopt-go"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"golang.org/x/sys/unix"

	"github.com/projectcalico/calico/felix/bpf"
	"github.com/projectcalico/calico/felix/bpf/conntrack"
	v2 "github.com/projectcalico/calico/felix/bpf/conntrack/v2"
	v3 "github.com/projectcalico/calico/felix/bpf/conntrack/v3"
	"github.com/projectcalico/calico/felix/bpf/maps"
)

func init() {
	conntrackCmd.AddCommand(newConntrackDumpCmd())
	conntrackCmd.AddCommand(newConntrackRemoveCmd())
	conntrackCmd.AddCommand(newConntrackCleanCmd())
	conntrackCmd.AddCommand(newConntrackWriteCmd())
	conntrackCmd.AddCommand(newConntrackFillCmd())
	conntrackCmd.AddCommand(newConntrackCreateCmd())
	conntrackCmd.AddCommand(newConntrackStatsCmd())
	rootCmd.AddCommand(conntrackCmd)
}

// conntrackCmd represents the conntrack command
var (
	conntrackCmd = &cobra.Command{
		Use:   "conntrack",
		Short: "Manipulates connection tracking",
	}

	voidIP4 = net.IPv4(0, 0, 0, 0)
	voidIP6 = net.ParseIP("::")
)

type conntrackOpts struct {
	version int
	ipv6    bool
}

type conntrackDumpCmd struct {
	*cobra.Command
	raw bool
	conntrackOpts
}

func newConntrackDumpCmd() *cobra.Command {
	cmd := &conntrackDumpCmd{
		Command: &cobra.Command{
			Use:   "dump [--ver=<version>] [--raw]",
			Short: "Dumps connection tracking table",
		},
	}

	cmd.Command.Flags().IntVarP((&cmd.version), "ver", "v", 3, "version to dump from")
	cmd.Command.Flags().BoolVar((&cmd.raw), "raw", false, "dump the raw conntrack table as is. For version < 3 it is always raw")
	cmd.Command.Args = cmd.Args
	cmd.Command.Run = cmd.Run

	return cmd.Command
}

func dumpCtMapV2(ctMap maps.Map) error {
	err := ctMap.Iter(func(k, v []byte) maps.IteratorAction {
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
		return maps.IterNone
	})
	return err
}

func (cmd *conntrackDumpCmd) Run(c *cobra.Command, _ []string) {
	var (
		ctMap maps.Map
		ctErr error
	)

	cmd.ipv6 = ipv6 != nil && *ipv6
	if cmd.version < 3 && cmd.version != 0 {
		cmd.raw = true
	}

	if ctMap, ctErr = GetCTMap(cmd.version, cmd.ipv6); ctErr != nil {
		log.WithError(ctErr).Fatal("Failed to get ConntrackMap")
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

	keyFromBytes := conntrack.KeyFromBytes
	valFromBytes := conntrack.ValueFromBytes
	if cmd.ipv6 {
		keyFromBytes = conntrack.KeyV6FromBytes
		valFromBytes = conntrack.ValueV6FromBytes
	}

	err := ctMap.Iter(func(k, v []byte) maps.IteratorAction {
		ctKey := keyFromBytes(k)
		ctVal := valFromBytes(v)

		if cmd.raw {
			fmt.Printf("%v -> %v", ctKey, ctVal)
			dumpExtra(ctKey, ctVal)
			fmt.Printf("\n")
		} else {
			cmd.prettyDump(ctKey, ctVal)
		}
		return maps.IterNone
	})
	if err != nil {
		log.WithError(err).Fatal("Failed to iterate over conntrack entries")
	}
}

func protoStr(proto uint8) string {
	switch proto {
	case 6:
		return "TCP"
	case 17:
		return "UDP"
	case 1:
		return "ICMP"
	case 58:
		return "ICMP6"
	}

	return "UNKNOWN"
}

func (cmd *conntrackDumpCmd) prettyDump(k conntrack.KeyInterface, v conntrack.ValueInterface) {
	d := v.Data()

	switch v.Type() {
	case conntrack.TypeNormal:
		if v.Flags()&v3.FlagSrcDstBA != 0 {
			cmd.Printf("%s %s:%d -> %s:%d ", protoStr(k.Proto()), k.AddrB(), k.PortB(), k.AddrA(), k.PortA())
		} else {
			cmd.Printf("%s %s:%d -> %s:%d ", protoStr(k.Proto()), k.AddrA(), k.PortA(), k.AddrB(), k.PortB())
		}
	case conntrack.TypeNATForward:
		return
	case conntrack.TypeNATReverse:
		if v.Flags()&v3.FlagSrcDstBA != 0 {
			cmd.Printf("%s %s:%d -> %s:%d -> %s:%d ",
				protoStr(k.Proto()), k.AddrB(), k.PortB(), d.OrigDst, d.OrigPort, k.AddrA(), k.PortA())
		} else {
			cmd.Printf("%s %s:%d -> %s:%d -> %s:%d ",
				protoStr(k.Proto()), k.AddrA(), k.PortA(), d.OrigDst, d.OrigPort, k.AddrB(), k.PortB())
		}

		if (cmd.ipv6 && !d.TunIP.Equal(voidIP6)) || (!cmd.ipv6 && !d.TunIP.Equal(voidIP4)) {
			cmd.Printf("external client, service forwarded to/from %s ", d.TunIP)
		}
	}

	if v.Flags()&v3.FlagHostPSNAT != 0 {
		cmd.Printf("source port changed from %d ", d.OrigSPort)
	}

	now := bpf.KTimeNanos()
	cmd.Printf(" Age: %s Active ago %s Duration %s",
		time.Duration(now-v.Created()), time.Duration(now-v.LastSeen()), time.Duration(v.LastSeen()-v.Created()))

	if k.Proto() == 6 {
		if (v.IsForwardDSR() && d.FINsSeenDSR()) || d.FINsSeen() {
			cmd.Printf(" CLOSED")
		} else if d.RSTSeen() {
			cmd.Printf(" RESET")
		} else if d.Established() {
			cmd.Printf(" ESTABLISHED")
		} else {
			cmd.Printf(" SYN-SENT")
		}
	}

	cmd.Printf("\n")
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

	if data.RSTSeen() {
		fmt.Printf(" RESET")
		return
	}

	if data.Established() {
		fmt.Printf(" ESTABLISHED")
		return
	}

	fmt.Printf(" SYN-SENT")
}

func dumpExtra(k conntrack.KeyInterface, v conntrack.ValueInterface) {
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

	if data.RSTSeen() {
		fmt.Printf(" RESET")
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

	conntrackOpts
}

func newConntrackRemoveCmd() *cobra.Command {
	cmd := &conntrackRemoveCmd{
		Command: &cobra.Command{
			Use:   "remove <proto> <ip1> <ip2>",
			Short: "Removes connection tracking",
		},
	}

	cmd.Command.Flags().IntVarP((&cmd.version), "ver", "v", 3, "version to remove from")
	cmd.Command.Args = cmd.Args
	cmd.Command.Run = cmd.Run

	return cmd.Command
}

func (cmd *conntrackRemoveCmd) Args(c *cobra.Command, args []string) error {
	a, err := docopt.ParseArgs(makeDocUsage(c), args, "")
	if err != nil {
		return err
	}

	err = a.Bind(cmd)
	if err != nil {
		return err
	}

	switch proto := strings.ToLower(args[0]); proto {
	case "udp":
		cmd.proto = 17
	case "tcp":
		cmd.proto = 6
	default:
		return fmt.Errorf("unknown protocol %s", proto)
	}

	cmd.ip1 = net.ParseIP(cmd.IP1)
	if cmd.ip1 == nil {
		return fmt.Errorf("ip1: %q is not an ip", cmd.IP1)
	}

	cmd.ip2 = net.ParseIP(cmd.IP2)
	if cmd.ip2 == nil {
		return fmt.Errorf("ip2: %q is not an ip", cmd.IP2)
	}

	return nil
}

func (cmd *conntrackRemoveCmd) Run(c *cobra.Command, _ []string) {
	var (
		ctMap maps.Map
		ctErr error
	)

	cmd.ipv6 = ipv6 != nil && *ipv6

	if ctMap, ctErr = GetCTMap(cmd.version, cmd.ipv6); ctErr != nil {
		log.WithError(ctErr).Fatal("Failed to get ConntrackMap")
	}
	if err := ctMap.Open(); err != nil {
		log.WithError(err).Error("Failed to access ConntrackMap")
	}
	err := ctMap.Iter(func(k, v []byte) maps.IteratorAction {
		var ctKey conntrack.Key
		if len(k) != len(ctKey) {
			log.Panic("Key has unexpected length")
		}
		copy(ctKey[:], k[:])

		log.Infof("Examining conntrack key: %v", ctKey)

		if ctKey.Proto() != cmd.proto {
			return maps.IterNone
		}

		if ctKey.AddrA().Equal(cmd.ip1) && ctKey.AddrB().Equal(cmd.ip2) {
			log.Info("Match")
			return maps.IterDelete
		} else if ctKey.AddrB().Equal(cmd.ip1) && ctKey.AddrA().Equal(cmd.ip2) {
			log.Info("Match")
			return maps.IterDelete
		}
		return maps.IterNone
	})
	if err != nil {
		log.WithError(err).Fatal("Failed to iterate over conntrack entries")
	}
}

type conntrackCleanCmd struct {
	*cobra.Command
	conntrackOpts
}

func newConntrackCleanCmd() *cobra.Command {
	cmd := &conntrackCleanCmd{
		Command: &cobra.Command{
			Use:   "clean [--ver=<version>]",
			Short: "Cleans all conntrack entries",
		},
	}

	cmd.Command.Flags().IntVarP((&cmd.version), "ver", "v", 3, "conntrack version to clean")
	cmd.Command.Args = cmd.Args
	cmd.Command.Run = cmd.Run

	return cmd.Command
}

func (cmd *conntrackCleanCmd) Run(c *cobra.Command, _ []string) {
	var (
		ctMap maps.Map
		ctErr error
	)

	cmd.ipv6 = ipv6 != nil && *ipv6

	if ctMap, ctErr = GetCTMap(cmd.version, cmd.ipv6); ctErr != nil {
		log.WithError(ctErr).Fatal("Failed to get ConntrackMap")
	}
	if err := ctMap.Open(); err != nil {
		log.WithError(err).Error("Failed to access ConntrackMap")
	}

	// Disable debug if set while deleting
	loglevel := log.GetLevel()
	log.SetLevel(log.WarnLevel)
	err := ctMap.Iter(func(k, v []byte) maps.IteratorAction {
		return maps.IterDelete
	})

	log.SetLevel(loglevel)
	if err != nil {
		log.WithError(err).Fatal("Failed to iterate over conntrack entries")
	}
}

type conntrackCreateCmd struct {
	*cobra.Command
	conntrackOpts
}

func newConntrackCreateCmd() *cobra.Command {
	cmd := &conntrackCreateCmd{
		Command: &cobra.Command{
			Use:   "create [--ver=<version>]",
			Short: "Creates a conntrack map of specified version",
		},
	}

	cmd.Command.Flags().IntVarP((&cmd.version), "ver", "v", 3, "conntrack version to create")
	cmd.Command.Args = cmd.Args
	cmd.Command.Run = cmd.Run

	return cmd.Command
}

func (cmd *conntrackCreateCmd) Run(c *cobra.Command, _ []string) {
	cmd.ipv6 = ipv6 != nil && *ipv6
	ctMap := getCTMap(cmd.version, cmd.ipv6)

	if err := ctMap.EnsureExists(); err != nil {
		log.WithError(err).Errorf("Failed to create conntrackMap version %d", cmd.version)
	}
}

type conntrackWriteCmd struct {
	*cobra.Command

	Key   string `docopt:"<key>"`
	Value string `docopt:"<value>"`

	key []byte
	val []byte
	conntrackOpts
}

func newConntrackWriteCmd() *cobra.Command {
	cmd := &conntrackWriteCmd{
		Command: &cobra.Command{
			Use:   "write <key> <value>",
			Short: "Writes a key-value pair, each encoded in base64",
		},
	}

	cmd.Command.Flags().IntVarP((&cmd.version), "ver", "v", 3, "conntrack map version")
	cmd.Command.Args = cmd.Args
	cmd.Command.Run = cmd.Run

	return cmd.Command
}

func (cmd *conntrackWriteCmd) Args(c *cobra.Command, args []string) error {
	a, err := docopt.ParseArgs(makeDocUsage(c), args, "")
	if err != nil {
		return err
	}

	err = a.Bind(cmd)
	if err != nil {
		return err
	}

	cmd.ipv6 = ipv6 != nil && *ipv6

	cmd.key, err = base64.StdEncoding.DecodeString(cmd.Key)
	if err != nil {
		switch cmd.version {
		case 2:
			if len(cmd.key) != len(v2.Key{}) {
				return fmt.Errorf("failed to decode key: %s", err)
			}
		default:
			if cmd.ipv6 && len(cmd.key) != len(conntrack.KeyV6{}) {
				return fmt.Errorf("failed to decode key: %s", err)
			} else if !cmd.ipv6 && len(cmd.key) != len(conntrack.Key{}) {
				return fmt.Errorf("failed to decode key: %s", err)
			}
		}
	}

	cmd.val, err = base64.StdEncoding.DecodeString(cmd.Value)
	if err != nil {
		switch cmd.version {
		case 2:
			if len(cmd.val) != len(v2.Value{}) {
				return fmt.Errorf("failed to decode val: %s", err)
			}
		default:
			if cmd.ipv6 && len(cmd.val) != len(conntrack.ValueV6{}) {
				return fmt.Errorf("failed to decode val: %s", err)
			} else if !cmd.ipv6 && len(cmd.val) != len(conntrack.Value{}) {
				return fmt.Errorf("failed to decode val: %s", err)
			}
		}
	}
	return nil
}

func (cmd *conntrackWriteCmd) Run(c *cobra.Command, _ []string) {
	var (
		ctMap maps.Map
		ctErr error
	)

	cmd.ipv6 = ipv6 != nil && *ipv6

	if ctMap, ctErr = GetCTMap(cmd.version, cmd.ipv6); ctErr != nil {
		log.WithError(ctErr).Fatal("Failed to get ConntrackMap")
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
				Short: "Fills the table with a key-value pair, each encoded in base64. " +
					"The prot-ip1-ip2 in the key are used as a start, ports are generated.",
			},
		},
	}

	cmd.Command.Flags().IntVarP((&cmd.version), "ver", "v", 3, "conntrack map version")
	cmd.Command.Args = cmd.Args
	cmd.Command.Run = cmd.Run

	return cmd.Command
}

func (cmd *conntrackFillCmd) Run(c *cobra.Command, _ []string) {
	var (
		key   conntrack.KeyInterface
		ctMap maps.Map
		ctErr error
	)

	cmd.ipv6 = ipv6 != nil && *ipv6

	if cmd.ipv6 {
		var k conntrack.KeyV6
		copy(k[:], cmd.key)
		key = k
	} else {
		var k conntrack.Key
		copy(k[:], cmd.key)
		key = k
	}

	ipA := key.AddrA()
	ipB := key.AddrB()
	proto := key.Proto()

	if ctMap, ctErr = GetCTMap(cmd.version, cmd.ipv6); ctErr != nil {
		log.WithError(ctErr).Fatal("Failed to get ConntrackMap")
	}

	if err := ctMap.Open(); err != nil {
		log.WithError(err).Error("Failed to access ConntrackMap")
	}

	// Disable debug if set while writing
	loglevel := log.GetLevel()
	log.SetLevel(log.WarnLevel)

	for i := 1; ; i++ {
		var err error
		portA := uint16(i >> 16)
		portB := uint16(i & 0xffff)

		if cmd.ipv6 {
			key := conntrack.NewKeyV6(proto, ipA, portA, ipB, portB)
			if err = ctMap.Update(key[:], cmd.val); err == nil {
				continue
			}
		} else {
			key := conntrack.NewKey(proto, ipA, portA, ipB, portB)
			if err = ctMap.Update(key[:], cmd.val); err == nil {
				continue
			}
		}

		log.SetLevel(loglevel)
		log.Infof("Written %d entries", i-1)
		if err == unix.E2BIG {
			return
		}
		log.WithError(err).Fatal("Failed to update ConntrackMap")
	}
}

type conntrackStatsCmd struct {
	*cobra.Command

	established int
	reset       int
	closed      int
	synSent     int
	total       int
	nat         int

	protos map[int]int

	conntrackOpts
}

func newConntrackStatsCmd() *cobra.Command {
	cmd := &conntrackStatsCmd{
		Command: &cobra.Command{
			Use:   "stats [--ver=<version>]",
			Short: "Prints conntrack statistics",
		},
		protos: make(map[int]int),
	}

	cmd.Command.Flags().IntVarP((&cmd.version), "ver", "v", 3, "conntrack map version")

	cmd.Command.Args = cmd.Args
	cmd.Command.Run = cmd.Run

	return cmd.Command
}

func (cmd *conntrackStatsCmd) Run(c *cobra.Command, _ []string) {
	var (
		ctMap maps.Map
		ctErr error
	)

	cmd.ipv6 = ipv6 != nil && *ipv6

	if ctMap, ctErr = GetCTMap(cmd.version, cmd.ipv6); ctErr != nil {
		log.WithError(ctErr).Fatal("Failed to get ConntrackMap")
	}

	if err := ctMap.Open(); err != nil {
		log.WithError(err).Fatal("Failed to access ConntrackMap")
	}

	keyFromBytes := conntrack.KeyFromBytes
	valFromBytes := conntrack.ValueFromBytes
	if cmd.ipv6 {
		keyFromBytes = conntrack.KeyV6FromBytes
		valFromBytes = conntrack.ValueV6FromBytes
	}

	err := ctMap.Iter(func(k, v []byte) maps.IteratorAction {
		ctKey := keyFromBytes(k)
		ctVal := valFromBytes(v)
		d := ctVal.Data()

		if ctVal.Type() == conntrack.TypeNATForward {
			cmd.nat++
			return maps.IterNone
		}

		if ctKey.Proto() == 6 {
			if (ctVal.IsForwardDSR() && d.FINsSeenDSR()) || d.FINsSeen() {
				cmd.closed++
			} else if d.RSTSeen() {
				cmd.reset++
			} else if d.Established() {
				cmd.established++
			} else {
				cmd.synSent++
			}
		}

		cmd.total++
		cmd.protos[int(ctKey.Proto())]++

		return maps.IterNone
	})

	cmd.Printf("Conntrack map size: %d\n", maps.Size(ctMap.GetName()))

	cmd.Printf("Total connections: %d\n", cmd.total)
	cmd.Printf("Total entries: %d\n", cmd.total+cmd.nat)
	cmd.Printf("NAT connections: %d\n\n", cmd.nat)

	cmd.Printf("TCP : %d\n", cmd.protos[6])
	cmd.Printf("UDP : %d\n", cmd.protos[17])
	cmd.Printf("Others : %d\n\n", cmd.total-cmd.protos[6]-cmd.protos[17])

	cmd.Printf("TCP Established: %d\n", cmd.established)
	cmd.Printf("TCP Closed: %d\n", cmd.closed)
	cmd.Printf("TCP Reset: %d\n", cmd.reset)
	cmd.Printf("TCP Syn-sent: %d\n", cmd.synSent)

	if err != nil {
		log.WithError(err).Fatal("Failed to iterate over conntrack entries")
	}
}

func GetCTMap(version int, ipv6 bool) (maps.Map, error) {
	// Set the map size based on the actual max entries obtained from the map info.
	if err := setCTMapSize(version, ipv6); err != nil {
		return nil, err
	}
	return getCTMap(version, ipv6), nil
}

func getCTMap(version int, ipv6 bool) maps.Map {
	var ctMap maps.Map
	switch version {
	case 2:
		ctMap = conntrack.MapV2()
	default:
		if ipv6 {
			ctMap = conntrack.MapV6()
		} else {
			ctMap = conntrack.Map()
		}
	}
	return ctMap
}

func setCTMapSize(version int, ipv6 bool) error {
	ctMap := getCTMap(version, ipv6)

	if err := ctMap.Open(); err != nil {
		return errors.New("failed to access conntrack Map")
	}
	defer ctMap.Close()

	if mapInfo, err := maps.GetMapInfo(ctMap.MapFD()); err != nil {
		return errors.New("failed to get map info")
	} else {
		// Set the map size based on the actual max entries obtained from the map info.
		maps.SetSize(ctMap.GetName(), mapInfo.MaxEntries)
	}

	return nil
}
