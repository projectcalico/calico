// Copyright (c) 2019 Tigera, Inc. All rights reserved.
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

package main

import (
	"fmt"
	"net"
	"os"
	"sort"
	"strings"
	"syscall"

	"github.com/docopt/docopt-go"
	log "github.com/sirupsen/logrus"

	intdataplane "github.com/projectcalico/felix/dataplane/linux"

	"github.com/projectcalico/felix/buildinfo"
)

const usage = `calico-bpf, tool for interrogating Calico BPF state.

Usage:
  calico-bpf ipsets dump 
  calico-bpf conntrack remove <proto> <ip1> <ip2>

Options:
  --version                    Print the version and exit.
`

// main is the entry point to the calico-bpf binary.
func main() {
	// Parse command-line args.
	version := "Version:            " + buildinfo.GitVersion + "\n" +
		"Full git commit ID: " + buildinfo.GitRevision + "\n" +
		"Build date:         " + buildinfo.BuildDate + "\n"

	arguments, err := docopt.ParseArgs(usage, os.Args[1:], version)
	if err != nil {
		println(usage)
		log.Fatalf("Failed to parse usage, exiting: %v", err)
	}

	var args struct {
		IPSets bool `docopt:"ipsets"`
		Dump   bool

		Conntrack bool
		Remove    bool
		Proto     string `docopt:"<proto>"`

		IP1 string `docopt:"<ip1>"`
		IP2 string `docopt:"<ip2>"`
	}

	err = arguments.Bind(&args)
	if err != nil {
		println(usage)
		log.WithError(err).Error("Failed to bind arguments")
	}

	if args.IPSets && args.Dump {
		dumpIPSets()
	} else if args.Conntrack && args.Remove {
		removeConntrackEntries(args.Proto, args.IP1, args.IP2)
	}
}

func removeConntrackEntries(rawProto, rawIP1, rawIP2 string) {
	log.WithField("ip1", rawIP1).WithField("ip2", rawIP2).Info("Removing conntrack entries for IP")

	var proto uint8
	switch strings.ToLower(rawProto) {
	case "udp":
		proto = 17
	case "tcp":
		proto = 6
	}

	ip1 := net.ParseIP(rawIP1)
	ip2 := net.ParseIP(rawIP2)

	ctMap := intdataplane.ConntrackMap()
	var keysToRemove []intdataplane.ConntrackKey
	err := ctMap.Iter(func(k, v []byte) {
		var ctKey intdataplane.ConntrackKey
		if len(k) != len(ctKey) {
			log.Panic("Key has unexpected length")
		}
		copy(ctKey[:], k[:])

		log.Infof("Examining conntrack key: %v", ctKey)

		if ctKey.Proto() != proto {
			return
		}

		if ctKey.AddrA().Equal(ip1) && ctKey.AddrB().Equal(ip2) {
			log.Info("Match")
			keysToRemove = append(keysToRemove, ctKey)
		} else if ctKey.AddrB().Equal(ip1) && ctKey.AddrA().Equal(ip2) {
			log.Info("Match")
			keysToRemove = append(keysToRemove, ctKey)
		}
	})
	if err != nil {
		log.WithError(err).Fatal("Failed to iterate over conntrack entries")
	}

	for _, k := range keysToRemove {
		err := ctMap.Delete(k[:])
		if err != nil {
			log.WithError(err).WithField("key", k).Warning("Failed to delete entry from map")
		}
	}
}

func dumpIPSets() {
	ipsets := intdataplane.IPSetsMap()
	membersBySet := map[uint64][]string{}
	err := ipsets.Iter(func(k, v []byte) {
		var entry intdataplane.IPSetEntry
		copy(entry[:], k[:])
		var member string
		if entry.Protocol() == 0 {
			member = fmt.Sprintf("%s/%d", entry.Addr(), entry.PrefixLen()-64)
		} else {
			member = fmt.Sprintf("%s:%d (proto %d)", entry.Addr(), entry.Port(), entry.Protocol())
		}
		membersBySet[entry.SetID()] = append(membersBySet[entry.SetID()], member)
	})
	if err != nil {
		log.WithError(err).Error("Failed to dump IP sets map.")
		syscall.Exit(1)
	}
	var setIDs []uint64
	for k, v := range membersBySet {
		setIDs = append(setIDs, k)
		sort.Strings(v)
	}
	sort.Slice(setIDs, func(i, j int) bool {
		return setIDs[i] < setIDs[j]
	})
	for _, setID := range setIDs {
		fmt.Printf("IP set %#x\n", setID)
		for _, member := range membersBySet[setID] {
			fmt.Println("  ", member)
		}
		fmt.Println()
	}
	if len(setIDs) == 0 {
		fmt.Println("No IP sets found.")
	}
}
