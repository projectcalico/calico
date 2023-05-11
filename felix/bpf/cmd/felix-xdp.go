// Copyright (c) 2017-2020 Tigera, Inc. All rights reserved.
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
	"os/exec"

	log "github.com/sirupsen/logrus"

	docopt "github.com/docopt/docopt-go"

	"github.com/projectcalico/calico/felix/bpf"
	"github.com/projectcalico/calico/felix/buildinfo"
	"github.com/projectcalico/calico/felix/labelindex"
)

const usage = `felix-xdp, dumping xdp state for Calico.

Usage:
  felix-xdp dump
  felix-xdp populate

Options:
  --version                    Print the version and exit.
`

var bpfLib bpf.BPFDataplane

func populate() {
	cmdVethPairArgs := []string{"-c", "ip link add eth42 type veth peer name eth43 || true"}
	_, _ = exec.Command("/bin/sh", cmdVethPairArgs...).CombinedOutput()
	_, _ = bpfLib.NewFailsafeMap()
	_ = bpfLib.UpdateFailsafeMap(uint8(labelindex.ProtocolTCP), 53)
	_ = bpfLib.UpdateFailsafeMap(uint8(labelindex.ProtocolTCP), 80)
	_ = bpfLib.UpdateFailsafeMap(uint8(labelindex.ProtocolTCP), 22)
	_ = bpfLib.UpdateFailsafeMap(uint8(labelindex.ProtocolUDP), 53)

	_ = bpfLib.RemoveXDP("eth42", bpf.XDPGeneric)
	_, _ = bpfLib.NewCIDRMap("eth42", bpf.IPFamilyV4)
	_ = bpfLib.UpdateCIDRMap("eth42", bpf.IPFamilyV4, net.ParseIP("1.1.1.1"), 16, 1)
	_ = bpfLib.UpdateCIDRMap("eth42", bpf.IPFamilyV4, net.ParseIP("8.8.8.8"), 16, 1)
	_ = bpfLib.LoadXDP("xdp/bpf/generated/xdp.o", "eth42", bpf.XDPGeneric)
}

func dump() {
	fmt.Printf("Failsafe ports:\n")
	pp, err := bpfLib.DumpFailsafeMap()
	if err != nil {
		fmt.Printf("  (error)\n")
	}
	for _, entry := range pp {
		proto := "<unknown>"
		switch entry.Proto {
		case labelindex.ProtocolTCP:
			proto = "TCP"
		case labelindex.ProtocolUDP:
			proto = "UDP"
		case labelindex.ProtocolSCTP:
			proto = "SCTP"
		}
		fmt.Printf("  %s: %d\n", proto, entry.Port)
	}

	fmt.Printf("Interfaces with blacklist:\n")
	ifaces, err := bpfLib.GetXDPIfaces()
	if err != nil {
		log.Fatalf("%v", err)
	}
	if len(ifaces) == 0 {
		fmt.Printf("  (none)\n")
	}
	for _, i := range ifaces {
		fmt.Printf("  %s:\n", i)
		ips, err := bpfLib.DumpCIDRMap(i, bpf.IPFamilyV4)
		if err != nil {
			fmt.Printf("    (error dumping map)\n")
		}
		for k, v := range ips {
			fmt.Printf("    %s value=%d\n", k.ToIPNet(), v)
		}
	}
}

// main is the entry point to the binary.
func main() {
	// Parse command-line args.
	version := "Version:            " + buildinfo.GitVersion + "\n" +
		"Full git commit ID: " + buildinfo.GitRevision + "\n" +
		"Build date:         " + buildinfo.BuildDate + "\n"

	args, err := docopt.ParseArgs(usage, nil, version)
	if err != nil {
		println(usage)
		log.Fatalf("Failed to parse usage, exiting: %v", err)
	}

	bpfLib, err = bpf.NewBPFLib(".")
	if err != nil {
		log.Fatalf("Failed to instantiate BPF library: %v", err)
	}

	if args["populate"] == true {
		populate()
	}

	if args["dump"] == true {
		dump()
	}
}
