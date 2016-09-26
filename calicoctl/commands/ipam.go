// Copyright (c) 2016 Tigera, Inc. All rights reserved.

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
	"net"
	"os"

	"github.com/projectcalico/libcalico-go/lib/client"
	cnet "github.com/projectcalico/libcalico-go/lib/net"

	docopt "github.com/docopt/docopt-go"
)

// IPAM takes keyword with an IP address then calls the subcommands.
func IPAM(args []string) error {
	doc := `Usage: 
    calicoctl ipam release --ip=<IP>
    calicoctl ipam show --ip=<IP>

Description:
    IP address management

Options:
    --ip=<IP>     IP address

Warnings:
  -  Releasing an in-use IP address can result in it being assigned to multiple
     workloads.
`

	parsedArgs, err := docopt.Parse(doc, args, true, "calicoctl", false, false)
	if err != nil {
		return err
	}

	// Length of parsedArgs is 0 when `-h` `--help` is passed.
	// Docopt takes care of printing the help message, but we need to
	// return nil here so command doesn't go any further when `-h` is passed.
	if len(parsedArgs) == 0 {
		return nil
	}

	// Create a new backend client from env vars.
	backendClient, err := newClient("")
	if err != nil {
		fmt.Println(err)
	}

	ipamClient := backendClient.IPAM()

	switch args[1] {
	case "show":
		showIP(ipamClient, parsedArgs["--ip"].(string))
	case "release":
		releaseIP(ipamClient, parsedArgs["--ip"].(string))
	}

	return nil
}

// showIP gets the attributes of an IP address, and returns nil if it is assigned
// or an error with a message if not assigned.
func showIP(ipamClient client.IPAMInterface, passedIP string) {
	ip := validateIP(passedIP)
	attr, err := ipamClient.GetAssignmentAttributes(cnet.IP{ip})

	// IP address is not assigned, this prints message like
	// `IP 192.168.71.1 is not assigned in block`. This is not exactly an error,
	// so not returning it to the caller.
	if err != nil {
		fmt.Println(err)
		return
	}

	// IP address is assigned with attributes.
	if len(attr) != 0 {
		fmt.Println(attr)
	} else {
		// IP address is assigned but attributes are not set.
		fmt.Printf("No attributes defined for IP %s\n", ip)
	}
}

// releaseIP releases the IP address passed to it
// or prints an error message if it's not assigned.
func releaseIP(ipamClient client.IPAMInterface, passedIP string) {
	ip := validateIP(passedIP)
	ips := []cnet.IP{cnet.IP{ip}}

	// Call ReleaseIPs releases the IP and returns an empty slice as unallocatedIPs if
	// release was successful else it returns back the slice with the IP passed in.
	unallocatedIPs, err := ipamClient.ReleaseIPs(ips)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}

	// Couldn't release the IP if the slice is not empty or IP might already be released/unassigned.
	// This is not exactly an error, so not returning it to the caller.
	if len(unallocatedIPs) != 0 {
		fmt.Printf("IP address %s is not assigned\n", ip)
		return
	}

	// If unallocatedIPs slice is empty then IP was released Successfully.
	fmt.Printf("Successfully released IP address %s\n", ip)
}

// validateIP takes a string as an inoput and makes sure it's a valid IPv4 or IPv6 address.
func validateIP(str string) net.IP {
	// Parse the input string as an IP address (IPv4 or IPv6).
	// This also validates the IP address.
	ip := net.ParseIP(str)
	if ip == nil {
		fmt.Println("Invalid IP address specified.")
		os.Exit(1)
	}
	return ip
}
