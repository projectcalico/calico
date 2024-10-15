// Copyright (c) 2017 Tigera, Inc. All rights reserved.

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

package resources

import (
	"fmt"
	"strings"

	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/libcalico-go/lib/net"
)

// This file contains various name conversion methods that can be used to convert
// between Calico key types and resource names.

// IPToResourceName converts an IP address to a name used for a k8s resource.
func IPToResourceName(ip net.IP) string {
	name := ""

	if ip.To4() != nil {
		name = strings.Replace(ip.String(), ".", "-", 3)
	} else {
		// IPv6 address can end in a "::" which would be a string ending in "--",
		// which is not allowed in k8s name field, so we expand the IPv6 address and then replace ":" with "-".
		// fe08:123:445:: will look like fe08-0123-0445-0000-0000-0000-0000-0000
		ip6 := ip.To16()
		bytes := []string{}

		// Go through pairs of bytes in the address and convert them to a hex string.
		for i := 0; i < len(ip6); i += 2 {
			bytes = append(bytes, fmt.Sprintf("%.2x%.2x", ip6[i], ip6[i+1]))
		}

		// Combine them all into a name.
		name = strings.Join(bytes, "-")
	}

	log.WithFields(log.Fields{
		"Name": name,
		"IP":   ip.String(),
	}).Debug("Converting IP to resource name")

	return name
}

// ResourceNameToIP converts a name used for a k8s resource to an IP address.
func ResourceNameToIP(name string) (*net.IP, error) {
	ip := net.ParseIP(resourceNameToIPString(name))
	if ip == nil {
		return nil, fmt.Errorf("invalid resource name %s: does not follow Calico IP name format", name)
	}
	return ip, nil
}

// resourceNameToIPString converts a name used for a k8s resource to an IP address string.
// This function does not check the validity of the result - it merely reverses the
// character conversion used to convert an IP address to a k8s compatible name.
func resourceNameToIPString(name string) string {
	// The IP address is stored in the name with periods and colons replaced
	// by dashes.  To determine if this is IPv4 or IPv6 count the dashes. If
	// either of the following are true, it's IPv6:
	// -  There is a "--"
	// -  The number of "-" is greater than 3.
	var ipstr string
	if strings.Contains(name, "--") || strings.Count(name, "-") > 3 {
		// IPv6:  replace - with :
		ipstr = strings.Replace(name, "-", ":", 7)
	} else {
		// IPv4:  replace - with .
		ipstr = strings.Replace(name, "-", ".", 3)
	}

	log.WithFields(log.Fields{
		"Name": name,
		"IP":   ipstr,
	}).Debug("Converting resource name to IP String")
	return ipstr
}
