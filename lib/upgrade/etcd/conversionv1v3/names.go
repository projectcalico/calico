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

package conversionv1v3

import (
	"fmt"
	"net"
	"regexp"
	"strings"
)

var (
	nonNameChar               = regexp.MustCompile("[^-.a-z0-9]+")
	nonNameNoDotChar          = regexp.MustCompile("[^-a-z0-9]+")
	dotDashSeq                = regexp.MustCompile("[.-]*[.][.-]*")
	trailingLeadingDotsDashes = regexp.MustCompile("^[.-]*(.*?)[.-]*$")
)

// Convert the v1 name to a standard v3 name.  This converts as follows (in the
// listed order):
// -  Convert to lowercase
// -  Convert [/] to .
// -  Convert any other char that is not in the set [-.a-z0-9] to -
// -  Convert any multi-byte sequence of [-.] with at least one [.] to a single .
// -  Remove leading and trailing dashes and dots
func convertName(v1Name string) string {
	name := strings.ToLower(v1Name)
	name = strings.Replace(name, "/", ".", -1)
	name = nonNameChar.ReplaceAllString(name, "-")
	name = dotDashSeq.ReplaceAllString(name, ".")

	// Extract the trailing and leading dots and dashes.   This should always match even if
	// the matched substring is empty.  The second item in the returned submatch
	// slice is the captured match group.
	submatches := trailingLeadingDotsDashes.FindStringSubmatch(name)
	name = submatches[1]
	return name
}

// Convert the v1 name to a standard v3 name with no dots.
// -  Convert to lowercase
// -  Convert any char that is not in the set [-a-z0-9] to -
// -  Remove leading and trailing dashes
func convertNameNoDots(v1Name string) string {
	name := strings.ToLower(v1Name)
	name = nonNameNoDotChar.ReplaceAllString(name, "-")

	// Extract the trailing and leading dashes (there are no dots by this point).
	// This should always match even if the matched substring is empty.  The second
	// item in the returned submatc
	// slice is the captured match group.
	submatches := trailingLeadingDotsDashes.FindStringSubmatch(name)
	name = submatches[1]
	return name
}

// Convert an IP to an IPv4 or IPv6 representation
// - IPv4 addresses will be of the format 1-2-3-4
// - IPv6 addresses will be of the format 00aa-00bb-0000-0000-0000-0000-0000-0000
//   with all zeros expanded
func convertIpToName(ip net.IP) string {
	name := ""
	if ip.To4() != nil {
		name = strings.Replace(ip.String(), ".", "-", 3)
	} else {
		ip6 := ip.To16()
		bytes := []string{}
		for i := 0; i < len(ip6); i += 2 {
			bytes = append(bytes, fmt.Sprintf("%.2x%.2x", ip6[i], ip6[i+1]))
		}
		name = strings.Join(bytes, "-")
	}

	return name
}
