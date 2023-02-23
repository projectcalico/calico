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

package converters

import (
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"net"
	"regexp"
	"strings"
)

var (
	nonNameChar               = regexp.MustCompile("[^-.a-z0-9]+")
	dotDashSeq                = regexp.MustCompile("[.-]*[.][.-]*")
	trailingLeadingDotsDashes = regexp.MustCompile("^[.-]*(.*?)[.-]*$")
)

// Convert the v1 node name to a standard v3 name.  This uses the standard name normalization
// but does not add a qualifier.  Any overlapping names will result in a failed upgrade, so the
// pre-upgrade validation script will check for conflicting names.
func ConvertNodeName(v1Name string) string {
	return normalizeName(v1Name)
}

// Convert a name to normalized form.  This is used for conversion of os.Hostname to a
// suitable node name, and is also used for the v2->v3 migration code.
// -  Convert to lowercase
// -  Convert [/] to .
// -  Convert any other char that is not in the set [-.a-z0-9] to -
// -  Convert any multi-byte sequence of [-.] with at least one [.] to a single .
// -  Remove leading and trailing dashes and dots
func normalizeName(name string) string {
	name = strings.ToLower(name)
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

// Convert the v1 name to a standard v3 name.  This uses the standard name normalization,
// and adds an additional qualifier if the name was modified.  The qualifier is calculated
// from the original name.
func convertName(v1Name string) string {
	name := normalizeName(v1Name)

	// If the name is different append a qualifier.
	return qualifiedName(v1Name, name)
}

// Convert the v1 name to a standard v3 name with no dots.
func convertNameNoDots(v1Name string) string {
	// Normalize the name and then convert dots to dashes.
	name := normalizeName(v1Name)
	name = strings.Replace(name, ".", "-", -1)

	// If the name is different append a qualifier.
	return qualifiedName(v1Name, name)
}

func qualifiedName(orig, final string) string {
	// If the name was not modified, just return the unmodified name.
	if orig == final {
		return orig
	}
	// The name was modified.  Calculate an 8-byte hex qualifier to append.
	h := sha1.New()
	h.Write([]byte(orig))
	return fmt.Sprintf("%s-%s", final, strings.ToLower(hex.EncodeToString(h.Sum(nil))[:8]))
}

// Convert an IP to an IPv4 or IPv6 representation
//   - IPv4 addresses will be of the format 1-2-3-4
//   - IPv6 addresses will be of the format 00aa-00bb-0000-0000-0000-0000-0000-0000
//     with all zeros expanded
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
