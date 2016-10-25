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

package ipam

import (
	"fmt"
	"net"
	"os"
)

// validateIP takes a string as an input and makes sure it's a valid IPv4 or IPv6 address.
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
