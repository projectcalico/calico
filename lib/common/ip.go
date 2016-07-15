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

package common

import (
	"encoding/json"
	"net"
)

// Sub class net.IP so that we can add JSON marshalling and unmarshalling.
type IP struct {
	net.IP
}

// Sub class net.IPNet so that we can add JSON marshalling and unmarshalling.
type IPNet struct {
	net.IPNet
}

// MarshalJSON interface for an IP
func (i *IP) MarshalJSON() ([]byte, error) {
	s, err := i.MarshalText()
	if err != nil {
		return nil, err
	}
	return json.Marshal(string(s))
}

// UnmarshalJSON interface for an IP
func (i *IP) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	return i.UnmarshalText([]byte(s))
}

// MarshalJSON interface for an IPNet
func (i *IPNet) MarshalJSON() ([]byte, error) {
	return json.Marshal(i.String())
}

// UnmarshalJSON interface for an IPNet
func (i *IPNet) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	if _, ipnet, err := net.ParseCIDR(s); err != nil {
		return err
	} else {
		i.IP = ipnet.IP
		i.Mask = ipnet.Mask

		return nil
	}
}
