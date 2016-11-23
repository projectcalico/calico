// Copyright (c) 2016 Tigera, Inc. All rights reserved.
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

package numorstring

import (
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

type Port struct {
	MinPort uint16
	MaxPort uint16
}

// SinglePort creates a Port struct representing a single port.
func SinglePort(port uint16) Port {
	return Port{port, port}
}

// PortFromRange creates a Port struct representing a range of ports.
func PortFromRange(minPort, maxPort uint16) (Port, error) {
	port := Port{minPort, maxPort}
	if minPort > maxPort {
		msg := fmt.Sprintf("minimum port number (%d) is greater than maximum port number (%d) in port range", minPort, maxPort)
		return port, errors.New(msg)
	}
	return port, nil
}

// PortFromString creates a Port struct from its string representation.  A port
// may either be single value "1234" or a range of values "100:200".
func PortFromString(s string) (Port, error) {
	if num, err := strconv.ParseUint(s, 10, 16); err == nil {
		return SinglePort(uint16(num)), nil
	}

	parts := strings.Split(s, ":")
	if len(parts) != 2 {
		msg := fmt.Sprintf("invalid port format (%s)", s)
		return Port{}, errors.New(msg)
	}

	if pmin, err := strconv.ParseUint(parts[0], 10, 16); err != nil {
		msg := fmt.Sprintf("invalid minimum port number in range (%s)", s)
		return Port{}, errors.New(msg)
	} else if pmax, err := strconv.ParseUint(parts[1], 10, 16); err != nil {
		msg := fmt.Sprintf("invalid maximum port number in range (%s)", s)
		return Port{}, errors.New(msg)
	} else {
		return PortFromRange(uint16(pmin), uint16(pmax))
	}
}

// UnmarshalJSON implements the json.Unmarshaller interface.
func (p *Port) UnmarshalJSON(b []byte) error {
	if b[0] == '"' {
		var s string
		if err := json.Unmarshal(b, &s); err != nil {
			return err
		}

		if v, err := PortFromString(s); err != nil {
			return err
		} else {
			*p = v
			return nil
		}
	}

	// It's not a string, it must be a single int.
	var i uint16
	if err := json.Unmarshal(b, &i); err != nil {
		return err
	}
	v := SinglePort(i)
	*p = v
	return nil
}

// MarshalJSON implements the json.Marshaller interface.
func (p Port) MarshalJSON() ([]byte, error) {
	if p.MinPort == p.MaxPort {
		return json.Marshal(p.MinPort)
	} else {
		return json.Marshal(p.String())
	}
}

// String returns the string value.  If the min and max port are the same
// this returns a single string representation of the port number, otherwise
// if returns a colon separated range of ports.
func (p Port) String() string {
	if p.MinPort == p.MaxPort {
		return strconv.FormatUint(uint64(p.MinPort), 10)
	} else {
		return fmt.Sprintf("%d:%d", p.MinPort, p.MaxPort)
	}
}
