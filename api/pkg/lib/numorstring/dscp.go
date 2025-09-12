// Copyright (c) 2025 Tigera, Inc. All rights reserved.

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
	"fmt"
	"strings"
)

const (
	// Default forwarding, i.e. best effort.
	DF = "DF" //  DSCP value 0

	// Expedited Forwarding
	EF = "EF" // DSCP value 46

	// Assured Forwarding
	AF11 = "AF11" // DSCP value 10
	AF12 = "AF12" // DSCP value 12
	AF13 = "AF13" // DSCP value 14

	AF21 = "AF21" // DSCP value 18
	AF22 = "AF22" // DSCP value 20
	AF23 = "AF23" // DSCP value 22

	AF31 = "AF31" // DSCP value 26
	AF32 = "AF32" // DSCP value 28
	AF33 = "AF33" // DSCP value 30

	AF41 = "AF41" // DSCP value 34
	AF42 = "AF42" // DSCP value 36
	AF43 = "AF43" // DSCP value 38

	// Class selectors, defined in RFC for backward compatibility with IP precedence.
	CS0 = "CS0" // DSCP value 0, similar to DF
	CS1 = "CS1" // DSCP value 8
	CS2 = "CS2" // DSCP value 16
	CS3 = "CS3" // DSCP value 24
	CS4 = "CS4" // DSCP value 32
	CS5 = "CS5" // DSCP value 40
	CS6 = "CS6" // DSCP value 48
)

var (
	AllDSCPValues = map[string]uint8{
		DF: 0,
		EF: 46,

		AF11: 10, AF12: 12, AF13: 14,
		AF21: 18, AF22: 20, AF23: 22,
		AF31: 26, AF32: 28, AF33: 30,
		AF41: 34, AF42: 36, AF43: 38,

		CS0: 0, CS1: 8, CS2: 16,
		CS3: 24, CS4: 32, CS5: 40,
		CS6: 48,
	}
)

type DSCP Uint8OrString

// DSCPFromInt creates a DSCP struct from an integer value.
func DSCPFromInt(v uint8) DSCP {
	return DSCP(
		Uint8OrString{Type: NumOrStringNum, NumVal: v},
	)
}

// DSCPFromString creates a DSCP struct from a string value.
func DSCPFromString(s string) DSCP {
	for k := range AllDSCPValues {
		if strings.EqualFold(k, s) {
			return DSCP(
				Uint8OrString{Type: NumOrStringString, StrVal: k},
			)
		}
	}

	// Unknown protocol - return the value unchanged.  Validation should catch this.
	return DSCP(
		Uint8OrString{Type: NumOrStringString, StrVal: s},
	)
}

func (d *DSCP) ToUint8() uint8 {
	val, err := (*Uint8OrString)(d).NumValue()
	if err == nil {
		return val
	}

	val, valid := AllDSCPValues[strings.ToUpper(strings.TrimSpace(d.StrVal))]
	if !valid {
		return 0
	}
	return val
}

func (d *DSCP) Validate() error {
	// If a number, it must be between 0 and 63.
	val, err := (*Uint8OrString)(d).NumValue()
	if err == nil {
		if val > 63 {
			return fmt.Errorf("DSCP must be between 0 and 63")
		}
		return nil
	}

	// Otherwise, it must be one of the known constant.
	_, valid := AllDSCPValues[strings.ToUpper(strings.TrimSpace(d.StrVal))]
	if !valid {
		return fmt.Errorf("%s is not a valid DSCP value", d.StrVal)
	}
	return nil
}

// UnmarshalJSON implements the json.Unmarshaller interface.
func (d *DSCP) UnmarshalJSON(b []byte) error {
	return (*Uint8OrString)(d).UnmarshalJSON(b)
}

// MarshalJSON implements the json.Marshaller interface.
func (d DSCP) MarshalJSON() ([]byte, error) {
	return Uint8OrString(d).MarshalJSON()
}

// String returns the string value, or the Itoa of the int value.
func (d DSCP) String() string {
	return (Uint8OrString)(d).String()
}

// OpenAPISchemaType is used by the kube-openapi generator when constructing
// the OpenAPI spec of this type.
// See: https://github.com/kubernetes/kube-openapi/tree/master/pkg/generators
func (DSCP) OpenAPISchemaType() []string { return []string{"string"} }

// OpenAPISchemaFormat is used by the kube-openapi generator when constructing
// the OpenAPI spec of this type.
// See: https://github.com/kubernetes/kube-openapi/tree/master/pkg/generators
func (DSCP) OpenAPISchemaFormat() string { return "int-or-string" }
