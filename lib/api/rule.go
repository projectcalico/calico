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

package api

import (
	"reflect"

	. "github.com/tigera/libcalico-go/lib/types"
	. "github.com/tigera/libcalico-go/lib/validator"
	"gopkg.in/go-playground/validator.v8"
)

type Rule struct {
	Action string `json:"action" validate:"action"`

	Protocol *Protocol `json:"protocol,omitempty" validate:"omitempty"`
	ICMPType *int      `json:"icmpType,omitempty" validate:"omitempty,gte=0,lte=255"`
	ICMPCode *int      `json:"icmpCode,omitempty" validate:"omitempty,gte=0,lte=255"`

	NotProtocol *Protocol `json:"!protocol,omitempty" validate:"omitempty"`
	NotICMPType *int      `json:"!icmpType,omitempty" validate:"omitempty,gte=0,lte=255"`
	NotICMPCode *int      `json:"!icmpCode,omitempty" validate:"omitempty,gte=0,lte=255"`

	Source      EntityRule `json:"source,omitempty" validate:"omitempty"`
	Destination EntityRule `json:"destination,omitempty" validate:"omitempty"`
}

type EntityRule struct {
	Tag      string `json:"tag,omitempty" validate:"omitempty,tag"`
	Net      *IPNet `json:"net,omitempty" validate:"omitempty"`
	Selector string `json:"selector,omitempty" validate:"omitempty,selector"`
	Ports    []Port `json:"ports,omitempty" validate:"omitempty,dive"`

	NotTag      string `json:"!tag,omitempty" validate:"omitempty,tag"`
	NotNet      *IPNet `json:"!net,omitempty" validate:"omitempty"`
	NotSelector string `json:"!selector,omitempty" validate:"omitempty,selector"`
	NotPorts    []Port `json:"!ports,omitempty" validate:"omitempty,dive"`
}

// Register v1 structure validators to validate cross-field dependencies in any of the
// required structures.
func init() {
	RegisterStructValidator(validateRule, Rule{})
}

func validateRule(v *validator.Validate, structLevel *validator.StructLevel) {
	rule := structLevel.CurrentStruct.Interface().(Rule)
	if rule.ICMPCode != nil && rule.ICMPType == nil {
		structLevel.ReportError(reflect.ValueOf(rule.ICMPCode), "ICMPCode", "icmpCode", "icmpCodeWithoutType")
	}

	// TODO other cross-struct validation
}
