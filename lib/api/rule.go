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

	. "github.com/tigera/libcalico-go/lib/net"
	. "github.com/tigera/libcalico-go/lib/numorstring"
	. "github.com/tigera/libcalico-go/lib/validator"
	"gopkg.in/go-playground/validator.v8"
)

type Rule struct {
	Action string `json:"action" validate:"action"`

	Protocol *Protocol   `json:"protocol,omitempty" validate:"omitempty"`
	ICMP     *ICMPFields `json:"icmp,omitempty" validate:"omitempty"`

	NotProtocol *Protocol   `json:"!protocol,omitempty" validate:"omitempty"`
	NotICMP     *ICMPFields `json:"!icmp,omitempty" validate:"omitempty"`

	Source      EntityRule `json:"source,omitempty" validate:"omitempty"`
	Destination EntityRule `json:"destination,omitempty" validate:"omitempty"`
}

// ICMPFields defines structure for ICMP and NotICMP sub-struct for ICMP code and type
type ICMPFields struct {
	Type *int `json:"type,omitempty" validate:"omitempty,gte=0,lte=255"`
	Code *int `json:"code,omitempty" validate:"omitempty,gte=0,lte=255"`
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
	if rule.ICMP != nil && rule.ICMP.Code != nil && rule.ICMP.Type == nil {
		structLevel.ReportError(reflect.ValueOf(rule.ICMP.Code), "Code", "code", "icmpCodeWithoutType")
	}

	if rule.NotICMP != nil && rule.NotICMP.Code != nil && rule.NotICMP.Type == nil {
		structLevel.ReportError(reflect.ValueOf(rule.NotICMP.Code), "Code", "code", "icmpCodeWithoutType")
	}

	// TODO other cross-struct validation
}
