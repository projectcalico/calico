// Copyright (c) 2016-2023 Tigera, Inc. All rights reserved.

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

package selector

import (
	"strings"

	"github.com/projectcalico/calico/libcalico-go/lib/selector/parser"
)

// Selector represents a label selector.
type Selector interface {
	// Evaluate evaluates the selector against the given labels expressed as a concrete map.
	Evaluate(labels map[string]string) bool

	// EvaluateLabels evaluates the selector against the given labels expressed as an interface.
	// This allows for labels that are calculated on the fly.
	EvaluateLabels(labels parser.Labels) bool

	// String returns a string that represents this selector.
	String() string

	// UniqueID returns the unique ID that represents this selector.
	UniqueID() string

	LabelRestrictions() map[string]parser.LabelRestriction
}

// Parse a string representation of a selector expression into a Selector.
func Parse(selector string) (sel Selector, err error) {
	return parser.Parse(selector)
}

// Validate checks the syntax of the given selector.
func Validate(selector string) (err error) {
	return parser.Validate(selector)
}

// Normalise converts the given selector to the form returned by
// Selector.String(), i.e. "" is converted to "all()" and whitespace is
// tidied up.  If the input string cannot be parsed, it is returned unaltered.
func Normalise(selector string) string {
	selector = strings.TrimSpace(selector)
	parsed, err := Parse(selector)
	if err != nil {
		return selector
	}
	return parsed.String()
}
