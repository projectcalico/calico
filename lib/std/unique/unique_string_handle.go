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

package unique

import (
	"encoding"
	"fmt"
	"unique"
)

func Make(s string) String {
	return String(unique.Make(s))
}

// String is an alias for unique.String that supports JSON
// serialization.  The serialized form is simply the underlying string.
type String unique.Handle[string]

//goland:noinspection GoMixedReceiverTypes
func (s String) MarshalText() (text []byte, err error) {
	str := s.Value()
	return []byte(str), nil
}

//goland:noinspection GoMixedReceiverTypes
func (s *String) UnmarshalText(text []byte) error {
	str := string(text)
	h := unique.Make(str)
	*s = String(h)
	return nil
}

var _ encoding.TextMarshaler = String{}
var _ encoding.TextUnmarshaler = &String{}

//goland:noinspection GoMixedReceiverTypes
func (s String) Value() string {
	return unique.Handle[string](s).Value()
}

type SliceStringer []String

func (s SliceStringer) String() string {
	parts := make([]string, len(s))
	for i, h := range s {
		parts[i] = h.Value()
	}
	return fmt.Sprint(parts)
}
