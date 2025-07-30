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

package uniquestr

import (
	"encoding"
	"fmt"
	"unique"
)

func Make(s string) Handle {
	return Handle(unique.Make(s))
}

// Handle is an alias for unique.Handle[string] that supports JSON
// serialization.  The serialized form is simply the underlying string.
type Handle unique.Handle[string]

// MarshalText implements JSON marshalling, must be defined on the value receiver.
// The handle is marshalled as the underlying string.
func (s Handle) MarshalText() (text []byte, err error) {
	str := s.Value()
	return []byte(str), nil
}

// UnmarshalText implements JSON unmarshalling, must be defined on the pointer receiver.
func (s *Handle) UnmarshalText(text []byte) error {
	str := string(text)
	h := unique.Make(str)
	*s = Handle(h)
	return nil
}

var _ encoding.TextMarshaler = Handle{}
var _ encoding.TextUnmarshaler = &Handle{}

//goland:noinspection GoMixedReceiverTypes
func (s Handle) Value() string {
	return unique.Handle[string](s).Value()
}

type HandleSliceStringer []Handle

func (s HandleSliceStringer) String() string {
	parts := make([]string, len(s))
	for i, h := range s {
		parts[i] = h.Value()
	}
	return fmt.Sprint(parts)
}
