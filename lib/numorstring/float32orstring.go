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

package numorstring

import (
	"encoding/json"
	"strconv"
)

// Float32OrString is a type that can hold an float32 or a string.  When used in
// JSON or YAML marshalling and unmarshalling, it produces or consumes the
// inner type.  This allows you to have, for example, a JSON field that can
// accept a name or number.
type Float32OrString struct {
	Type   NumOrStringType
	NumVal float32
	StrVal string
}

// UnmarshalJSON implements the json.Unmarshaller interface.
func (f *Float32OrString) UnmarshalJSON(b []byte) error {
	if b[0] == '"' {
		f.Type = NumOrStringString
		err := json.Unmarshal(b, &f.StrVal)
		if err != nil {
			return err
		}

		// If this string is actually a number then tweak to return
		// a number type.
		num, err := f.NumValue()
		if err == nil {
			f.Type = NumOrStringNum
			f.NumVal = num
		}

		return nil
	}
	f.Type = NumOrStringNum
	return json.Unmarshal(b, &f.NumVal)
}

// String returns the string value, or the Itoa of the int value.
func (f *Float32OrString) String() string {
	if f.Type == NumOrStringString {
		return f.StrVal
	}
	return strconv.Itoa(int(f.NumVal))
}

// NumValue returns the NumVal if type float32, or if
// it is a String, will attempt a conversion to float32.
func (f *Float32OrString) NumValue() (float32, error) {
	if f.Type == NumOrStringString {
		num, err := strconv.ParseFloat(f.StrVal, 32)
		return float32(num), err
	}
	return f.NumVal, nil
}

// MarshalJSON implements the json.Marshaller interface.
func (f Float32OrString) MarshalJSON() ([]byte, error) {
	num, err := f.NumValue()
	if err != nil {
		return json.Marshal(num)
	} else {
		return json.Marshal(f.StrVal)
	}
}
