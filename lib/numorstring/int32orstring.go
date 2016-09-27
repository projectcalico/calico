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

// Int32OrString is a type that can hold an int32 or a string.  When used in
// JSON or YAML marshalling and unmarshalling, it produces or consumes the
// inner type.  This allows you to have, for example, a JSON field that can
// accept a name or number.
type Int32OrString struct {
	Type   NumOrStringType
	NumVal int32
	StrVal string
}

// UnmarshalJSON implements the json.Unmarshaller interface.
func (i *Int32OrString) UnmarshalJSON(b []byte) error {
	if b[0] == '"' {
		i.Type = NumOrStringString
		err := json.Unmarshal(b, &i.StrVal)
		if err != nil {
			return err
		}

		// If this string is actually a number then tweak to return
		// a number type.
		num, err := i.NumValue()
		if err == nil {
			i.Type = NumOrStringNum
			i.NumVal = num
		}

		return nil
	}
	i.Type = NumOrStringNum
	return json.Unmarshal(b, &i.NumVal)
}

// String returns the string value, or the Itoa of the int value.
func (i *Int32OrString) String() string {
	if i.Type == NumOrStringString {
		return i.StrVal
	}
	return strconv.Itoa(int(i.NumVal))
}

// NumValue returns the NumVal if type Int, or if
// it is a String, will attempt a conversion to int.
func (i *Int32OrString) NumValue() (int32, error) {
	if i.Type == NumOrStringString {
		num, err := strconv.ParseInt(i.StrVal, 10, 32)
		return int32(num), err
	}
	return i.NumVal, nil
}

// MarshalJSON implements the json.Marshaller interface.
func (i Int32OrString) MarshalJSON() ([]byte, error) {
	num, err := i.NumValue()
	if err != nil {
		return json.Marshal(num)
	} else {
		return json.Marshal(i.StrVal)
	}
}
