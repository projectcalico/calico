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

type Protocol struct {
	Int32OrString
}

func ProtocolFromInt(p int32) Protocol {
	return Protocol{
		Int32OrString{Type: NumOrStringNum, NumVal: p},
	}
}

func ProtocolFromString(p string) Protocol {
	return Protocol{
		Int32OrString{Type: NumOrStringString, StrVal: p},
	}
}

// SupportsPorts returns whether this protocol supports ports.  This returns true if
// the numerical or string verion of the protocol indicates TCP (6) or UDP (17).
func (p Protocol) SupportsPorts() bool {
	num, err := p.NumValue()
	if err == nil {
		return num == 6 || num == 17
	} else {
		return p.StrVal == "tcp" || p.StrVal == "udp"
	}
}
