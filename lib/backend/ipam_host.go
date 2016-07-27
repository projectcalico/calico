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

package backend

import (
	"github.com/tigera/libcalico-go/lib/common"
	"reflect"
)

var (
	typeIPAMHost = reflect.TypeOf(IPAMHost{})
)

type IPAMHostKey struct {
	Host string
}

func (key IPAMHostKey) asEtcdKey() (string, error) {
	if key.Host == "" {
		return "", common.ErrorInsufficientIdentifiers{Name: "host"}
	}

	k := "/calico/ipam/v2/host/" + key.Host
	return k, nil
}

func (key IPAMHostKey) asEtcdDeleteKey() (string, error) {
	return key.asEtcdKey()
}

func (key IPAMHostKey) valueType() reflect.Type {
	return typeIPAMHost
}

type IPAMHost struct {
}
