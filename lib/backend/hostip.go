// Copyright (c) 2016 Tigera, Inc. All rights reserved.
//
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
	"fmt"
	"reflect"
	"regexp"
)

var (
	matchHostIp = regexp.MustCompile(`^/?calico/v1/host/([^/]+)/bird_ip`)
)

// TODO find a place to put this
type HostIPKey struct {
	Hostname string
}

func (key HostIPKey) asEtcdKey() (string, error) {
	return fmt.Sprintf("/calico/v1/host/%s/bird_ip",
		key.Hostname), nil
}

func (key HostIPKey) asEtcdDeleteKey() (string, error) {
	return key.asEtcdKey()
}

func (key HostIPKey) valueType() reflect.Type {
	return reflect.TypeOf(HostIP{})
}

type HostIP struct {
}
