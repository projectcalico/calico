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
	"fmt"
	"reflect"
	"regexp"
	"strings"

	"github.com/golang/glog"
	"github.com/tigera/libcalico-go/lib/common"
)

var (
	matchBlock = regexp.MustCompile("^/?/calico/ipam/v2/assignment/ipv./block/([^/]+)$")
	typeBlock  = reflect.TypeOf(AllocationBlock{})
)

type BlockKey struct {
	CIDR common.IPNet `json:"-" validate:"required,name"`
}

func (key BlockKey) asEtcdKey() (string, error) {
	if key.CIDR.IP == nil {
		return "", common.ErrorInsufficientIdentifiers{}
	}
	c := strings.Replace(key.CIDR.String(), "/", "-", 1)
	e := fmt.Sprintf("/calico/ipam/v2/assignment/ipv%d/block/%s", key.CIDR.Version(), c)
	return e, nil
}

func (key BlockKey) asEtcdDeleteKey() (string, error) {
	return key.asEtcdKey()
}

func (key BlockKey) valueType() reflect.Type {
	return typeBlock
}

type BlockListOptions struct {
	// TODO: Have some options here?
}

func (options BlockListOptions) asEtcdKeyRoot() string {
	k := "/calico/ipam/v2/assignment/"
	return k
}

func (options BlockListOptions) keyFromEtcdResult(ekey string) KeyInterface {
	glog.V(2).Infof("Get Block key from %s", ekey)
	r := matchBlock.FindAllStringSubmatch(ekey, -1)
	if len(r) != 1 {
		glog.V(2).Infof("%s didn't match regex", ekey)
		return nil
	}
	cidrStr := strings.Replace(r[0][1], "-", "/", 1)
	_, cidr, _ := common.ParseCIDR(cidrStr)
	return BlockKey{CIDR: *cidr}
}

type AllocationBlock struct {
	CIDR           common.IPNet          `json:"cidr"`
	HostAffinity   *string               `json:"hostAffinity"`
	StrictAffinity bool                  `json:"strictAffinity"`
	Allocations    []*int                `json:"allocations"`
	Unallocated    []int                 `json:"unallocated"`
	Attributes     []AllocationAttribute `json:"attributes"`
}

type AllocationAttribute struct {
	AttrPrimary   *string           `json:"handle_id"`
	AttrSecondary map[string]string `json:"secondary"`
}
