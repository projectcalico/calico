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

package model

import (
	"fmt"
	"reflect"
	"regexp"
	"strings"

	"github.com/projectcalico/libcalico-go/lib/errors"
	"github.com/projectcalico/libcalico-go/lib/net"
	log "github.com/sirupsen/logrus"
	"k8s.io/apimachinery/pkg/types"
)

var (
	matchBlock = regexp.MustCompile("^/?calico/ipam/v2/assignment/ipv./block/([^/]+)$")
	typeBlock  = reflect.TypeOf(AllocationBlock{})
)

type BlockKey struct {
	CIDR net.IPNet  `json:"-" validate:"required,name"`
	UID  *types.UID `json:"-"`
}

func (key BlockKey) defaultPath() (string, error) {
	if key.CIDR.IP == nil {
		return "", errors.ErrorInsufficientIdentifiers{}
	}
	c := strings.Replace(key.CIDR.String(), "/", "-", 1)
	e := fmt.Sprintf("/calico/ipam/v2/assignment/ipv%d/block/%s", key.CIDR.Version(), c)
	return e, nil
}

func (key BlockKey) defaultDeletePath() (string, error) {
	return key.defaultPath()
}

func (key BlockKey) defaultDeleteParentPaths() ([]string, error) {
	return nil, nil
}

func (key BlockKey) valueType() (reflect.Type, error) {
	return typeBlock, nil
}

func (key BlockKey) String() string {
	return fmt.Sprintf("BlockKey(cidr=%s)", key.CIDR.String())
}

type BlockListOptions struct {
	IPVersion int `json:"-"`
}

func (options BlockListOptions) defaultPathRoot() string {
	k := "/calico/ipam/v2/assignment/"
	if options.IPVersion != 0 {
		k = k + fmt.Sprintf("ipv%d/", options.IPVersion)
	}
	return k
}

func (options BlockListOptions) KeyFromDefaultPath(path string) Key {
	log.Debugf("Get Block key from %s", path)
	r := matchBlock.FindAllStringSubmatch(path, -1)
	if len(r) != 1 {
		log.Debugf("%s didn't match regex", path)
		return nil
	}
	cidrStr := strings.Replace(r[0][1], "-", "/", 1)
	_, cidr, _ := net.ParseCIDR(cidrStr)
	return BlockKey{CIDR: *cidr}
}

type AllocationBlock struct {
	CIDR           net.IPNet             `json:"cidr"`
	Affinity       *string               `json:"affinity"`
	StrictAffinity bool                  `json:"strictAffinity"`
	Allocations    []*int                `json:"allocations"`
	Unallocated    []int                 `json:"unallocated"`
	Attributes     []AllocationAttribute `json:"attributes"`
	Deleting       bool                  `json:"deleting"`

	// HostAffinity is deprecated in favor of Affinity.
	// This is only to keep compatiblity with existing deployments.
	// The data format should be `Affinity: host:hostname` (not `hostAffinity: hostname`).
	HostAffinity *string `json:"hostAffinity,omitempty"`
}

type AllocationAttribute struct {
	AttrPrimary   *string           `json:"handle_id"`
	AttrSecondary map[string]string `json:"secondary"`
}
