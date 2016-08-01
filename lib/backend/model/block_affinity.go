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

	"github.com/golang/glog"
	"github.com/tigera/libcalico-go/lib/errors"
	"github.com/tigera/libcalico-go/lib/net"
)

var (
	matchBlockAffinity = regexp.MustCompile("^/?calico/ipam/v2/host/([^/]+)/ipv./block/([^/]+)$")
	typeBlockAff       = reflect.TypeOf(BlockAffinity{})
)

type BlockAffinityKey struct {
	CIDR net.IPNet `json:"-" validate:"required,name"`
	Host string    `json:"-"`
}

func (key BlockAffinityKey) DefaultPath() (string, error) {
	if key.CIDR.IP == nil || key.Host == "" {
		return "", errors.ErrorInsufficientIdentifiers{}
	}
	c := strings.Replace(key.CIDR.String(), "/", "-", 1)
	e := fmt.Sprintf("/calico/ipam/v2/host/%s/ipv%d/block/%s", key.Host, key.CIDR.Version(), c)
	return e, nil
}

func (key BlockAffinityKey) DefaultDeletePath() (string, error) {
	return key.DefaultPath()
}

func (key BlockAffinityKey) valueType() reflect.Type {
	return typeBlockAff
}

type BlockAffinityListOptions struct {
	Host      string
	IPVersion int
}

func (options BlockAffinityListOptions) DefaultPathRoot() string {
	k := "/calico/ipam/v2/host/"
	if options.Host != "" {
		k = k + options.Host

		if options.IPVersion != 0 {
			k = k + fmt.Sprintf("/ipv%d/block", options.IPVersion)
		}
	}
	return k
}

func (options BlockAffinityListOptions) ParseDefaultKey(ekey string) Key {
	glog.V(2).Infof("Get Block affinity key from %s", ekey)
	r := matchBlockAffinity.FindAllStringSubmatch(ekey, -1)
	if len(r) != 1 {
		glog.V(2).Infof("%s didn't match regex", ekey)
		return nil
	}
	cidrStr := strings.Replace(r[0][2], "-", "/", 1)
	_, cidr, _ := net.ParseCIDR(cidrStr)
	host := r[0][1]

	if options.Host != host {
		glog.V(3).Infof("Didn't match hostname: %s != %s", options.Host, host)
		return nil
	}
	if options.IPVersion != cidr.Version() {
		glog.V(3).Infof("Didn't match IP version. %d != %d", options.IPVersion, cidr.Version())
		return nil
	}
	return BlockAffinityKey{CIDR: *cidr, Host: host}
}

type BlockAffinity struct {
}
