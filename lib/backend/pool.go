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
	"regexp"
	"strings"

	"reflect"

	"github.com/golang/glog"
	"github.com/tigera/libcalico-go/lib/common"
)

var (
	matchPool = regexp.MustCompile("^/?calico/v1/ipam/v./pool/([^/]+)$")
	typePool  = reflect.TypeOf(Pool{})
)

type PoolKey struct {
	CIDR common.IPNet `json:"-" validate:"required,name"`
}

func (key PoolKey) asEtcdKey() (string, error) {
	if key.CIDR.IP == nil {
		return "", common.ErrorInsufficientIdentifiers{Name: "cidr"}
	}
	c := strings.Replace(key.CIDR.String(), "/", "-", 1)
	e := fmt.Sprintf("/calico/v1/ipam/v%d/pool/%s", key.CIDR.Version(), c)
	return e, nil
}

func (key PoolKey) asEtcdDeleteKey() (string, error) {
	return key.asEtcdKey()
}

func (key PoolKey) valueType() reflect.Type {
	return typePool
}

func (key PoolKey) String() string {
	return fmt.Sprintf("Policy(cidr=%s)", key.CIDR)
}

type PoolListOptions struct {
	CIDR common.IPNet
}

func (options PoolListOptions) asEtcdKeyRoot() string {
	k := "/calico/v1/ipam/"
	if options.CIDR.IP == nil {
		return k
	}
	c := strings.Replace(options.CIDR.String(), "/", "-", 1)
	k = k + fmt.Sprintf("v%d/pool/", options.CIDR.Version()) + fmt.Sprintf("%s", c)
	return k
}

func (options PoolListOptions) keyFromEtcdResult(ekey string) KeyInterface {
	glog.V(2).Infof("Get Pool key from %s", ekey)
	r := matchPool.FindAllStringSubmatch(ekey, -1)
	if len(r) != 1 {
		glog.V(2).Infof("%s didn't match regex", ekey)
		return nil
	}
	cidrStr := strings.Replace(r[0][1], "-", "/", 1)
	_, cidr, _ := common.ParseCIDR(cidrStr)
	if options.CIDR.IP != nil && reflect.DeepEqual(*cidr, options.CIDR) {
		glog.V(2).Infof("Didn't match cidr %s != %s", options.CIDR.String(), cidr.String())
		return nil
	}
	return PoolKey{CIDR: *cidr}
}

type Pool struct {
	CIDR          common.IPNet `json:"cidr"`
	IPIPInterface string       `json:"ipip"`
	Masquerade    bool         `json:"masquerade"`
	Ipam          bool         `json:"ipam"`
	Disabled      bool         `json:"disabled"`
}
