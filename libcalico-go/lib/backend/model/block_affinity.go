// Copyright (c) 2016-2019 Tigera, Inc. All rights reserved.

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
	"crypto/sha3"
	"encoding/base32"
	"fmt"
	"reflect"
	"regexp"
	"strconv"
	"strings"

	apiv3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	log "github.com/sirupsen/logrus"
	"k8s.io/apimachinery/pkg/labels"

	libapiv3 "github.com/projectcalico/calico/libcalico-go/lib/apis/v3"
	"github.com/projectcalico/calico/libcalico-go/lib/errors"
	"github.com/projectcalico/calico/libcalico-go/lib/net"
)

var (
	matchBlockAffinity = regexp.MustCompile(fmt.Sprintf("^/?calico/ipam/v2/(@|%s|%s)/([^/]+)/ipv./block/([^/]+)$", IPAMAffinityTypeHost, IPAMAffinityTypeVirtual))
	typeBlockAff       = reflect.TypeOf(BlockAffinity{})
)

type BlockAffinityState string

const (
	StateConfirmed       BlockAffinityState = "confirmed"
	StatePending         BlockAffinityState = "pending"
	StatePendingDeletion BlockAffinityState = "pendingDeletion"
)

type BlockAffinityKey struct {
	CIDR         net.IPNet `json:"-" validate:"required,name"`
	Host         string    `json:"-"`
	AffinityType string    `json:"-"`
}

type BlockAffinity struct {
	State   BlockAffinityState `json:"state"`
	Deleted bool               `json:"deleted"`
}

func (key BlockAffinityKey) defaultPath() (string, error) {
	if key.CIDR.IP == nil || key.Host == "" {
		return "", errors.ErrorInsufficientIdentifiers{}
	}

	affinityType := key.AffinityType
	if affinityType == "" {
		affinityType = IPAMAffinityTypeHost
	}

	c := strings.Replace(key.CIDR.String(), "/", "-", 1)
	e := fmt.Sprintf("/calico/ipam/v2/%s/%s/ipv%d/block/%s", affinityType, key.Host, key.CIDR.Version(), c)
	return e, nil
}

func (key BlockAffinityKey) defaultDeletePath() (string, error) {
	return key.defaultPath()
}

func (key BlockAffinityKey) defaultDeleteParentPaths() ([]string, error) {
	return nil, nil
}

func (key BlockAffinityKey) valueType() (reflect.Type, error) {
	return typeBlockAff, nil
}

func (key BlockAffinityKey) parseValue(rawData []byte) (any, error) {
	if len(rawData) == 0 {
		// Special case: block affinities used to be stored with no value.
		// "Upgrade" to equivalent empty JSON.
		rawData = []byte("{}")
	}
	return parseJSONPointer[BlockAffinity](key, rawData)
}

func (key BlockAffinityKey) String() string {
	return fmt.Sprintf("BlockAffinityKey(cidr=%s, host=%s, affinityType=%s)", key.CIDR, key.Host, key.AffinityType)
}

type BlockAffinityListOptions struct {
	Host         string
	AffinityType string
	IPVersion    int
}

func (options BlockAffinityListOptions) defaultPathRoot() string {
	k := "/calico/ipam/v2/"

	if options.AffinityType != "" {
		k = k + options.AffinityType + "/"
	} else {
		k = k + IPAMAffinityTypeHost + "/"
	}

	if options.Host != "" {
		k = k + options.Host

		if options.IPVersion != 0 {
			k = k + fmt.Sprintf("/ipv%d/block", options.IPVersion)
		}
	}
	return k
}

func (options BlockAffinityListOptions) KeyFromDefaultPath(path string) Key {
	log.Debugf("Get Block affinity key from %s", path)
	r := matchBlockAffinity.FindAllStringSubmatch(path, -1)
	if len(r) != 1 {
		log.Debugf("%s didn't match regex", path)
		return nil
	}
	cidrStr := strings.Replace(r[0][3], "-", "/", 1)
	_, cidr, _ := net.ParseCIDR(cidrStr)
	if cidr == nil {
		log.Debugf("Failed to parse CIDR in block affinity path: %q", path)
		return nil
	}
	host := r[0][2]
	affinityType := r[0][1]

	if options.Host != "" && options.Host != host {
		log.Debugf("Didn't match hostname: %s != %s", options.Host, host)
		return nil
	}
	if options.IPVersion != 0 && options.IPVersion != cidr.Version() {
		log.Debugf("Didn't match IP version. %d != %d", options.IPVersion, cidr.Version())
		return nil
	}
	return BlockAffinityKey{
		CIDR:         *cidr,
		Host:         host,
		AffinityType: affinityType,
	}
}

func EnsureBlockAffinityLabels(ba *libapiv3.BlockAffinity) {
	if ba.Labels == nil {
		ba.Labels = make(map[string]string)
	}
	// Hostnames can be longer than labels are allowed to be, so we hash it down.
	ba.Labels[apiv3.LabelHostnameHash] = hashHostnameForLabel(ba.Spec.Node)
	ba.Labels[apiv3.LabelAffinityType] = ba.Spec.Type
	var ipVersion string
	if strings.Contains(ba.Spec.CIDR, ":") {
		ipVersion = "6"
	} else {
		ipVersion = "4"
	}
	ba.Labels[apiv3.LabelIPVersion] = ipVersion
}

func CalculateBlockAffinityLabelSelector(list BlockAffinityListOptions) labels.Selector {
	labelsToMatch := map[string]string{}
	if list.Host != "" {
		labelsToMatch[apiv3.LabelHostnameHash] = hashHostnameForLabel(list.Host)
	}
	if list.AffinityType != "" {
		labelsToMatch[apiv3.LabelAffinityType] = list.AffinityType
	}
	if list.IPVersion != 0 {
		labelsToMatch[apiv3.LabelIPVersion] = strconv.Itoa(list.IPVersion)
	}
	var labelSelector labels.Selector
	if len(labelsToMatch) > 0 {
		labelSelector = labels.SelectorFromSet(labelsToMatch)
	}
	return labelSelector
}

var base32StdNoPad = base32.StdEncoding.WithPadding(base32.NoPadding)

func hashHostnameForLabel(hostname string) string {
	// The max length of a label is 63 chars, so we use base32 to squeeze in
	// 256 bits.
	h := sha3.Sum256([]byte(hostname))
	return base32StdNoPad.EncodeToString(h[:])
}
