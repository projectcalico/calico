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
	"regexp"

	"reflect"

	log "github.com/Sirupsen/logrus"
	"github.com/projectcalico/libcalico-go/lib/errors"
	"github.com/projectcalico/libcalico-go/lib/net"
	"github.com/projectcalico/libcalico-go/lib/numorstring"
	"github.com/projectcalico/libcalico-go/lib/scope"
)

var (
	matchGlobalBGPPeer = regexp.MustCompile("^/?calico/bgp/v1/global/peer_v./([^/]+)$")
	matchHostBGPPeer   = regexp.MustCompile("^/?calico/bgp/v1/host/([^/]+)/peer_v./([^/]+)$")
	typeBGPPeer        = reflect.TypeOf(BGPPeer{})
)

type BGPPeerKey struct {
	Scope    scope.Scope `json:"-" validate:"omitempty"`
	Hostname string      `json:"-" validate:"omitempty"`
	PeerIP   net.IP      `json:"-" validate:"required"`
}

func (key BGPPeerKey) defaultPath() (string, error) {
	if key.PeerIP.IP == nil {
		return "", errors.ErrorInsufficientIdentifiers{Name: "peerIP"}
	}
	switch key.Scope {
	case scope.Undefined:
		return "", errors.ErrorInsufficientIdentifiers{Name: "scope"}
	case scope.Global:
		if key.Hostname != "" {
			return "", fmt.Errorf("hostname should not be specified when BGP peer scope is global")
		}
		e := fmt.Sprintf("/calico/bgp/v1/global/peer_v%d/%s",
			key.PeerIP.Version(), key.PeerIP)
		return e, nil
	case scope.Node:
		if key.Hostname == "" {
			return "", errors.ErrorInsufficientIdentifiers{Name: "hostname"}
		}
		e := fmt.Sprintf("/calico/bgp/v1/host/%s/peer_v%d/%s",
			key.Hostname, key.PeerIP.Version(), key.PeerIP)
		return e, nil
	default:
		return "", fmt.Errorf("invalid scope value: %d", key.Scope)
	}
}

func (key BGPPeerKey) defaultDeletePath() (string, error) {
	return key.defaultPath()
}

func (key BGPPeerKey) defaultDeleteParentPaths() ([]string, error) {
	return nil, nil
}

func (key BGPPeerKey) valueType() reflect.Type {
	return typeBGPPeer
}

func (key BGPPeerKey) String() string {
	if key.Scope == scope.Global {
		return fmt.Sprintf("BGPPeer(global, ip=%s)", key.PeerIP)
	} else {
		return fmt.Sprintf("BGPPeer(hostname=%s, ip=%s)", key.Hostname, key.PeerIP)
	}
}

type BGPPeerListOptions struct {
	Scope    scope.Scope `json:"-" validate:"omitempty"`
	Hostname string
	PeerIP   net.IP
}

func (options BGPPeerListOptions) defaultPathRoot() string {
	switch options.Scope {
	case scope.Undefined:
		if options.Hostname == "" {
			return "/calico/bgp/v1"
		} else if options.PeerIP.IP == nil {
			return fmt.Sprintf("/calico/bgp/v1/host/%s",
				options.Hostname)
		} else {
			return fmt.Sprintf("/calico/bgp/v1/host/%s/peer_v%d/%s",
				options.Hostname, options.PeerIP.Version(), options.PeerIP)
		}
	case scope.Global:
		if options.PeerIP.IP == nil {
			return "/calico/bgp/v1/global"
		} else {
			return fmt.Sprintf("/calico/bgp/v1/global/peer_v%d/%s",
				options.PeerIP.Version(), options.PeerIP)
		}
	case scope.Node:
		if options.Hostname == "" {
			return "/calico/bgp/v1/host"
		} else if options.PeerIP.IP == nil {
			return fmt.Sprintf("/calico/bgp/v1/host/%s",
				options.Hostname)
		} else {
			return fmt.Sprintf("/calico/bgp/v1/host/%s/peer_v%d/%s",
				options.Hostname, options.PeerIP.Version(), options.PeerIP)
		}
	}
	panic(fmt.Errorf("Unexpected scope value: %d", options.Scope))
}

func (options BGPPeerListOptions) KeyFromDefaultPath(path string) Key {
	log.Infof("Get BGPPeer key from %s", path)
	hostname := ""
	peerIP := net.IP{}
	ekeyb := []byte(path)
	var peerScope scope.Scope

	if r := matchGlobalBGPPeer.FindAllSubmatch(ekeyb, -1); len(r) == 1 {
		_ = peerIP.UnmarshalText(r[0][1])
		peerScope = scope.Global
	} else if r := matchHostBGPPeer.FindAllSubmatch(ekeyb, -1); len(r) == 1 {
		hostname = string(r[0][1])
		_ = peerIP.UnmarshalText(r[0][2])
		peerScope = scope.Node
	} else {
		log.Infof("%s didn't match regex", path)
		return nil
	}

	if options.PeerIP.IP != nil && !options.PeerIP.Equal(peerIP.IP) {
		log.Infof("Didn't match peerIP %s != %s", options.PeerIP.String(), peerIP.String())
		return nil
	}
	if options.Hostname != "" && hostname != options.Hostname {
		log.Infof("Didn't match hostname %s != %s", options.Hostname, hostname)
		return nil
	}
	return BGPPeerKey{Scope: peerScope, PeerIP: peerIP, Hostname: hostname}
}

type BGPPeer struct {
	PeerIP net.IP               `json:"ip"`
	ASNum  numorstring.ASNumber `json:"as_num"`
}
