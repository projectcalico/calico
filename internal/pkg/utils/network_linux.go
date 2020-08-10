// Copyright (c) 2018-2020 Tigera, Inc. All rights reserved.
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

package utils

import (
	"context"
	"net"

	"github.com/containernetworking/cni/pkg/skel"
	"github.com/projectcalico/cni-plugin/pkg/types"
	calicoclient "github.com/projectcalico/libcalico-go/lib/clientv3"
)

func updateHostLocalIPAMDataForOS(subnet string, ipamData map[string]interface{}) error {
	return nil
}

func EnsureVXLANTunnelAddr(ctx context.Context, calicoClient calicoclient.Interface, nodeName string, ipNet *net.IPNet, conf types.NetConf) error {
	return nil
}

func NetworkApplicationContainer(args *skel.CmdArgs) error {
	return nil
}

func MaintainWepDeletionTimestamps(timeout int) error {
	return nil
}

func CheckWepJustDeleted(containerID string, timeout int) (bool, error) {
	return false, nil
}

func RegisterDeletedWep(containerID string) error {
	return nil
}
