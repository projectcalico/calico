// Copyright (c) 2018-2021 Tigera, Inc. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package utils

import (
	"context"
	"net"

	cniv1 "github.com/containernetworking/cni/pkg/types/100"
	"github.com/sirupsen/logrus"

	"github.com/containernetworking/cni/pkg/skel"

	"github.com/projectcalico/calico/cni-plugin/pkg/types"
	api "github.com/projectcalico/calico/libcalico-go/lib/apis/v3"
	calicoclient "github.com/projectcalico/calico/libcalico-go/lib/clientv3"
)

func updateHostLocalIPAMDataForOS(subnet string, ipamData map[string]interface{}) error {
	return nil
}

func EnsureVXLANTunnelAddr(ctx context.Context, calicoClient calicoclient.Interface, nodeName string, ipNet *net.IPNet, networkName string) error {
	return nil
}

func RegisterDeletedWep(containerID string) error {
	return nil
}

func CheckForSpuriousDockerAdd(args *skel.CmdArgs,
	conf types.NetConf,
	epIDs WEPIdentifiers,
	endpoint *api.WorkloadEndpoint,
	logger *logrus.Entry) (*cniv1.Result, error) {
	return nil, nil
}
