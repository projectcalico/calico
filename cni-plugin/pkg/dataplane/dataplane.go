// Copyright 2020 Cisco Systems Inc
// Copyright (c) 2020 Tigera, Inc. All rights reserved.
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

package dataplane

import (
	"context"
	"fmt"
	"net"

	"github.com/containernetworking/cni/pkg/skel"
	cniv1 "github.com/containernetworking/cni/pkg/types/100"
	"github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/cni-plugin/pkg/dataplane/grpc"
	"github.com/projectcalico/calico/cni-plugin/pkg/types"
	api "github.com/projectcalico/calico/libcalico-go/lib/apis/v3"
	calicoclient "github.com/projectcalico/calico/libcalico-go/lib/clientv3"
)

type Dataplane interface {
	DoNetworking(
		ctx context.Context,
		calicoClient calicoclient.Interface,
		args *skel.CmdArgs,
		result *cniv1.Result,
		desiredVethName string,
		routes []*net.IPNet,
		endpoint *api.WorkloadEndpoint,
		annotations map[string]string,
	) (hostVethName, contVethMAC string, err error)

	CleanUpNamespace(args *skel.CmdArgs) error
}

func GetDataplane(conf types.NetConf, logger *logrus.Entry) (Dataplane, error) {
	name, ok := conf.DataplaneOptions["type"]
	if !ok {
		return getDefaultSystemDataplane(conf, logger)
	}
	switch name {
	case "grpc":
		return grpc.NewGrpcDataplane(conf, logger)
	default:
		return nil, fmt.Errorf("Invalid dataplane type: %s", name)
	}
}
