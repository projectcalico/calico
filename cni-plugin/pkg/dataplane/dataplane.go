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

	var externalDataplane Dataplane

	switch name {
	case "grpc":
		var err error
		externalDataplane, err = grpc.NewGrpcDataplane(conf, logger)
		if err != nil {
			return nil, fmt.Errorf("Unable to create a new GRPC dataplane: %w", err)
		}
	default:
		return nil, fmt.Errorf("Invalid dataplane type: %s", name)
	}

	useAsSecondary, ok := conf.DataplaneOptions["useAsSecondary"]
	if useAsSecondary == "true" {
		defaultSystemDataplane, err := getDefaultSystemDataplane(conf, logger)
		if err != nil {
			return nil, fmt.Errorf("Unable to create new GRPC dataplane: %w", err)
		}
		return multiplexer{primary: defaultSystemDataplane, secondary: externalDataplane}, nil
	}

	return externalDataplane, nil
}
