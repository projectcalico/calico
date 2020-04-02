// Copyright 2020 Cisco Systems Inc
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
	"fmt"
	"net"

	"github.com/containernetworking/cni/pkg/skel"
	"github.com/containernetworking/cni/pkg/types/current"
	"github.com/projectcalico/cni-plugin/pkg/dataplane/grpc"
	"github.com/projectcalico/cni-plugin/pkg/dataplane/linux"
	"github.com/projectcalico/cni-plugin/pkg/types"
	api "github.com/projectcalico/libcalico-go/lib/apis/v3"
	"github.com/sirupsen/logrus"
)

type Dataplane interface {
	DoNetworking(
		args *skel.CmdArgs,
		result *current.Result,
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
		return linux.NewLinuxDataplane(conf, logger), nil
	}
	switch name {
	case "grpc":
		return grpc.NewGrpcDataplane(conf, logger)
	default:
		return nil, fmt.Errorf("Invalid dataplane type: %s", name)
	}
}
