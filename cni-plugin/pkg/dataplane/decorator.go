// Copyright 2020 Cisco Systems Inc
// Copyright (c) 2020 Tigera, Inc. All rights reserved.
// Copyright (c) 2024 NeuReality, Ltd. All rights reserved.
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
	"net"

	"github.com/containernetworking/cni/pkg/skel"
	cniv1 "github.com/containernetworking/cni/pkg/types/100"

	api "github.com/projectcalico/calico/libcalico-go/lib/apis/v3"
	calicoclient "github.com/projectcalico/calico/libcalico-go/lib/clientv3"
)

type decorator struct {
     primary Dataplane
     secondary Dataplane
}

func (d decorator) DoNetworking(
	ctx context.Context,
	calicoClient calicoclient.Interface,
	args *skel.CmdArgs,
	result *cniv1.Result,
	desiredVethName string,
	routes []*net.IPNet,
	endpoint *api.WorkloadEndpoint,
	annotations map[string]string,
) (string, string, error) {
  d.secondary.DoNetworking(ctx, calicoClient, args, result, desiredVethName, routes, endpoint, annotations)
  return d.primary.DoNetworking(ctx, calicoClient, args, result, desiredVethName, routes, endpoint, annotations)
}

func (d decorator) CleanUpNamespace(args *skel.CmdArgs) error {
     d.secondary.CleanUpNamespace(args)
     return d.primary.CleanUpNamespace(args)
}
