// Copyright (c) 2025 NeuReality Ltd.
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
	api "github.com/projectcalico/calico/libcalico-go/lib/apis/v3"
	calicoclient "github.com/projectcalico/calico/libcalico-go/lib/clientv3"
)

type multiplexer struct {
	primary   Dataplane
	secondary Dataplane
}

func (m multiplexer) DoNetworking(
	ctx context.Context,
	calicoClient calicoclient.Interface,
	args *skel.CmdArgs,
	result *cniv1.Result,
	desiredVethName string,
	routes []*net.IPNet,
	endpoint *api.WorkloadEndpoint,
	annotations map[string]string,
) (string, string, error) {
	_, _, secondaryErr := m.secondary.DoNetworking(ctx, calicoClient, args, result, desiredVethName, routes, endpoint, annotations)
	hostVethName, contVethMAC, primaryErr := m.primary.DoNetworking(ctx, calicoClient, args, result, desiredVethName, routes, endpoint, annotations)

	if primaryErr != nil || secondaryErr != nil {
		return "", "", fmt.Errorf("errors in sending message to dataplanes: primary error %w, secondary error %w",
			primaryErr, secondaryErr)
	}

	return hostVethName, contVethMAC, nil
}

func (m multiplexer) CleanUpNamespace(args *skel.CmdArgs) error {
	secondaryErr := m.secondary.CleanUpNamespace(args)
	primaryErr := m.primary.CleanUpNamespace(args)

	if primaryErr != nil || secondaryErr != nil {
		return fmt.Errorf("errors in clean up namespaces of dataplanes: primary error %w, secondary error %w",
			primaryErr, secondaryErr)
	}

	return nil
}
