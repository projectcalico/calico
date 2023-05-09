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

package grpc

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/containernetworking/cni/pkg/skel"
	cniv1 "github.com/containernetworking/cni/pkg/types/100"
	"github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/projectcalico/calico/cni-plugin/pkg/dataplane/grpc/proto"
	"github.com/projectcalico/calico/cni-plugin/pkg/types"
	api "github.com/projectcalico/calico/libcalico-go/lib/apis/v3"
	calicoclient "github.com/projectcalico/calico/libcalico-go/lib/clientv3"
)

const (
	timeout = 5 * time.Second
)

type grpcDataplane struct {
	socket            string
	allowIPForwarding bool
	mtu               int
	logger            *logrus.Entry
	options           map[string]string
}

func NewGrpcDataplane(conf types.NetConf, logger *logrus.Entry) (*grpcDataplane, error) {
	socket, ok := conf.DataplaneOptions["socket"].(string)
	if !ok {
		return nil, fmt.Errorf("GRPC dataplane socket not configured")
	}

	userOpts := make(map[string]string)
	for k, v := range conf.DataplaneOptions {
		str, ok := v.(string)
		if ok {
			userOpts[k] = str
		}
	}

	return &grpcDataplane{
		socket:            socket,
		allowIPForwarding: conf.ContainerSettings.AllowIPForwarding,
		mtu:               conf.MTU,
		logger:            logger,
		options:           userOpts,
	}, nil
}

func (d *grpcDataplane) DoNetworking(
	ctx context.Context,
	calicoClient calicoclient.Interface,
	args *skel.CmdArgs,
	result *cniv1.Result,
	desiredVethName string,
	routes []*net.IPNet,
	endpoint *api.WorkloadEndpoint,
	annotations map[string]string,
) (ifName, contTapMAC string, err error) {
	d.logger.Infof("Connecting to GRPC backend server at %s", d.socket)
	conn, err := grpc.Dial(d.socket, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return "", "", fmt.Errorf("cannot connect to grpc dataplane: %v", err)
	}

	c := proto.NewCniDataplaneClient(conn)

	request := &proto.AddRequest{
		InterfaceName:            args.IfName,
		Netns:                    args.Netns,
		DesiredHostInterfaceName: desiredVethName,
		Settings: &proto.ContainerSettings{
			AllowIpForwarding: d.allowIPForwarding,
			Mtu:               int32(d.mtu),
		},
		ContainerIps:    make([]*proto.IPConfig, 0),
		ContainerRoutes: make([]string, 0),
		Workload: &proto.WorkloadIDs{
			Name:         endpoint.Name,
			Namespace:    endpoint.Namespace,
			Labels:       endpoint.Labels,
			Annotations:  annotations,
			Endpoint:     endpoint.Spec.Endpoint,
			Node:         endpoint.Spec.Node,
			Orchestrator: endpoint.Spec.Orchestrator,
			Pod:          endpoint.Spec.Pod,
		},
		DataplaneOptions: d.options,
	}
	for _, ipConf := range result.IPs {
		request.ContainerIps = append(request.ContainerIps, &proto.IPConfig{
			Address: ipConf.Address.String(),
			Gateway: ipConf.Gateway.String(),
		})
	}
	for _, r := range routes {
		request.ContainerRoutes = append(request.ContainerRoutes, r.String())
	}
	for _, p := range endpoint.Spec.Ports {
		request.Workload.Ports = append(request.Workload.Ports, &proto.Port{
			Name:     p.Name,
			Protocol: p.Protocol.String(),
			Port:     uint32(p.Port),
			HostPort: uint32(p.HostPort),
			HostIp:   p.HostIP,
		})
	}

	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	reply, err := c.Add(ctx, request)
	if err != nil {
		d.logger.Errorf("request to grpc dataplane failed : %v", err)
		return "", "", err
	}
	if !reply.GetSuccessful() {
		return reply.HostInterfaceName, reply.ContainerMac, fmt.Errorf("grpc dataplane error: %s", reply.GetErrorMessage())
	}
	return reply.HostInterfaceName, reply.ContainerMac, nil
}

func (d *grpcDataplane) CleanUpNamespace(args *skel.CmdArgs) error {
	d.logger.Infof("Connecting to GRPC backend server at %s", d.socket)
	conn, err := grpc.Dial(d.socket, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return fmt.Errorf("cannot connect to grpc dataplane: %v", err)
	}
	c := proto.NewCniDataplaneClient(conn)

	request := &proto.DelRequest{
		InterfaceName:    args.IfName,
		Netns:            args.Netns,
		DataplaneOptions: d.options,
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	reply, err := c.Del(ctx, request)
	if err != nil {
		d.logger.Errorf("request to grpc dataplane failed : %v", err)
		return err
	}
	if !reply.Successful {
		return fmt.Errorf("grpc dataplane error: %s", reply.ErrorMessage)
	}
	return nil
}
