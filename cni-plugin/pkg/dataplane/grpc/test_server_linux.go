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

	"github.com/containernetworking/plugins/pkg/ip"
	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/gogo/protobuf/proto"
	log "github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
	"google.golang.org/grpc"

	pb "github.com/projectcalico/calico/cni-plugin/pkg/dataplane/grpc/proto"
)

type TestServer struct {
	retval   bool
	contMac  string
	Received chan interface{}

	lis        net.Listener
	grpcServer *grpc.Server
}

func (s *TestServer) Add(ctx context.Context, in *pb.AddRequest) (*pb.AddReply, error) {
	in2 := proto.Clone(in)
	s.Received <- in2
	out := &pb.AddReply{
		Successful:        s.retval,
		HostInterfaceName: in.DesiredHostInterfaceName,
		ContainerMac:      s.contMac,
	}
	// Create an unconfigured veth just to make the test code happy
	if s.retval {
		err := ns.WithNetNSPath(in.Netns, func(hostNS ns.NetNS) error {
			veth := &netlink.Veth{
				LinkAttrs: netlink.LinkAttrs{Name: in.InterfaceName},
				PeerName:  "peer0",
			}

			if err := netlink.LinkAdd(veth); err != nil {
				return fmt.Errorf("error adding veth: %s", err)
			}
			return nil
		})
		if err != nil {
			out.Successful = false
			out.ErrorMessage = err.Error()
		}
	}

	return out, nil
}

func (s *TestServer) Del(ctx context.Context, in *pb.DelRequest) (*pb.DelReply, error) {
	in2 := proto.Clone(in)
	s.Received <- in2
	out := &pb.DelReply{
		Successful: s.retval,
	}
	if s.retval {
		err := ns.WithNetNSPath(in.Netns, func(_ ns.NetNS) error {
			return ip.DelLinkByName(in.InterfaceName)
		})
		if err != nil {
			out.Successful = false
			out.ErrorMessage = "error deleting veth: " + err.Error()
		}
	}
	return out, nil
}

func (s *TestServer) SetResult(r bool) {
	s.retval = r
}

func (s *TestServer) GracefulStop() {
	s.grpcServer.GracefulStop()
	s.lis.Close()
}

func (s *TestServer) startServer() {
	err := s.grpcServer.Serve(s.lis)
	if err != nil {
		log.Printf("error running test grpc server: %v", err)
	}
}

func StartTestServer(socket string, retval bool, contMac string) (s *TestServer, err error) {
	s = &TestServer{
		retval:     retval,
		contMac:    contMac,
		Received:   make(chan interface{}, 1),
		grpcServer: grpc.NewServer(),
	}

	s.lis, err = net.Listen("unix", socket)
	if err != nil {
		return nil, fmt.Errorf("failed to listen on unix socket %s: %v", socket, err)
	}

	pb.RegisterCniDataplaneServer(s.grpcServer, s)
	go s.startServer()
	return s, nil
}
