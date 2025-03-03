// Copyright (c) 2025 Tigera, Inc. All rights reserved.
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

package client

import (
	"context"
	"fmt"
	"io"

	"google.golang.org/grpc"

	"github.com/projectcalico/calico/goldmane/proto"
)

type flowServiceClient struct {
	cli proto.FlowsClient
}

// FlowsClient is a client used for retrieving flows aggregated by goldmane. This is a separate service from the
// FlowCollector used for retrieving the aggregated flows from Goldmane.
type FlowsClient interface {
	List(context.Context, *proto.FlowListRequest) ([]*proto.FlowResult, error)
	Stream(ctx context.Context, request *proto.FlowStreamRequest) (proto.Flows_StreamClient, error)
}

func NewFlowsAPIClient(host string, opts ...grpc.DialOption) (FlowsClient, error) {
	gmCli, err := grpc.NewClient(host, opts...)
	if err != nil {
		return nil, fmt.Errorf("failed to create grpc client: %w", err)
	}

	return &flowServiceClient{
		cli: proto.NewFlowsClient(gmCli),
	}, nil
}

// List retrieves a list of proto.Flow from the Goldmane service. The proto.FlowRequest struct provides filters, sorting,
// and pagination options (see proto.FlowRequest definition for more details).
func (cli *flowServiceClient) List(ctx context.Context, request *proto.FlowListRequest) ([]*proto.FlowResult, error) {
	stream, err := cli.cli.List(ctx, request)
	if err != nil {
		return nil, fmt.Errorf("failed to list flows: %w", err)
	}

	var flows []*proto.FlowResult
	for {
		flow, err := stream.Recv()
		// Break if EOF is found (no more data to be returned).
		if err == io.EOF {
			break
		} else if err != nil {
			return nil, fmt.Errorf("failed to receive flow from stream: %w", err)
		}

		flows = append(flows, flow)
	}

	return flows, nil
}

// Stream opens up a stream to Goldmane and streams new flows from Goldmane as they're discovered.
// TODO Maybe we shouldn't use proto.FlowRequest since it provides options, like pagination and sorting, that aren't
// TODO usable for a stream request.
func (cli *flowServiceClient) Stream(ctx context.Context, request *proto.FlowStreamRequest) (proto.Flows_StreamClient, error) {
	return cli.cli.Stream(ctx, request)
}
