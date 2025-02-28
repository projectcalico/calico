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

type statisticsServiceClient struct {
	cli proto.StatisticsClient
}

type StatisticsClient interface {
	List(context.Context, *proto.StatisticsRequest) ([]*proto.StatisticsResult, error)
}

func NewStatisticsAPIClient(host string, opts ...grpc.DialOption) (StatisticsClient, error) {
	// TODO: We probably want the ability to pass in a custom client here, so we can mock it in tests
	// and also so we can share gRPC clients between services.
	gmCli, err := grpc.NewClient(host, opts...)
	if err != nil {
		return nil, fmt.Errorf("failed to create grpc client: %w", err)
	}

	return &statisticsServiceClient{
		cli: proto.NewStatisticsClient(gmCli),
	}, nil
}

func (cli *statisticsServiceClient) List(ctx context.Context, request *proto.StatisticsRequest) ([]*proto.StatisticsResult, error) {
	stream, err := cli.cli.List(ctx, request)
	if err != nil {
		return nil, fmt.Errorf("failed to list statistics: %w", err)
	}

	var results []*proto.StatisticsResult
	for {
		result, err := stream.Recv()
		if err == io.EOF {
			// Break if EOF is found (no more data to be returned).
			break
		} else if err != nil {
			return nil, fmt.Errorf("failed to receive result from stream: %w", err)
		}
		results = append(results, result)
	}
	return results, nil
}
