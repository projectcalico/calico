// Copyright (c) 2026 Tigera, Inc. All rights reserved.
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

package ec2query

import (
	"context"
	"net/url"
	"strconv"
)

// DescribeInstancesInput is the subset of parameters we need.
type DescribeInstancesInput struct {
	InstanceIDs []string
}

// DescribeInstancesOutput is the subset of fields we read from the response.
// The XML root element <DescribeInstancesResponse> is unmarshalled into this
// struct directly.
type DescribeInstancesOutput struct {
	Reservations []Reservation `xml:"reservationSet>item"`
}

type Reservation struct {
	Instances []Instance `xml:"instancesSet>item"`
}

type Instance struct {
	NetworkInterfaces []InstanceNetworkInterface `xml:"networkInterfaceSet>item"`
}

type InstanceNetworkInterface struct {
	NetworkInterfaceID string                              `xml:"networkInterfaceId"`
	Attachment         *InstanceNetworkInterfaceAttachment `xml:"attachment"`
}

type InstanceNetworkInterfaceAttachment struct {
	DeviceIndex int32 `xml:"deviceIndex"`
}

// DescribeInstances calls the EC2 DescribeInstances operation.
func (c *Client) DescribeInstances(ctx context.Context, in *DescribeInstancesInput) (*DescribeInstancesOutput, error) {
	params := url.Values{}
	for i, id := range in.InstanceIDs {
		params.Set("InstanceId."+strconv.Itoa(i+1), id)
	}
	var out DescribeInstancesOutput
	if err := c.Do(ctx, "DescribeInstances", params, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// ModifyNetworkInterfaceAttributeInput covers the SourceDestCheck use case.
// Only one attribute may be modified per call.
type ModifyNetworkInterfaceAttributeInput struct {
	NetworkInterfaceID string
	SourceDestCheck    *bool
}

type ModifyNetworkInterfaceAttributeOutput struct{}

// ModifyNetworkInterfaceAttribute calls the EC2 ModifyNetworkInterfaceAttribute
// operation. Today only SourceDestCheck is supported.
func (c *Client) ModifyNetworkInterfaceAttribute(ctx context.Context, in *ModifyNetworkInterfaceAttributeInput) (*ModifyNetworkInterfaceAttributeOutput, error) {
	params := url.Values{}
	params.Set("NetworkInterfaceId", in.NetworkInterfaceID)
	if in.SourceDestCheck != nil {
		params.Set("SourceDestCheck.Value", strconv.FormatBool(*in.SourceDestCheck))
	}
	if err := c.Do(ctx, "ModifyNetworkInterfaceAttribute", params, nil); err != nil {
		return nil, err
	}
	return &ModifyNetworkInterfaceAttributeOutput{}, nil
}
