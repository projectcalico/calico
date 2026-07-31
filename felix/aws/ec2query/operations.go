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

// The Input/Output structs below mirror their counterparts in
// aws-sdk-go-v2/service/ec2 and service/ec2/types at EC2 API version 2016-11-15
// (see APIVersion). Field names and pointer-ness match the upstream types so
// that callers read them the same way; each struct carries only the fields
// felix/aws sends or reads, and adding a field means copying it from the
// matching upstream type. The xml tags name the elements of the EC2 Query API
// response.

// DescribeInstancesInput mirrors ec2.DescribeInstancesInput.
type DescribeInstancesInput struct {
	InstanceIds []string
}

// DescribeInstancesOutput mirrors ec2.DescribeInstancesOutput. The XML root
// element <DescribeInstancesResponse> is unmarshalled into this struct directly.
type DescribeInstancesOutput struct {
	Reservations []Reservation `xml:"reservationSet>item"`
}

// Reservation mirrors ec2types.Reservation.
type Reservation struct {
	Instances []Instance `xml:"instancesSet>item"`
}

// Instance mirrors ec2types.Instance.
type Instance struct {
	NetworkInterfaces []InstanceNetworkInterface `xml:"networkInterfaceSet>item"`
}

// InstanceNetworkInterface mirrors ec2types.InstanceNetworkInterface.
type InstanceNetworkInterface struct {
	NetworkInterfaceId *string                             `xml:"networkInterfaceId"`
	Attachment         *InstanceNetworkInterfaceAttachment `xml:"attachment"`
}

// InstanceNetworkInterfaceAttachment mirrors ec2types.InstanceNetworkInterfaceAttachment.
type InstanceNetworkInterfaceAttachment struct {
	DeviceIndex *int32 `xml:"deviceIndex"`
}

// DescribeInstances calls the EC2 DescribeInstances operation.
func (c *Client) DescribeInstances(ctx context.Context, in *DescribeInstancesInput) (*DescribeInstancesOutput, error) {
	params := url.Values{}
	for i, id := range in.InstanceIds {
		params.Set("InstanceId."+strconv.Itoa(i+1), id)
	}
	var out DescribeInstancesOutput
	if err := c.Do(ctx, "DescribeInstances", params, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// AttributeBooleanValue mirrors ec2types.AttributeBooleanValue.
type AttributeBooleanValue struct {
	Value *bool
}

// ModifyNetworkInterfaceAttributeInput mirrors the SourceDestCheck subset of
// ec2.ModifyNetworkInterfaceAttributeInput. Only one attribute may be modified
// per call.
type ModifyNetworkInterfaceAttributeInput struct {
	NetworkInterfaceId *string
	SourceDestCheck    *AttributeBooleanValue
}

// ModifyNetworkInterfaceAttributeOutput mirrors ec2.ModifyNetworkInterfaceAttributeOutput.
type ModifyNetworkInterfaceAttributeOutput struct{}

// ModifyNetworkInterfaceAttribute calls the EC2 ModifyNetworkInterfaceAttribute
// operation. Today only SourceDestCheck is supported.
func (c *Client) ModifyNetworkInterfaceAttribute(ctx context.Context, in *ModifyNetworkInterfaceAttributeInput) (*ModifyNetworkInterfaceAttributeOutput, error) {
	params := url.Values{}
	if in.NetworkInterfaceId != nil {
		params.Set("NetworkInterfaceId", *in.NetworkInterfaceId)
	}
	if in.SourceDestCheck != nil && in.SourceDestCheck.Value != nil {
		params.Set("SourceDestCheck.Value", strconv.FormatBool(*in.SourceDestCheck.Value))
	}
	if err := c.Do(ctx, "ModifyNetworkInterfaceAttribute", params, nil); err != nil {
		return nil, err
	}
	return &ModifyNetworkInterfaceAttributeOutput{}, nil
}
