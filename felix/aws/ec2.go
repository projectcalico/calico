// Copyright (c) 2020-2021 Tigera, Inc. All rights reserved.
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

package aws

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/feature/ec2/imds"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/smithy-go"
	log "github.com/sirupsen/logrus"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/utils/clock"

	apiv3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"

	"github.com/projectcalico/calico/libcalico-go/lib/health"
)

const (
	timeout         = 20 * time.Second
	retries         = 3
	deviceIndexZero = 0
)

func convertError(err error) string {
	var awsErr smithy.APIError
	if errors.As(err, &awsErr) {
		return fmt.Sprintf("%s: %s", awsErr.ErrorCode(), awsErr.ErrorMessage())
	}

	return fmt.Sprintf("%v", err.Error())
}

func retriable(err error) bool {
	var awsErr smithy.APIError
	if errors.As(err, &awsErr) {
		switch awsErr.ErrorCode() {
		case "InternalError":
			return true
		case "InternalFailure":
			return true
		case "RequestLimitExceeded":
			return true
		case "ServiceUnavailable":
			return true
		case "Unavailable":
			return true
		}
	}

	return false
}

type SrcDstCheckUpdater interface {
	Update(option string) error
}

func WaitForEC2SrcDstCheckUpdate(check string, healthAgg *health.HealthAggregator, updater SrcDstCheckUpdater, c clock.Clock) {
	log.Infof("Setting AWS EC2 source-destination-check to %s", check)

	const (
		initBackoff   = 30 * time.Second
		maxBackoff    = 8 * time.Minute
		resetDuration = time.Hour
		backoffFactor = 2.0
		jitter        = 0.1
	)

	backoffMgr := wait.NewExponentialBackoffManager(initBackoff, maxBackoff, resetDuration, backoffFactor, jitter, c)
	defer backoffMgr.Backoff().Stop()

	const healthName = "aws-source-destination-check"
	healthAgg.RegisterReporter(healthName, &health.HealthReport{Live: true, Ready: true}, 0)

	// set not-ready.
	healthAgg.Report(healthName, &health.HealthReport{Live: true, Ready: false})

	for {
		if err := updater.Update(check); err != nil {
			log.WithField("src-dst-check", check).Warnf("Failed to set source-destination-check: %v", err)
		} else {
			// set ready.
			healthAgg.Report(healthName, &health.HealthReport{Live: true, Ready: true})
			return
		}

		<-backoffMgr.Backoff().C()
	}
}

type EC2SrcDstCheckUpdater struct{}

func NewEC2SrcDstCheckUpdater() *EC2SrcDstCheckUpdater {
	return &EC2SrcDstCheckUpdater{}
}

func (updater *EC2SrcDstCheckUpdater) Update(caliCheckOption string) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	ec2Cli, err := newEC2Client(ctx)
	if err != nil {
		return err
	}

	ec2NetId, err := ec2Cli.getEC2NetworkInterfaceId(ctx)
	if err != nil {
		return fmt.Errorf("error getting ec2 network-interface-id: %s", convertError(err))
	}

	checkEnabled := caliCheckOption == apiv3.AWSSrcDstCheckOptionEnable
	err = ec2Cli.setEC2SourceDestinationCheck(ctx, ec2NetId, checkEnabled)
	if err != nil {
		return fmt.Errorf("error setting src-dst-check for network-interface-id: %s", convertError(err))
	}

	log.Infof("Successfully set source-destination-check to %t on network-interface-id: %s", checkEnabled, ec2NetId)
	return nil
}

// Interface for EC2 Metadata service.
type ec2MetadaAPI interface {
	GetInstanceIdentityDocument(
		ctx context.Context, params *imds.GetInstanceIdentityDocumentInput, optFns ...func(*imds.Options),
	) (*imds.GetInstanceIdentityDocumentOutput, error)
	GetRegion(
		ctx context.Context, params *imds.GetRegionInput, optFns ...func(*imds.Options),
	) (*imds.GetRegionOutput, error)
}

type ec2API interface {
	DescribeInstances(ctx context.Context, params *ec2.DescribeInstancesInput, optFns ...func(*ec2.Options)) (*ec2.DescribeInstancesOutput, error)
	ModifyNetworkInterfaceAttribute(ctx context.Context, params *ec2.ModifyNetworkInterfaceAttributeInput, optFns ...func(*ec2.Options)) (*ec2.ModifyNetworkInterfaceAttributeOutput, error)
}

func getEC2InstanceID(ctx context.Context, svc ec2MetadaAPI) (string, error) {
	idDoc, err := svc.GetInstanceIdentityDocument(ctx, nil)
	if err != nil {
		return "", err
	}
	log.Debugf("ec2-instance-id: %s", idDoc.InstanceID)
	return idDoc.InstanceID, nil
}

func getEC2Region(ctx context.Context, svc ec2MetadaAPI) (string, error) {
	region, err := svc.GetRegion(ctx, nil)
	if err != nil {
		return "", err
	}
	log.Debugf("region: %s", region)
	return region.Region, nil
}

type ec2Client struct {
	EC2Svc        ec2API
	ec2InstanceId string
}

func newEC2Client(ctx context.Context) (*ec2Client, error) {
	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return nil, fmt.Errorf("error loading AWS config: %w", err)
	}
	metadataSvc := imds.NewFromConfig(cfg)

	region, err := getEC2Region(ctx, metadataSvc)
	if err != nil {
		return nil, fmt.Errorf("error getting ec2 region: %s", convertError(err))
	}

	instanceId, err := getEC2InstanceID(ctx, metadataSvc)
	if err != nil {
		return nil, fmt.Errorf("error getting ec2 instance-id: %s", convertError(err))
	}

	ec2Svc := ec2.NewFromConfig(cfg, func(o *ec2.Options) {
		o.Region = region
	})
	if ec2Svc == nil {
		return nil, fmt.Errorf("error connecting to EC2 service")
	}

	return &ec2Client{
		EC2Svc:        ec2Svc,
		ec2InstanceId: instanceId,
	}, nil
}

func (c *ec2Client) getEC2NetworkInterfaceId(ctx context.Context) (networkInstanceId string, err error) {
	input := &ec2.DescribeInstancesInput{
		InstanceIds: []string{
			c.ec2InstanceId,
		},
	}

	var out *ec2.DescribeInstancesOutput
	for i := 0; i < retries; i++ {
		out, err = c.EC2Svc.DescribeInstances(ctx, input)
		if err != nil {
			if retriable(err) {
				// if error is temporary, try again in a second.
				time.Sleep(1 * time.Second)
				log.WithField("instance-id", c.ec2InstanceId).Debug("retrying getting network-interface-id")
				continue
			}
			return "", err
		} else {
			break
		}
	}

	if out == nil || len(out.Reservations) == 0 {
		return "", fmt.Errorf("no network-interface-id found for EC2 instance %s", c.ec2InstanceId)
	}

	var interfaceId string
	for _, instance := range out.Reservations[0].Instances {
		if len(instance.NetworkInterfaces) == 0 {
			return "", fmt.Errorf("no network-interface-id found for EC2 instance %s", c.ec2InstanceId)
		}
		// We are only modifying network interface with device-id-0 to update
		// instance source-destination-check.
		// An instance can have multiple interfaces and the API response can be
		// out-of-order interface list. We compare the device-id in the
		// response to make sure the right device is updated.
		for _, networkInterface := range instance.NetworkInterfaces {
			if networkInterface.Attachment != nil &&
				networkInterface.Attachment.DeviceIndex != nil &&
				*(networkInterface.Attachment.DeviceIndex) == deviceIndexZero {
				interfaceId = *(networkInterface.NetworkInterfaceId)
				if interfaceId != "" {
					log.Debugf("instance-id: %s, network-interface-id: %s", c.ec2InstanceId, interfaceId)
					return interfaceId, nil
				}
			}
			log.Debugf("instance-id: %s, network-interface-id: %s", c.ec2InstanceId, interfaceId)
		}
		if interfaceId == "" {
			return "", fmt.Errorf("no network-interface-id found for EC2 instance %s", c.ec2InstanceId)
		}
	}
	return interfaceId, nil
}

func (c *ec2Client) setEC2SourceDestinationCheck(ctx context.Context, ec2NetId string, checkVal bool) error {
	input := &ec2.ModifyNetworkInterfaceAttributeInput{
		NetworkInterfaceId: aws.String(ec2NetId),
		SourceDestCheck: &types.AttributeBooleanValue{
			Value: aws.Bool(checkVal),
		},
	}

	var err error
	for i := 0; i < retries; i++ {
		_, err = c.EC2Svc.ModifyNetworkInterfaceAttribute(ctx, input)
		if err != nil {
			if retriable(err) {
				// if error is temporary, try again in a second.
				time.Sleep(1 * time.Second)
				log.WithField("net-instance-id", ec2NetId).Debug("retrying setting source-destination-check")
				continue
			}

			return err
		} else {
			break
		}
	}

	return err
}
