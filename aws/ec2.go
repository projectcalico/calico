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
	"fmt"
	"time"

	"k8s.io/apimachinery/pkg/util/clock"
	"k8s.io/apimachinery/pkg/util/wait"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/ec2metadata"
	awssession "github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/aws/aws-sdk-go/service/ec2/ec2iface"
	log "github.com/sirupsen/logrus"

	apiv3 "github.com/projectcalico/libcalico-go/lib/apis/v3"
	"github.com/projectcalico/libcalico-go/lib/health"
)

const (
	timeout         = 20 * time.Second
	retries         = 3
	deviceIndexZero = 0
)

func convertError(err error) string {
	if awsErr, ok := err.(awserr.Error); ok {
		return fmt.Sprintf("%s: %s", awsErr.Code(), awsErr.Message())
	}

	return fmt.Sprintf("%v", err.Error())
}

func retriable(err error) bool {
	if awsErr, ok := err.(awserr.Error); ok {
		switch awsErr.Code() {
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
	AvailableWithContext(ctx aws.Context) bool
	GetInstanceIdentityDocumentWithContext(ctx aws.Context) (ec2metadata.EC2InstanceIdentityDocument, error)
	RegionWithContext(ctx aws.Context) (string, error)
}

func getEC2InstanceID(ctx context.Context, svc ec2MetadaAPI) (string, error) {
	idDoc, err := svc.GetInstanceIdentityDocumentWithContext(ctx)
	if err != nil {
		return "", err
	}
	log.Debugf("ec2-instance-id: %s", idDoc.InstanceID)
	return idDoc.InstanceID, nil
}

func getEC2Region(ctx context.Context, svc ec2MetadaAPI) (string, error) {
	region, err := svc.RegionWithContext(ctx)
	if err != nil {
		return "", err
	}
	log.Debugf("region: %s", region)
	return region, nil
}

type ec2Client struct {
	EC2Svc        ec2iface.EC2API
	ec2InstanceId string
}

func newEC2Client(ctx context.Context) (*ec2Client, error) {
	awsSession, err := awssession.NewSession()
	if err != nil {
		return nil, fmt.Errorf("error creating AWS session: %w", err)
	}

	metadataSvc := ec2metadata.New(awsSession)
	if metadataSvc == nil {
		return nil, fmt.Errorf("error connecting to EC2 Metadata service")
	}

	if !metadataSvc.AvailableWithContext(ctx) {
		return nil, fmt.Errorf("EC2 metadata service is unavailable or not running on an EC2 instance")
	}

	region, err := getEC2Region(ctx, metadataSvc)
	if err != nil {
		return nil, fmt.Errorf("error getting ec2 region: %s", convertError(err))
	}

	instanceId, err := getEC2InstanceID(ctx, metadataSvc)
	if err != nil {
		return nil, fmt.Errorf("error getting ec2 instance-id: %s", convertError(err))
	}

	ec2Svc := ec2.New(awsSession, aws.NewConfig().WithRegion(region))
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
		InstanceIds: []*string{
			aws.String(c.ec2InstanceId),
		},
	}

	var out *ec2.DescribeInstancesOutput
	for i := 0; i < retries; i++ {
		out, err = c.EC2Svc.DescribeInstancesWithContext(ctx, input)
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
		SourceDestCheck: &ec2.AttributeBooleanValue{
			Value: aws.Bool(checkVal),
		},
	}

	var err error
	for i := 0; i < retries; i++ {
		_, err = c.EC2Svc.ModifyNetworkInterfaceAttributeWithContext(ctx, input)
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
