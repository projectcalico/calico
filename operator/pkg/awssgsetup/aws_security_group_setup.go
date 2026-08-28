// Copyright (c) 2020-2026 Tigera, Inc. All rights reserved.

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

package awssgsetup

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/feature/ec2/imds"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"

	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8stypes "k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

var (
	log   = logf.Log.WithName("AWS_SG_Setup")
	TRACE = 7
	DEBUG = 5
)

type errorSecurityGroupNotFound struct {
	FilterKey   string
	FilterValue string
}

func (e errorSecurityGroupNotFound) Error() string {
	return fmt.Sprintf("No security groups found matching filter %s = %s", e.FilterKey, e.FilterValue)
}

// setupAWSSecurityGroups updates the master and worker security groups used in an
// OpenShift AWS setup. It sets a time that should be checked before attempting
// to do another call to setup. 'hosted' should be true if this is an OpenShift
// hosted control planes (HCP) hosted cluster.
func SetupAWSSecurityGroups(ctx context.Context, client client.Client, hosted bool) error {
	// Grab ConfigMap kube-system aws-creds
	//		get aws_access_key_id and aws_secret_access_key
	awsKeyId, awsSecret, err := getAWSCreds(ctx, client)
	if err != nil {
		return fmt.Errorf("failed to get AWS credentials: %v", err)
	}

	cfg, err := awsconfig.LoadDefaultConfig(ctx)
	if err != nil {
		return fmt.Errorf("failed to load AWS config: %v", err)
	}

	imdsClient := imds.NewFromConfig(cfg)

	doc, err := imdsClient.GetInstanceIdentityDocument(ctx, &imds.GetInstanceIdentityDocumentInput{})
	if err != nil {
		return fmt.Errorf("failed to get metadata document: %v", err)
	}

	region := doc.Region
	vpcId, err := getVPCid(ctx, imdsClient)
	if err != nil {
		return fmt.Errorf("failed to update AWS SecurityGroups: %v", err)
	}

	cfg, err = awsconfig.LoadDefaultConfig(ctx,
		awsconfig.WithRegion(region),
		awsconfig.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(awsKeyId, awsSecret, "")),
	)
	if err != nil {
		return fmt.Errorf("failed to update AWS SecurityGroups: %v", err)
	}

	ec2Cli := ec2.NewFromConfig(cfg)
	if hosted {
		return setupHostedClusterSGs(ctx, ec2Cli, vpcId)
	}

	return setupClusterSGs(ctx, ec2Cli, vpcId)
}

func setupClusterSGs(ctx context.Context, ec2Cli *ec2.Client, vpcId string) error {
	// Get SG ids in VPC
	// Get controlplane SG with role filter
	controlPlaneSg, err := getSecurityGroup(ctx, ec2Cli, vpcId, "tag:sigs.k8s.io/cluster-api-provider-aws/role", "controlplane")
	// Fall back to using filter tag:Name with *-master-sg if not found
	var notFound errorSecurityGroupNotFound
	if err != nil && errors.As(err, &notFound) {
		controlPlaneSg, err = getSecurityGroup(ctx, ec2Cli, vpcId, "tag:Name", "*-master-sg")
	}
	if err != nil {
		return fmt.Errorf("failed to get controlplane AWS SecurityGroup: %v", err)
	}

	// Get node SG with role filter
	nodeSg, err := getSecurityGroup(ctx, ec2Cli, vpcId, "tag:sigs.k8s.io/cluster-api-provider-aws/role", "node")
	// Fall back to using filter tag:Name with *-worker-sg if not found
	if err != nil && errors.As(err, &notFound) {
		nodeSg, err = getSecurityGroup(ctx, ec2Cli, vpcId, "tag:Name", "*-worker-sg")
	}
	if err != nil {
		return fmt.Errorf("failed to get node AWS SecurityGroup: %v", err)
	}

	err = setupSG(ctx, ec2Cli, controlPlaneSg, []string{aws.ToString(controlPlaneSg.GroupId), aws.ToString(nodeSg.GroupId)})
	if err != nil {
		return fmt.Errorf("failed to update controlplane AWS SecurityGroup: %v", err)
	}

	err = setupSG(ctx, ec2Cli, nodeSg, []string{aws.ToString(controlPlaneSg.GroupId), aws.ToString(nodeSg.GroupId)})
	if err != nil {
		return fmt.Errorf("failed to update node AWS SecurityGroup: %v", err)
	}

	return nil
}

func setupHostedClusterSGs(ctx context.Context, ec2Cli *ec2.Client, vpcId string) error {
	// On an OpenShift HCP hosted (guest) cluster, there are no master and worker
	// security groups, there is only one sg named '*-default-sg'
	defaultSg, err := getSecurityGroup(ctx, ec2Cli, vpcId, "tag:Name", "*-default-sg")
	if err != nil {
		return fmt.Errorf("failed to get AWS SecurityGroups: %v", err)
	}
	err = setupSG(ctx, ec2Cli, defaultSg, []string{aws.ToString(defaultSg.GroupId)})
	if err != nil {
		return fmt.Errorf("failed to update default AWS SecurityGroup: %v", err)
	}
	return nil
}

// getAWSCreds reads the aws-creds Secret that is created by an Openshift install and returns
// the id and secret.
func getAWSCreds(ctx context.Context, client client.Client) (id, secret string, err error) {
	// Grab Secret kube-system aws-creds
	//		get aws_access_key_id and aws_secret_access_key
	creds := &v1.Secret{}
	key := k8stypes.NamespacedName{Name: "aws-creds", Namespace: metav1.NamespaceSystem}

	if err := client.Get(ctx, key, creds); err != nil {
		return "", "", err
	}
	log.V(DEBUG).Info("Retrieved aws-creds")

	idByte, ok := creds.Data["aws_access_key_id"]
	if !ok {
		return "", "", fmt.Errorf("aws-creds ConfigMap does not have key aws_access_key_id")
	}
	secretByte, ok := creds.Data["aws_secret_access_key"]
	if !ok {
		return "", "", fmt.Errorf("aws-creds ConfigMap does not have key aws_secret_access_key")
	}
	return string(idByte), string(secretByte), nil
}

// getVPCid gets the VPC id by querying the instance metadata.
func getVPCid(ctx context.Context, meta *imds.Client) (string, error) {
	macOut, err := meta.GetMetadata(ctx, &imds.GetMetadataInput{Path: "mac"})
	if err != nil {
		return "", fmt.Errorf("failed to read MAC for VPC Id: %v", err)
	}
	defer func() { _ = macOut.Content.Close() }()
	macBytes, err := io.ReadAll(macOut.Content)
	if err != nil {
		return "", fmt.Errorf("failed to read MAC response body: %v", err)
	}
	mac := strings.TrimSpace(string(macBytes))
	log.V(TRACE).Info("MAC read from metadata", "MAC", mac)
	if len(mac) < 1 {
		return "", fmt.Errorf("no MAC read for VPC Id; metadata service returned empty response")
	}
	vpcOut, err := meta.GetMetadata(ctx, &imds.GetMetadataInput{Path: fmt.Sprintf("network/interfaces/macs/%s/vpc-id", mac)})
	if err != nil {
		return "", fmt.Errorf("failed to read VPC Id: %v", err)
	}
	defer func() { _ = vpcOut.Content.Close() }()
	vpcBytes, err := io.ReadAll(vpcOut.Content)
	if err != nil {
		return "", fmt.Errorf("failed to read VPC Id response body: %v", err)
	}
	vpcId := strings.TrimSpace(string(vpcBytes))

	log.V(TRACE).Info("VPC id read from metadata", "VPCid", vpcId)
	return vpcId, nil
}

// getSecurityGroup returns the first SG that is in the specified VPC and matches the nameFilter.
// nameFilter matches tag:Name.
func getSecurityGroup(ctx context.Context, cli *ec2.Client, vpcId string, filterKey string, filterValue string) (*types.SecurityGroup, error) {
	in := &ec2.DescribeSecurityGroupsInput{
		Filters: []types.Filter{
			{
				Name:   aws.String("vpc-id"),
				Values: []string{vpcId},
			},
			{
				Name:   aws.String(filterKey),
				Values: []string{filterValue},
			},
		},
	}
	out, err := cli.DescribeSecurityGroups(ctx, in)
	if err != nil {
		return nil, err
	}

	if len(out.SecurityGroups) == 0 {
		log.Info("No security groups found", "vpc-id", vpcId, filterKey, filterValue, "SecurityGroupOutput", out)
		return nil, errorSecurityGroupNotFound{FilterKey: filterKey, FilterValue: filterValue}
	}

	if len(out.SecurityGroups) > 1 {
		log.Info("Multiple security groups matching filter, using the first", filterKey, "=", filterValue, "SecurityGroupOutput", out)
	}

	log.V(TRACE).Info("DescribeSecurityGroups", "SecurityGroupOutput", out)
	return &out.SecurityGroups[0], nil
}

type ingressSrc struct {
	port     *int32
	protocol string
	srcSGId  string
}

func (is *ingressSrc) String() string {
	if is.port == nil {
		return fmt.Sprintf("SourceSGId: %s, Protocol: %s, Port: nil", is.srcSGId, is.protocol)
	}
	return fmt.Sprintf("SourceSGId: %s, Protocol: %s, Port: %d", is.srcSGId, is.protocol, *is.port)
}

// ingressSrcMatchesIpPermission checks if the s (source) is already in the
// IpPermission and returns true if so, otherwise false is returned.
func ingressSrcMatchesIpPermission(s ingressSrc, ipp types.IpPermission) bool {
	if aws.ToString(ipp.IpProtocol) != s.protocol {
		return false
	}
	// Some protocols do not use port so skip checking that if we don't have one
	// specified in s
	p := aws.ToInt32(s.port)
	if s.port != nil && (aws.ToInt32(ipp.FromPort) != p || aws.ToInt32(ipp.ToPort) != p) {
		return false
	}
	for _, y := range ipp.UserIdGroupPairs {
		if aws.ToString(y.GroupId) == s.srcSGId {
			return true
		}
	}
	return false
}

// setupSG adds rules to SG that allow incoming from srcSGIDs for BGP, IPIP, Typha comms
func setupSG(ctx context.Context, ec2Cli *ec2.Client, sg *types.SecurityGroup, srcSGIDs []string) error {
	src := []ingressSrc{}
	for _, srcSGID := range srcSGIDs {
		src = append(src, []ingressSrc{
			{
				// BGP
				srcSGId:  srcSGID,
				protocol: "tcp",
				port:     aws.Int32(179),
			},
			{
				// IP-in-IP
				srcSGId:  srcSGID,
				protocol: "4",
			},
			{
				// Typha
				srcSGId:  srcSGID,
				protocol: "tcp",
				port:     aws.Int32(5473),
			},
		}...)
	}

	err := allowIngressToSG(ctx, ec2Cli, sg, src)
	if err != nil {
		return fmt.Errorf("failed to update AWS SecurityGroup Name: %v, ID: %v, error: %v", sg.GroupName, sg.GroupId, err)
	}
	return nil
}

// allowIngressToSG adds rules to the toSG Security Group for each element of sources.
// Before attempting to add a rule the function checks the toSG to see if the rule already exists.
// If there is an error adding the rules then an error is returned.
func allowIngressToSG(ctx context.Context, cli *ec2.Client, toSG *types.SecurityGroup, sources []ingressSrc) error {
	sgId := aws.ToString(toSG.GroupId)
	in := &ec2.AuthorizeSecurityGroupIngressInput{
		GroupId: aws.String(sgId),
	}
	for _, s := range sources {
		log.V(DEBUG).Info("Ingress src being added", "toSG.GroupId", sgId, "ingressSrc", s.String())
		skip := false
		// Check the allowed IpPermissions to see if the s (source) is already allowed
		for _, x := range toSG.IpPermissions {
			if ingressSrcMatchesIpPermission(s, x) {
				log.V(DEBUG).Info("Ingress rule already exists", "toSG.GroupId", sgId, "ingressSrc", s.String())
				skip = true
				break
			}
		}
		// If the s (source) is already allowed then nothing more to do so continue
		// to the next loop iteration.
		if skip {
			continue
		}
		in.IpPermissions = []types.IpPermission{{
			UserIdGroupPairs: []types.UserIdGroupPair{{
				GroupId: aws.String(s.srcSGId),
			}},
			IpProtocol: aws.String(s.protocol),
			FromPort:   s.port,
			ToPort:     s.port,
		}}
		_, err := cli.AuthorizeSecurityGroupIngress(ctx, in)
		if err != nil {
			return fmt.Errorf("failed to add to SG '%s' the ingress rule '%s': %v: %v", sgId, s.String(), toSG, err)
		}
		log.V(DEBUG).Info("Added Ingress rule", "toSG.GroupId", sgId, "ingressSrc", s.String())
	}
	log.Info("Ingress configured for Security Group", "toSG.GroupId", sgId)
	return nil
}
