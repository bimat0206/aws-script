package main

import (
	"bufio"
	"context"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/ecs"
	elbv2 "github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
	"github.com/aws/aws-sdk-go-v2/service/rds"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
)

// ===== CONFIGURATION SECTION =====
const (
	// AWS Region to operate in
	AWS_REGION = "us-east-1"
	
	// Resource name prefix to match for deletion
	RESOURCE_PREFIX = "hsk"
	
	// Timeout for AWS operations
	OPERATION_TIMEOUT = 30 * time.Second
)

// ===== END CONFIGURATION SECTION =====

type ResourceInfo struct {
	Type         string
	Identifier   string
	Name         string
	Description  string
}

type AWSCleanup struct {
	cfg           aws.Config
	ec2Client     *ec2.Client
	s3Client      *s3.Client
	rdsClient     *rds.Client
	lambdaClient  *lambda.Client
	ecsClient     *ecs.Client
	elbv2Client   *elbv2.Client
	logsClient    *cloudwatchlogs.Client
	ctx           context.Context
	
	// Resources to be deleted
	resourcesToDelete []ResourceInfo
}

func NewAWSCleanup() (*AWSCleanup, error) {
	ctx := context.Background()
	
	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(AWS_REGION))
	if err != nil {
		return nil, fmt.Errorf("failed to load AWS config: %w", err)
	}

	return &AWSCleanup{
		cfg:           cfg,
		ec2Client:     ec2.NewFromConfig(cfg),
		s3Client:      s3.NewFromConfig(cfg),
		rdsClient:     rds.NewFromConfig(cfg),
		lambdaClient:  lambda.NewFromConfig(cfg),
		ecsClient:     ecs.NewFromConfig(cfg),
		elbv2Client:   elbv2.NewFromConfig(cfg),
		logsClient:    cloudwatchlogs.NewFromConfig(cfg),
		ctx:           ctx,
		resourcesToDelete: make([]ResourceInfo, 0),
	}, nil
}

func (a *AWSCleanup) containsPrefix(name string) bool {
	return strings.Contains(strings.ToLower(name), strings.ToLower(RESOURCE_PREFIX))
}

func (a *AWSCleanup) addResource(resourceType, identifier, name, description string) {
	a.resourcesToDelete = append(a.resourcesToDelete, ResourceInfo{
		Type:        resourceType,
		Identifier:  identifier,
		Name:        name,
		Description: description,
	})
}

// Discover EC2 Instances
func (a *AWSCleanup) discoverEC2Instances() error {
	log.Println("Scanning EC2 instances...")
	
	result, err := a.ec2Client.DescribeInstances(a.ctx, &ec2.DescribeInstancesInput{})
	if err != nil {
		return fmt.Errorf("failed to describe EC2 instances: %w", err)
	}

	for _, reservation := range result.Reservations {
		for _, instance := range reservation.Instances {
			if instance.State.Name == "terminated" {
				continue
			}
			
			// Check instance name from tags
			var instanceName string
			for _, tag := range instance.Tags {
				if aws.ToString(tag.Key) == "Name" {
					instanceName = aws.ToString(tag.Value)
					break
				}
			}
			
			if instanceName == "" {
				instanceName = aws.ToString(instance.InstanceId)
			}
			
			if a.containsPrefix(instanceName) {
				description := fmt.Sprintf("Instance ID: %s, State: %s, Type: %s", 
					aws.ToString(instance.InstanceId), 
					string(instance.State.Name),
					string(instance.InstanceType))
				
				a.addResource("EC2 Instance", aws.ToString(instance.InstanceId), instanceName, description)
			}
		}
	}

	return nil
}

// Discover S3 Buckets
func (a *AWSCleanup) discoverS3Buckets() error {
	log.Println("Scanning S3 buckets...")
	
	result, err := a.s3Client.ListBuckets(a.ctx, &s3.ListBucketsInput{})
	if err != nil {
		return fmt.Errorf("failed to list S3 buckets: %w", err)
	}

	for _, bucket := range result.Buckets {
		bucketName := aws.ToString(bucket.Name)
		if a.containsPrefix(bucketName) {
			description := fmt.Sprintf("Created: %s", bucket.CreationDate.Format("2006-01-02 15:04:05"))
			a.addResource("S3 Bucket", bucketName, bucketName, description)
		}
	}

	return nil
}

// Discover RDS Instances
func (a *AWSCleanup) discoverRDSInstances() error {
	log.Println("Scanning RDS instances...")
	
	result, err := a.rdsClient.DescribeDBInstances(a.ctx, &rds.DescribeDBInstancesInput{})
	if err != nil {
		return fmt.Errorf("failed to describe RDS instances: %w", err)
	}

	for _, instance := range result.DBInstances {
		instanceId := aws.ToString(instance.DBInstanceIdentifier)
		if a.containsPrefix(instanceId) {
			description := fmt.Sprintf("Engine: %s, Status: %s, Class: %s", 
				aws.ToString(instance.Engine),
				aws.ToString(instance.DBInstanceStatus),
				aws.ToString(instance.DBInstanceClass))
			
			a.addResource("RDS Instance", instanceId, instanceId, description)
		}
	}

	return nil
}

// Discover Lambda Functions
func (a *AWSCleanup) discoverLambdaFunctions() error {
	log.Println("Scanning Lambda functions...")
	
	result, err := a.lambdaClient.ListFunctions(a.ctx, &lambda.ListFunctionsInput{})
	if err != nil {
		return fmt.Errorf("failed to list Lambda functions: %w", err)
	}

	for _, function := range result.Functions {
		functionName := aws.ToString(function.FunctionName)
		if a.containsPrefix(functionName) {
			description := fmt.Sprintf("Runtime: %s, Size: %d bytes", 
				string(function.Runtime),
				function.CodeSize)
			
			a.addResource("Lambda Function", functionName, functionName, description)
		}
	}

	return nil
}

// Discover ECS Clusters
func (a *AWSCleanup) discoverECSClusters() error {
	log.Println("Scanning ECS clusters...")
	
	result, err := a.ecsClient.ListClusters(a.ctx, &ecs.ListClustersInput{})
	if err != nil {
		return fmt.Errorf("failed to list ECS clusters: %w", err)
	}

	if len(result.ClusterArns) == 0 {
		return nil
	}

	// Get detailed cluster information
	clusters, err := a.ecsClient.DescribeClusters(a.ctx, &ecs.DescribeClustersInput{
		Clusters: result.ClusterArns,
	})
	if err != nil {
		return fmt.Errorf("failed to describe ECS clusters: %w", err)
	}

	for _, cluster := range clusters.Clusters {
		clusterName := aws.ToString(cluster.ClusterName)
		
		if a.containsPrefix(clusterName) {
			description := fmt.Sprintf("Status: %s, Tasks: %d, Services: %d", 
				aws.ToString(cluster.Status),
				cluster.RunningTasksCount,
				cluster.ActiveServicesCount)
			
			a.addResource("ECS Cluster", aws.ToString(cluster.ClusterArn), clusterName, description)
		}
	}

	return nil
}

// Discover Load Balancers
func (a *AWSCleanup) discoverLoadBalancers() error {
	log.Println("Scanning Load Balancers...")
	
	result, err := a.elbv2Client.DescribeLoadBalancers(a.ctx, &elbv2.DescribeLoadBalancersInput{})
	if err != nil {
		return fmt.Errorf("failed to describe load balancers: %w", err)
	}

	for _, lb := range result.LoadBalancers {
		lbName := aws.ToString(lb.LoadBalancerName)
		if a.containsPrefix(lbName) {
			description := fmt.Sprintf("Type: %s, Scheme: %s, State: %s", 
				string(lb.Type),
				string(lb.Scheme),
				string(lb.State.Code))
			
			a.addResource("Load Balancer", aws.ToString(lb.LoadBalancerArn), lbName, description)
		}
	}

	return nil
}

// Discover Security Groups (excluding default)
// Discover VPCs
func (a *AWSCleanup) discoverVPCs() error {
	log.Println("Scanning VPCs...")

	result, err := a.ec2Client.DescribeVpcs(a.ctx, &ec2.DescribeVpcsInput{})
	if err != nil {
		return fmt.Errorf("failed to describe VPCs: %w", err)
	}

	for _, vpc := range result.Vpcs {
		var vpcName string
		for _, tag := range vpc.Tags {
			if aws.ToString(tag.Key) == "Name" {
				vpcName = aws.ToString(tag.Value)
				break
			}
		}

		if vpcName == "" {
			vpcName = aws.ToString(vpc.VpcId)
		}

		if a.containsPrefix(vpcName) {
			description := fmt.Sprintf("VPC ID: %s, CIDR: %s",
				aws.ToString(vpc.VpcId),
				aws.ToString(vpc.CidrBlock))

			a.addResource("VPC", aws.ToString(vpc.VpcId), vpcName, description)
		}
	}

	return nil
}

// Discover VPC Endpoints
func (a *AWSCleanup) discoverVPCEndpoints() error {
	log.Println("Scanning VPC Endpoints...")

	result, err := a.ec2Client.DescribeVpcEndpoints(a.ctx, &ec2.DescribeVpcEndpointsInput{})
	if err != nil {
		return fmt.Errorf("failed to describe VPC endpoints: %w", err)
	}

	for _, endpoint := range result.VpcEndpoints {
		var endpointName string
		for _, tag := range endpoint.Tags {
			if aws.ToString(tag.Key) == "Name" {
				endpointName = aws.ToString(tag.Value)
				break
			}
		}

		if endpointName == "" {
			endpointName = aws.ToString(endpoint.VpcEndpointId)
		}

		if a.containsPrefix(endpointName) {
			description := fmt.Sprintf("Endpoint ID: %s, Service: %s, State: %s",
				aws.ToString(endpoint.VpcEndpointId),
				aws.ToString(endpoint.ServiceName),
				string(endpoint.State))

			a.addResource("VPC Endpoint", aws.ToString(endpoint.VpcEndpointId), endpointName, description)
		}
	}

	return nil
}

// Discover NAT Gateways
func (a *AWSCleanup) discoverNATGateways() error {
	log.Println("Scanning NAT Gateways...")

	result, err := a.ec2Client.DescribeNatGateways(a.ctx, &ec2.DescribeNatGatewaysInput{})
	if err != nil {
		return fmt.Errorf("failed to describe NAT gateways: %w", err)
	}

	for _, natGw := range result.NatGateways {
		var natGwName string
		for _, tag := range natGw.Tags {
			if aws.ToString(tag.Key) == "Name" {
				natGwName = aws.ToString(tag.Value)
				break
			}
		}

		if natGwName == "" {
			natGwName = aws.ToString(natGw.NatGatewayId)
		}

		if a.containsPrefix(natGwName) {
			description := fmt.Sprintf("NAT Gateway ID: %s, VPC: %s, State: %s",
				aws.ToString(natGw.NatGatewayId),
				aws.ToString(natGw.VpcId),
				string(natGw.State))

			a.addResource("NAT Gateway", aws.ToString(natGw.NatGatewayId), natGwName, description)
		}
	}

	return nil
}

// Discover Internet Gateways
func (a *AWSCleanup) discoverInternetGateways() error {
	log.Println("Scanning Internet Gateways...")

	result, err := a.ec2Client.DescribeInternetGateways(a.ctx, &ec2.DescribeInternetGatewaysInput{})
	if err != nil {
		return fmt.Errorf("failed to describe internet gateways: %w", err)
	}

	for _, igw := range result.InternetGateways {
		var igwName string
		for _, tag := range igw.Tags {
			if aws.ToString(tag.Key) == "Name" {
				igwName = aws.ToString(tag.Value)
				break
			}
		}

		if igwName == "" {
			igwName = aws.ToString(igw.InternetGatewayId)
		}

		if a.containsPrefix(igwName) {
			var attachments []string
			for _, attachment := range igw.Attachments {
				attachments = append(attachments, aws.ToString(attachment.VpcId))
			}

			description := fmt.Sprintf("IGW ID: %s, Attached VPCs: %s",
				aws.ToString(igw.InternetGatewayId),
				strings.Join(attachments, ", "))

			a.addResource("Internet Gateway", aws.ToString(igw.InternetGatewayId), igwName, description)
		}
	}

	return nil
}

// Discover Subnets
func (a *AWSCleanup) discoverSubnets() error {
	log.Println("Scanning Subnets...")

	result, err := a.ec2Client.DescribeSubnets(a.ctx, &ec2.DescribeSubnetsInput{})
	if err != nil {
		return fmt.Errorf("failed to describe subnets: %w", err)
	}

	for _, subnet := range result.Subnets {
		var subnetName string
		for _, tag := range subnet.Tags {
			if aws.ToString(tag.Key) == "Name" {
				subnetName = aws.ToString(tag.Value)
				break
			}
		}

		if subnetName == "" {
			subnetName = aws.ToString(subnet.SubnetId)
		}

		if a.containsPrefix(subnetName) {
			description := fmt.Sprintf("Subnet ID: %s, VPC: %s, CIDR: %s, AZ: %s",
				aws.ToString(subnet.SubnetId),
				aws.ToString(subnet.VpcId),
				aws.ToString(subnet.CidrBlock),
				aws.ToString(subnet.AvailabilityZone))

			a.addResource("Subnet", aws.ToString(subnet.SubnetId), subnetName, description)
		}
	}

	return nil
}

// Discover Route Tables (excluding main route tables)
func (a *AWSCleanup) discoverRouteTables() error {
	log.Println("Scanning Route Tables...")

	result, err := a.ec2Client.DescribeRouteTables(a.ctx, &ec2.DescribeRouteTablesInput{})
	if err != nil {
		return fmt.Errorf("failed to describe route tables: %w", err)
	}

	for _, rt := range result.RouteTables {
		var rtName string
		var isMain bool

		for _, tag := range rt.Tags {
			if aws.ToString(tag.Key) == "Name" {
				rtName = aws.ToString(tag.Value)
				break
			}
		}

		// Check if this is the main route table
		for _, association := range rt.Associations {
			if aws.ToBool(association.Main) {
				isMain = true
				break
			}
		}

		// Skip main route tables
		if isMain {
			continue
		}

		if rtName == "" {
			rtName = aws.ToString(rt.RouteTableId)
		}

		if a.containsPrefix(rtName) {
			description := fmt.Sprintf("Route Table ID: %s, VPC: %s, Routes: %d",
				aws.ToString(rt.RouteTableId),
				aws.ToString(rt.VpcId),
				len(rt.Routes))

			a.addResource("Route Table", aws.ToString(rt.RouteTableId), rtName, description)
		}
	}

	return nil
}

// Discover Network ACLs (excluding default NACLs)
func (a *AWSCleanup) discoverNACLs() error {
	log.Println("Scanning Network ACLs...")

	result, err := a.ec2Client.DescribeNetworkAcls(a.ctx, &ec2.DescribeNetworkAclsInput{})
	if err != nil {
		return fmt.Errorf("failed to describe network ACLs: %w", err)
	}

	for _, nacl := range result.NetworkAcls {
		var naclName string

		for _, tag := range nacl.Tags {
			if aws.ToString(tag.Key) == "Name" {
				naclName = aws.ToString(tag.Value)
				break
			}
		}

		// Skip default NACLs
		if aws.ToBool(nacl.IsDefault) {
			continue
		}

		if naclName == "" {
			naclName = aws.ToString(nacl.NetworkAclId)
		}

		if a.containsPrefix(naclName) {
			description := fmt.Sprintf("NACL ID: %s, VPC: %s, Associations: %d",
				aws.ToString(nacl.NetworkAclId),
				aws.ToString(nacl.VpcId),
				len(nacl.Associations))

			a.addResource("Network ACL", aws.ToString(nacl.NetworkAclId), naclName, description)
		}
	}

	return nil
}

// Discover VPC Peering Connections
func (a *AWSCleanup) discoverVPCPeeringConnections() error {
	log.Println("Scanning VPC Peering Connections...")

	result, err := a.ec2Client.DescribeVpcPeeringConnections(a.ctx, &ec2.DescribeVpcPeeringConnectionsInput{})
	if err != nil {
		return fmt.Errorf("failed to describe VPC peering connections: %w", err)
	}

	for _, conn := range result.VpcPeeringConnections {
		var connName string
		for _, tag := range conn.Tags {
			if aws.ToString(tag.Key) == "Name" {
				connName = aws.ToString(tag.Value)
				break
			}
		}

		if connName == "" {
			connName = aws.ToString(conn.VpcPeeringConnectionId)
		}

		if a.containsPrefix(connName) {
			description := fmt.Sprintf("Peering ID: %s, Requester VPC: %s, Accepter VPC: %s, Status: %s",
				aws.ToString(conn.VpcPeeringConnectionId),
				aws.ToString(conn.RequesterVpcInfo.VpcId),
				aws.ToString(conn.AccepterVpcInfo.VpcId),
				string(conn.Status.Code))

			a.addResource("VPC Peering Connection", aws.ToString(conn.VpcPeeringConnectionId), connName, description)
		}
	}

	return nil
}

// Discover VPC Flow Logs
func (a *AWSCleanup) discoverVPCFlowLogs() error {
	log.Println("Scanning VPC Flow Logs...")

	result, err := a.ec2Client.DescribeFlowLogs(a.ctx, &ec2.DescribeFlowLogsInput{})
	if err != nil {
		return fmt.Errorf("failed to describe flow logs: %w", err)
	}

	for _, flowLog := range result.FlowLogs {
		var flowLogName string
		for _, tag := range flowLog.Tags {
			if aws.ToString(tag.Key) == "Name" {
				flowLogName = aws.ToString(tag.Value)
				break
			}
		}

		if flowLogName == "" {
			flowLogName = aws.ToString(flowLog.FlowLogId)
		}

		if a.containsPrefix(flowLogName) {
			description := fmt.Sprintf("Flow Log ID: %s, Resource ID: %s, Status: %s",
				aws.ToString(flowLog.FlowLogId),
				aws.ToString(flowLog.ResourceId),
				aws.ToString(flowLog.FlowLogStatus))

			a.addResource("VPC Flow Log", aws.ToString(flowLog.FlowLogId), flowLogName, description)
		}
	}

	return nil
}

// Discover Transit Gateways
func (a *AWSCleanup) discoverTransitGateways() error {
	log.Println("Scanning Transit Gateways...")

	result, err := a.ec2Client.DescribeTransitGateways(a.ctx, &ec2.DescribeTransitGatewaysInput{})
	if err != nil {
		return fmt.Errorf("failed to describe transit gateways: %w", err)
	}

	for _, tgw := range result.TransitGateways {
		var tgwName string
		for _, tag := range tgw.Tags {
			if aws.ToString(tag.Key) == "Name" {
				tgwName = aws.ToString(tag.Value)
				break
			}
		}

		if tgwName == "" {
			tgwName = aws.ToString(tgw.TransitGatewayId)
		}

		if a.containsPrefix(tgwName) {
			description := fmt.Sprintf("TGW ID: %s, State: %s",
				aws.ToString(tgw.TransitGatewayId),
				string(tgw.State))

			a.addResource("Transit Gateway", aws.ToString(tgw.TransitGatewayId), tgwName, description)
		}
	}

	return nil
}

// Discover Transit Gateway Attachments
func (a *AWSCleanup) discoverTransitGatewayAttachments() error {
	log.Println("Scanning Transit Gateway Attachments...")

	result, err := a.ec2Client.DescribeTransitGatewayAttachments(a.ctx, &ec2.DescribeTransitGatewayAttachmentsInput{})
	if err != nil {
		return fmt.Errorf("failed to describe transit gateway attachments: %w", err)
	}

	for _, attachment := range result.TransitGatewayAttachments {
		var attachmentName string
		for _, tag := range attachment.Tags {
			if aws.ToString(tag.Key) == "Name" {
				attachmentName = aws.ToString(tag.Value)
				break
			}
		}

		if attachmentName == "" {
			attachmentName = aws.ToString(attachment.TransitGatewayAttachmentId)
		}

		if a.containsPrefix(attachmentName) {
			description := fmt.Sprintf("Attachment ID: %s, TGW: %s, Resource: %s, Type: %s, State: %s",
				aws.ToString(attachment.TransitGatewayAttachmentId),
				aws.ToString(attachment.TransitGatewayId),
				aws.ToString(attachment.ResourceId),
				string(attachment.ResourceType),
				string(attachment.State))

			a.addResource("Transit Gateway Attachment", aws.ToString(attachment.TransitGatewayAttachmentId), attachmentName, description)
		}
	}

	return nil
}

// Discover Network Interfaces
func (a *AWSCleanup) discoverNetworkInterfaces() error {
	log.Println("Scanning Network Interfaces...")

	result, err := a.ec2Client.DescribeNetworkInterfaces(a.ctx, &ec2.DescribeNetworkInterfacesInput{})
	if err != nil {
		return fmt.Errorf("failed to describe network interfaces: %w", err)
	}

	for _, eni := range result.NetworkInterfaces {
		var eniName string
		for _, tag := range eni.TagSet {
			if aws.ToString(tag.Key) == "Name" {
				eniName = aws.ToString(tag.Value)
				break
			}
		}

		if eniName == "" {
			eniName = aws.ToString(eni.NetworkInterfaceId)
		}

		// Check if any of the security groups attached to this ENI have the prefix
		// Or if the ENI itself has the prefix in its name
		// Or if the ENI is in a VPC that matches our prefix
		hasPrefix := false
		if a.containsPrefix(eniName) {
			hasPrefix = true
		} else {
			for _, sg := range eni.Groups {
				if a.containsPrefix(aws.ToString(sg.GroupName)) {
					hasPrefix = true
					break
				}
			}
		}

		// Also check if ENI is in a VPC that matches our prefix
		if !hasPrefix && eni.VpcId != nil {
			if a.vpcMatchesPrefix(aws.ToString(eni.VpcId)) {
				hasPrefix = true
			}
		}

		if hasPrefix {
			description := fmt.Sprintf("ENI ID: %s, Status: %s, VPC: %s, Subnet: %s",
				aws.ToString(eni.NetworkInterfaceId),
				string(eni.Status),
				aws.ToString(eni.VpcId),
				aws.ToString(eni.SubnetId))

			a.addResource("Network Interface", aws.ToString(eni.NetworkInterfaceId), eniName, description)
		}
	}

	return nil
}

// Check if a VPC matches our prefix by checking existing VPC resources
func (a *AWSCleanup) vpcMatchesPrefix(vpcId string) bool {
	// Check if we already have this VPC in our resources to delete
	for _, resource := range a.resourcesToDelete {
		if resource.Type == "VPC" && resource.Identifier == vpcId {
			return true
		}
	}
	
	// If not found in our list, check the VPC name directly
	result, err := a.ec2Client.DescribeVpcs(a.ctx, &ec2.DescribeVpcsInput{
		VpcIds: []string{vpcId},
	})
	if err != nil {
		return false
	}
	
	if len(result.Vpcs) == 0 {
		return false
	}
	
	vpc := result.Vpcs[0]
	var vpcName string
	for _, tag := range vpc.Tags {
		if aws.ToString(tag.Key) == "Name" {
			vpcName = aws.ToString(tag.Value)
			break
		}
	}
	
	if vpcName == "" {
		vpcName = vpcId
	}
	
	return a.containsPrefix(vpcName)
}

func (a *AWSCleanup) discoverSecurityGroups() error {
	log.Println("Scanning Security Groups...")
	
	result, err := a.ec2Client.DescribeSecurityGroups(a.ctx, &ec2.DescribeSecurityGroupsInput{})
	if err != nil {
		return fmt.Errorf("failed to describe security groups: %w", err)
	}

	for _, sg := range result.SecurityGroups {
		sgName := aws.ToString(sg.GroupName)
		
		// Skip default security groups
		if sgName == "default" {
			continue
		}
		
		if a.containsPrefix(sgName) {
			description := fmt.Sprintf("Group ID: %s, VPC: %s", 
				aws.ToString(sg.GroupId),
				aws.ToString(sg.VpcId))
			
			a.addResource("Security Group", aws.ToString(sg.GroupId), sgName, description)
		}
	}

	return nil
}

// Discover all resources
func (a *AWSCleanup) discoverResources() error {
	log.Printf("Discovering AWS resources with prefix: %s", RESOURCE_PREFIX)
	log.Printf("Region: %s", AWS_REGION)
	log.Println("=" + strings.Repeat("=", 50))

	// List of discovery functions ordered for proper VPC cleanup
	discoveryFunctions := []struct {
		name string
		fn   func() error
	}{
		{"EC2 Instances", a.discoverEC2Instances},
		{"S3 Buckets", a.discoverS3Buckets},
		{"RDS Instances", a.discoverRDSInstances},
		{"Lambda Functions", a.discoverLambdaFunctions},
		{"ECS Clusters", a.discoverECSClusters},
		{"Load Balancers", a.discoverLoadBalancers},
		{"VPC Flow Logs", a.discoverVPCFlowLogs},
		{"Transit Gateway Attachments", a.discoverTransitGatewayAttachments},
		{"Transit Gateways", a.discoverTransitGateways},
		{"VPC Peering Connections", a.discoverVPCPeeringConnections},
		{"VPC Endpoints", a.discoverVPCEndpoints},
		{"NAT Gateways", a.discoverNATGateways},
		{"Internet Gateways", a.discoverInternetGateways},
		{"Network Interfaces", a.discoverNetworkInterfaces},
		{"Route Tables", a.discoverRouteTables},
		{"Network ACLs", a.discoverNACLs},
		{"Subnets", a.discoverSubnets},
		{"Security Groups", a.discoverSecurityGroups},
		{"VPCs", a.discoverVPCs},
	}

	for _, discovery := range discoveryFunctions {
		if err := discovery.fn(); err != nil {
			log.Printf("Warning: Error discovering %s: %v", discovery.name, err)
		}
	}

	return nil
}

// Display found resources grouped by type
func (a *AWSCleanup) displayResources() {
	if len(a.resourcesToDelete) == 0 {
		log.Printf("\n✅ No resources found with prefix '%s'", RESOURCE_PREFIX)
		return
	}

	log.Printf("\n🔍 Found %d resources with prefix '%s':\n", len(a.resourcesToDelete), RESOURCE_PREFIX)

	// Group resources by type
	resourcesByType := make(map[string][]ResourceInfo)
	for _, resource := range a.resourcesToDelete {
		resourcesByType[resource.Type] = append(resourcesByType[resource.Type], resource)
	}

	// Display grouped resources
	for resourceType, resources := range resourcesByType {
		fmt.Printf("📁 %s (%d):\n", resourceType, len(resources))
		for i, resource := range resources {
			fmt.Printf("   %d. %s\n", i+1, resource.Name)
			fmt.Printf("      %s\n", resource.Description)
		}
		fmt.Println()
	}
}

// Get user confirmation
func (a *AWSCleanup) getUserConfirmation() bool {
	if len(a.resourcesToDelete) == 0 {
		return false
	}

	fmt.Printf("⚠️  WARNING: This will DELETE %d resources permanently!\n", len(a.resourcesToDelete))
	fmt.Printf("Region: %s\n", AWS_REGION)
	fmt.Printf("Prefix: %s\n\n", RESOURCE_PREFIX)
	
	reader := bufio.NewReader(os.Stdin)
	
	for {
		fmt.Print("Do you want to proceed with deletion? Type 'yes' to confirm or 'no' to cancel: ")
		response, err := reader.ReadString('\n')
		if err != nil {
			log.Printf("Error reading input: %v", err)
			return false
		}
		
		response = strings.TrimSpace(strings.ToLower(response))
		
		switch response {
		case "yes", "y":
			return true
		case "no", "n":
			return false
		default:
			fmt.Println("Please type 'yes' or 'no'")
		}
	}
}

// Delete confirmed resources
func (a *AWSCleanup) deleteResources() error {
	log.Printf("\n🗑️  Starting deletion of %d resources...\n", len(a.resourcesToDelete))
	
	for i, resource := range a.resourcesToDelete {
		log.Printf("[%d/%d] Deleting %s: %s", i+1, len(a.resourcesToDelete), resource.Type, resource.Name)
		
		var err error
		switch resource.Type {
		case "EC2 Instance":
			err = a.deleteEC2Instance(resource.Identifier)
		case "S3 Bucket":
			err = a.deleteS3Bucket(resource.Identifier)
		case "RDS Instance":
			err = a.deleteRDSInstance(resource.Identifier)
		case "Lambda Function":
			err = a.deleteLambdaFunction(resource.Identifier)
		case "ECS Cluster":
			err = a.deleteECSCluster(resource.Identifier)
		case "Load Balancer":
			err = a.deleteLoadBalancer(resource.Identifier)
		case "VPC":
			err = a.deleteVPC(resource.Identifier)
		case "VPC Endpoint":
			err = a.deleteVPCEndpoint(resource.Identifier)
		case "NAT Gateway":
			err = a.deleteNATGateway(resource.Identifier)
		case "Internet Gateway":
			err = a.deleteInternetGateway(resource.Identifier)
		case "Subnet":
			err = a.deleteSubnet(resource.Identifier)
		case "Route Table":
			err = a.deleteRouteTable(resource.Identifier)
		case "Network ACL":
			err = a.deleteNACL(resource.Identifier)
		case "VPC Peering Connection":
			err = a.deleteVPCPeeringConnection(resource.Identifier)
		case "VPC Flow Log":
			err = a.deleteVPCFlowLog(resource.Identifier)
		case "Transit Gateway":
			err = a.deleteTransitGateway(resource.Identifier)
		case "Transit Gateway Attachment":
			err = a.deleteTransitGatewayAttachment(resource.Identifier)
		case "Network Interface":
			err = a.deleteNetworkInterface(resource.Identifier)
		case "Security Group":
			err = a.deleteSecurityGroup(resource.Identifier)
		}
		
		if err != nil {
			log.Printf("   ❌ Failed: %v", err)
		} else {
			log.Printf("   ✅ Success")
		}
	}
	
	return nil
}

// Individual delete functions
func (a *AWSCleanup) deleteEC2Instance(instanceId string) error {
	_, err := a.ec2Client.TerminateInstances(a.ctx, &ec2.TerminateInstancesInput{
		InstanceIds: []string{instanceId},
	})
	return err
}

func (a *AWSCleanup) getS3ClientForBucketRegion(bucketName string) (*s3.Client, error) {
	// Get bucket location
	locationOutput, err := a.s3Client.GetBucketLocation(a.ctx, &s3.GetBucketLocationInput{
		Bucket: aws.String(bucketName),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to get bucket location for %s: %w", bucketName, err)
	}

	bucketRegion := string(locationOutput.LocationConstraint)
	if bucketRegion == "" {
		// If location constraint is empty, it's us-east-1
		bucketRegion = "us-east-1"
	}

	// If the bucket region is different from the current client's region, create a new client
	if bucketRegion != a.cfg.Region {
		log.Printf("Bucket %s is in region %s, current client is in %s. Creating new client for bucket region.", bucketName, bucketRegion, a.cfg.Region)
		cfg, err := config.LoadDefaultConfig(a.ctx, config.WithRegion(bucketRegion))
		if err != nil {
			return nil, fmt.Errorf("failed to load AWS config for region %s: %w", bucketRegion, err)
		}
		return s3.NewFromConfig(cfg), nil
	}

	return a.s3Client, nil
}

func (a *AWSCleanup) deleteS3Bucket(bucketName string) error {
	// First, empty the bucket
	err := a.emptyS3Bucket(bucketName)
	if err != nil {
		return fmt.Errorf("failed to empty bucket: %w", err)
	}
	
	// Then delete the bucket
	s3Client, err := a.getS3ClientForBucketRegion(bucketName)
	if err != nil {
		return err
	}
	_, err = s3Client.DeleteBucket(a.ctx, &s3.DeleteBucketInput{
		Bucket: aws.String(bucketName),
	})
	return err
}

func (a *AWSCleanup) emptyS3Bucket(bucketName string) error {
	s3Client, err := a.getS3ClientForBucketRegion(bucketName)
	if err != nil {
		return err
	}

	log.Printf("   Emptying S3 bucket: %s", bucketName)

	// First, delete all object versions and delete markers
	err = a.deleteS3ObjectVersions(s3Client, bucketName)
	if err != nil {
		return fmt.Errorf("failed to delete object versions: %w", err)
	}

	// Then delete current objects (in case there are any left)
	err = a.deleteS3CurrentObjects(s3Client, bucketName)
	if err != nil {
		return fmt.Errorf("failed to delete current objects: %w", err)
	}

	// Delete any multipart uploads
	err = a.abortS3MultipartUploads(s3Client, bucketName)
	if err != nil {
		log.Printf("   Warning: Failed to abort multipart uploads: %v", err)
	}

	return nil
}

func (a *AWSCleanup) deleteS3CurrentObjects(s3Client *s3.Client, bucketName string) error {
	// Use paginated listing to handle large buckets
	paginator := s3.NewListObjectsV2Paginator(s3Client, &s3.ListObjectsV2Input{
		Bucket: aws.String(bucketName),
	})

	for paginator.HasMorePages() {
		page, err := paginator.NextPage(a.ctx)
		if err != nil {
			return err
		}

		if len(page.Contents) == 0 {
			continue
		}

		var objectsToDelete []s3types.ObjectIdentifier
		for _, obj := range page.Contents {
			objectsToDelete = append(objectsToDelete, s3types.ObjectIdentifier{
				Key: obj.Key,
			})
		}

		// Delete in batches of 1000
		for i := 0; i < len(objectsToDelete); i += 1000 {
			end := i + 1000
			if end > len(objectsToDelete) {
				end = len(objectsToDelete)
			}

			_, err = s3Client.DeleteObjects(a.ctx, &s3.DeleteObjectsInput{
				Bucket: aws.String(bucketName),
				Delete: &s3types.Delete{
					Objects: objectsToDelete[i:end],
				},
			})
			if err != nil {
				return err
			}
		}
	}

	return nil
}

func (a *AWSCleanup) deleteS3ObjectVersions(s3Client *s3.Client, bucketName string) error {
	// Use paginated listing to handle large numbers of versions
	paginator := s3.NewListObjectVersionsPaginator(s3Client, &s3.ListObjectVersionsInput{
		Bucket: aws.String(bucketName),
	})

	for paginator.HasMorePages() {
		page, err := paginator.NextPage(a.ctx)
		if err != nil {
			return err
		}

		var objectsToDelete []s3types.ObjectIdentifier

		// Add all versions from this page
		for _, version := range page.Versions {
			objectsToDelete = append(objectsToDelete, s3types.ObjectIdentifier{
				Key:       version.Key,
				VersionId: version.VersionId,
			})
		}

		// Add all delete markers from this page
		for _, marker := range page.DeleteMarkers {
			objectsToDelete = append(objectsToDelete, s3types.ObjectIdentifier{
				Key:       marker.Key,
				VersionId: marker.VersionId,
			})
		}

		if len(objectsToDelete) == 0 {
			continue
		}

		// Delete versions in batches of 1000 (AWS limit)
		for i := 0; i < len(objectsToDelete); i += 1000 {
			end := i + 1000
			if end > len(objectsToDelete) {
				end = len(objectsToDelete)
			}

			_, err = s3Client.DeleteObjects(a.ctx, &s3.DeleteObjectsInput{
				Bucket: aws.String(bucketName),
				Delete: &s3types.Delete{
					Objects: objectsToDelete[i:end],
				},
			})
			if err != nil {
				return err
			}
		}
	}

	return nil
}

func (a *AWSCleanup) abortS3MultipartUploads(s3Client *s3.Client, bucketName string) error {
	// List multipart uploads
	result, err := s3Client.ListMultipartUploads(a.ctx, &s3.ListMultipartUploadsInput{
		Bucket: aws.String(bucketName),
	})
	if err != nil {
		return err
	}

	// Abort each multipart upload
	for _, upload := range result.Uploads {
		_, err := s3Client.AbortMultipartUpload(a.ctx, &s3.AbortMultipartUploadInput{
			Bucket:   aws.String(bucketName),
			Key:      upload.Key,
			UploadId: upload.UploadId,
		})
		if err != nil {
			log.Printf("   Warning: Failed to abort multipart upload %s: %v", aws.ToString(upload.UploadId), err)
		}
	}

	return nil
}

func (a *AWSCleanup) deleteRDSInstance(instanceId string) error {
	_, err := a.rdsClient.DeleteDBInstance(a.ctx, &rds.DeleteDBInstanceInput{
		DBInstanceIdentifier: aws.String(instanceId),
		SkipFinalSnapshot:   aws.Bool(true),
	})
	return err
}

func (a *AWSCleanup) deleteLambdaFunction(functionName string) error {
	_, err := a.lambdaClient.DeleteFunction(a.ctx, &lambda.DeleteFunctionInput{
		FunctionName: aws.String(functionName),
	})
	return err
}

func (a *AWSCleanup) deleteECSCluster(clusterArn string) error {
	// First, stop all services in the cluster
	err := a.stopECSServices(clusterArn)
	if err != nil {
		return fmt.Errorf("failed to stop services: %w", err)
	}
	
	// Wait a bit for services to stop
	time.Sleep(5 * time.Second)
	
	// Then delete the cluster
	_, err = a.ecsClient.DeleteCluster(a.ctx, &ecs.DeleteClusterInput{
		Cluster: aws.String(clusterArn),
	})
	return err
}

func (a *AWSCleanup) stopECSServices(clusterArn string) error {
	services, err := a.ecsClient.ListServices(a.ctx, &ecs.ListServicesInput{
		Cluster: aws.String(clusterArn),
	})
	if err != nil {
		return err
	}

	for _, serviceArn := range services.ServiceArns {
		_, err := a.ecsClient.UpdateService(a.ctx, &ecs.UpdateServiceInput{
			Cluster:      aws.String(clusterArn),
			Service:      aws.String(serviceArn),
			DesiredCount: aws.Int32(0),
		})
		if err != nil {
			log.Printf("Warning: failed to stop ECS service %s: %v", serviceArn, err)
		}
	}

	return nil
}

func (a *AWSCleanup) deleteLoadBalancer(lbArn string) error {
	_, err := a.elbv2Client.DeleteLoadBalancer(a.ctx, &elbv2.DeleteLoadBalancerInput{
		LoadBalancerArn: aws.String(lbArn),
	})
	return err
}

func (a *AWSCleanup) deleteVPC(vpcId string) error {
	_, err := a.ec2Client.DeleteVpc(a.ctx, &ec2.DeleteVpcInput{
		VpcId: aws.String(vpcId),
	})
	return err
}

func (a *AWSCleanup) deleteVPCEndpoint(endpointId string) error {
	_, err := a.ec2Client.DeleteVpcEndpoints(a.ctx, &ec2.DeleteVpcEndpointsInput{
		VpcEndpointIds: []string{endpointId},
	})
	return err
}

func (a *AWSCleanup) deleteNATGateway(natGwId string) error {
	_, err := a.ec2Client.DeleteNatGateway(a.ctx, &ec2.DeleteNatGatewayInput{
		NatGatewayId: aws.String(natGwId),
	})
	return err
}

func (a *AWSCleanup) deleteInternetGateway(igwId string) error {
	// First get the internet gateway details to see what VPCs it's attached to
	result, err := a.ec2Client.DescribeInternetGateways(a.ctx, &ec2.DescribeInternetGatewaysInput{
		InternetGatewayIds: []string{igwId},
	})
	if err != nil {
		return fmt.Errorf("failed to describe internet gateway: %w", err)
	}

	if len(result.InternetGateways) == 0 {
		return fmt.Errorf("internet gateway %s not found", igwId)
	}

	igw := result.InternetGateways[0]

	// Detach from all VPCs
	for _, attachment := range igw.Attachments {
		_, err := a.ec2Client.DetachInternetGateway(a.ctx, &ec2.DetachInternetGatewayInput{
			InternetGatewayId: aws.String(igwId),
			VpcId:             attachment.VpcId,
		})
		if err != nil {
			return fmt.Errorf("failed to detach internet gateway from VPC %s: %w", aws.ToString(attachment.VpcId), err)
		}
	}

	// Delete the internet gateway
	_, err = a.ec2Client.DeleteInternetGateway(a.ctx, &ec2.DeleteInternetGatewayInput{
		InternetGatewayId: aws.String(igwId),
	})
	return err
}

func (a *AWSCleanup) deleteSubnet(subnetId string) error {
	// First, check for and clean up any route table associations
	err := a.cleanupSubnetRouteTableAssociations(subnetId)
	if err != nil {
		log.Printf("   Warning: Failed to clean up route table associations for subnet %s: %v", subnetId, err)
	}
	
	// Also clean up any remaining ENIs in the subnet
	err = a.cleanupSubnetENIs(subnetId)
	if err != nil {
		log.Printf("   Warning: Failed to clean up ENIs for subnet %s: %v", subnetId, err)
	}
	
	_, err = a.ec2Client.DeleteSubnet(a.ctx, &ec2.DeleteSubnetInput{
		SubnetId: aws.String(subnetId),
	})
	return err
}

func (a *AWSCleanup) cleanupSubnetRouteTableAssociations(subnetId string) error {
	// Get route tables associated with this subnet
	result, err := a.ec2Client.DescribeRouteTables(a.ctx, &ec2.DescribeRouteTablesInput{
		Filters: []types.Filter{
			{
				Name:   aws.String("association.subnet-id"),
				Values: []string{subnetId},
			},
		},
	})
	if err != nil {
		return err
	}

	for _, rt := range result.RouteTables {
		for _, association := range rt.Associations {
			if aws.ToString(association.SubnetId) == subnetId && !aws.ToBool(association.Main) {
				_, err := a.ec2Client.DisassociateRouteTable(a.ctx, &ec2.DisassociateRouteTableInput{
					AssociationId: association.RouteTableAssociationId,
				})
				if err != nil {
					return fmt.Errorf("failed to disassociate route table %s from subnet %s: %w", aws.ToString(rt.RouteTableId), subnetId, err)
				}
			}
		}
	}
	return nil
}

func (a *AWSCleanup) cleanupSubnetENIs(subnetId string) error {
	// Get ENIs in this subnet
	result, err := a.ec2Client.DescribeNetworkInterfaces(a.ctx, &ec2.DescribeNetworkInterfacesInput{
		Filters: []types.Filter{
			{
				Name:   aws.String("subnet-id"),
				Values: []string{subnetId},
			},
		},
	})
	if err != nil {
		return err
	}

	for _, eni := range result.NetworkInterfaces {
		// Only delete ENIs that are available (not attached)
		if eni.Status == types.NetworkInterfaceStatusAvailable {
			_, err := a.ec2Client.DeleteNetworkInterface(a.ctx, &ec2.DeleteNetworkInterfaceInput{
				NetworkInterfaceId: aws.String(aws.ToString(eni.NetworkInterfaceId)),
			})
			if err != nil {
				log.Printf("   Warning: Failed to delete ENI %s in subnet %s: %v", aws.ToString(eni.NetworkInterfaceId), subnetId, err)
			}
		}
	}
	return nil
}

func (a *AWSCleanup) deleteRouteTable(rtId string) error {
	// First get the route table details to disassociate any subnet associations
	result, err := a.ec2Client.DescribeRouteTables(a.ctx, &ec2.DescribeRouteTablesInput{
		RouteTableIds: []string{rtId},
	})
	if err != nil {
		return fmt.Errorf("failed to describe route table: %w", err)
	}

	if len(result.RouteTables) == 0 {
		return fmt.Errorf("route table %s not found", rtId)
	}

	rt := result.RouteTables[0]

	// Disassociate from all subnets
	for _, association := range rt.Associations {
		if !aws.ToBool(association.Main) && association.RouteTableAssociationId != nil {
			_, err := a.ec2Client.DisassociateRouteTable(a.ctx, &ec2.DisassociateRouteTableInput{
				AssociationId: association.RouteTableAssociationId,
			})
			if err != nil {
				return fmt.Errorf("failed to disassociate route table: %w", err)
			}
		}
	}

	// Delete the route table
	_, err = a.ec2Client.DeleteRouteTable(a.ctx, &ec2.DeleteRouteTableInput{
		RouteTableId: aws.String(rtId),
	})
	return err
}

func (a *AWSCleanup) deleteNACL(naclId string) error {
	_, err := a.ec2Client.DeleteNetworkAcl(a.ctx, &ec2.DeleteNetworkAclInput{
		NetworkAclId: aws.String(naclId),
	})
	return err
}

func (a *AWSCleanup) deleteVPCPeeringConnection(connId string) error {
	_, err := a.ec2Client.DeleteVpcPeeringConnection(a.ctx, &ec2.DeleteVpcPeeringConnectionInput{
		VpcPeeringConnectionId: aws.String(connId),
	})
	return err
}

func (a *AWSCleanup) deleteVPCFlowLog(flowLogId string) error {
	_, err := a.ec2Client.DeleteFlowLogs(a.ctx, &ec2.DeleteFlowLogsInput{
		FlowLogIds: []string{flowLogId},
	})
	return err
}

func (a *AWSCleanup) deleteTransitGateway(tgwId string) error {
	_, err := a.ec2Client.DeleteTransitGateway(a.ctx, &ec2.DeleteTransitGatewayInput{
		TransitGatewayId: aws.String(tgwId),
	})
	return err
}

func (a *AWSCleanup) deleteTransitGatewayAttachment(attachmentId string) error {
	_, err := a.ec2Client.DeleteTransitGatewayVpcAttachment(a.ctx, &ec2.DeleteTransitGatewayVpcAttachmentInput{
		TransitGatewayAttachmentId: aws.String(attachmentId),
	})
	if err != nil {
		return err
	}
	
	// Wait for attachment to be deleted before proceeding
	log.Printf("   Waiting for TGW attachment %s to be deleted...", attachmentId)
	time.Sleep(10 * time.Second)
	return nil
}

func (a *AWSCleanup) deleteNetworkInterface(eniId string) error {
	// First, check if the ENI is attached and detach if necessary
	result, err := a.ec2Client.DescribeNetworkInterfaces(a.ctx, &ec2.DescribeNetworkInterfacesInput{
		NetworkInterfaceIds: []string{eniId},
	})
	if err != nil {
		return fmt.Errorf("failed to describe network interface: %w", err)
	}

	if len(result.NetworkInterfaces) == 0 {
		return fmt.Errorf("network interface %s not found", eniId)
	}

	eni := result.NetworkInterfaces[0]

	// If ENI is attached, detach it first
	if eni.Attachment != nil && eni.Attachment.AttachmentId != nil {
		_, err := a.ec2Client.DetachNetworkInterface(a.ctx, &ec2.DetachNetworkInterfaceInput{
			AttachmentId: eni.Attachment.AttachmentId,
			Force:        aws.Bool(true),
		})
		if err != nil {
			return fmt.Errorf("failed to detach network interface: %w", err)
		}
		
		// Wait a moment for detachment
		time.Sleep(5 * time.Second)
	}

	// Now delete the ENI
	_, err = a.ec2Client.DeleteNetworkInterface(a.ctx, &ec2.DeleteNetworkInterfaceInput{
		NetworkInterfaceId: aws.String(eniId),
	})
	return err
}

func (a *AWSCleanup) deleteSecurityGroup(sgId string) error {
	_, err := a.ec2Client.DeleteSecurityGroup(a.ctx, &ec2.DeleteSecurityGroupInput{
		GroupId: aws.String(sgId),
	})
	return err
}

func main() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	
	cleanup, err := NewAWSCleanup()
	if err != nil {
		log.Fatalf("Failed to initialize AWS cleanup: %v", err)
	}

	// Phase 1: Discover resources
	if err := cleanup.discoverResources(); err != nil {
		log.Fatalf("Resource discovery failed: %v", err)
	}

	// Phase 2: Display resources
	cleanup.displayResources()

	// Phase 3: Get user confirmation
	if !cleanup.getUserConfirmation() {
		log.Println("\n❌ Operation cancelled by user.")
		return
	}

	// Phase 4: Delete resources
	if err := cleanup.deleteResources(); err != nil {
		log.Fatalf("Deletion failed: %v", err)
	}

	log.Println("\n🎉 Cleanup completed!")
}