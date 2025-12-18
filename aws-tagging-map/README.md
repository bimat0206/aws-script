# AWS Service Tagging Script

This script checks the availability of various AWS services in your AWS account and runs corresponding tagging scripts if the services are available.

## Prerequisites

- AWS CLI must be installed and configured with appropriate permissions.
- set the AWS environment variables:
export AWS_ACCESS_KEY_ID=
export AWS_SECRET_ACCESS_KEY=
export AWS_SESSION_TOKEN=
- `jq` must be installed for JSON processing.
- Ensure individual service tagging scripts (e.g., `ecr.sh`, `ec2.sh`, etc.) are available in the same directory as this script.

## Usage

Run the script:
chmod +x master.sh
./master.sh

## Script Details

The script performs the following tasks:

1. Retrieves the AWS Account ID using the AWS CLI.
2. Checks the availability of each specified AWS service in the account.
3. If a service is available, it runs the corresponding tagging script for that service.
4. Displays progress and handles cases where services or scripts are not available gracefully.

## Services Checked

The script checks for the following AWS services and runs their corresponding scripts if available:

- Amazon Elastic Container Registry (ECR)
- AWS Secrets Manager
- Amazon EC2 Instances
- Amazon EBS Volumes
- Amazon RDS Instances
- Amazon SNS Topics
- Amazon SQS Queues
- Amazon S3 Buckets
- AWS Lambda Functions
- Amazon Elastic Load Balancers (ELB)
- Amazon EBS Snapshots
- Amazon ECS Clusters
- AWS Direct Connect
- Amazon EKS Clusters
- Amazon FSx File Systems
- Amazon API Gateway
- AWS Network Firewall
- Amazon OpenSearch (Elasticsearch Service)
- Amazon Route 53 Hosted Zones
- AWS Backup Vaults
- Amazon CloudWatch Log Groups
- Amazon EFS File Systems
- Amazon ElastiCache Clusters

## Script Execution

For each service, the script:

1. Checks if the service is available in the AWS account using the corresponding AWS CLI command.
2. If the service is available and a corresponding script file (e.g., `ecr.sh`) is found, it makes the script executable and runs it.
3. If the service is not available or the script file is not found, it skips to the next service.

## Example `tags.json`

Ensure each individual service tagging script uses a `tags.json` file for the tags to be applied. An example `tags.json` file:

```json
{
  "Tags": {
    "Environment": "Production",
    "Owner": "YourName"
  }
}
