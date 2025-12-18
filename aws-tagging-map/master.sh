#!/bin/bash

AWS_ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
echo "Running tagging on AWS Account ID: $AWS_ACCOUNT_ID"

# Function to check if a service is available in the AWS account
check_service() {
    local service=$1
    local command=$2

    if $command &>/dev/null; then
        return 0
    else
        return 1
    fi
}

# Array of services and their corresponding AWS CLI commands to check availability
services=(
    "secretsmanager:aws secretsmanager list-secrets"
    "ecr:aws ecr describe-repositories"
    "ec2:aws ec2 describe-instances"
    "ebs_volume:aws ec2 describe-volumes"
    "rds:aws rds describe-db-instances"
    "sns:aws sns list-topics"
    "sqs:aws sqs list-queues"
    "s3:aws s3api list-buckets"
    "lambda:aws lambda list-functions"
    "elb:aws elb describe-load-balancers"
    "ebs_snapshot:aws ec2 describe-snapshots"
    "ecs:aws ecs list-clusters"
    "direct_connect:aws directconnect describe-connections"
    "eks:aws eks list-clusters"
    "fsx:aws fsx describe-file-systems"
    "apigateway:aws apigateway get-rest-apis"
    "network_firewall:aws network-firewall list-firewalls"
    "opensearch:aws opensearch list-domain-names"
    "route53:aws route53 list-hosted-zones"
    "aws_backup:aws backup list-backup-vaults"
    "cloudwatch_logs_groups:aws logs describe-log-groups"
    "efs:aws efs describe-file-systems"
    "elasticache:aws elasticache describe-cache-clusters"
)

total_services=${#services[@]}
current_service=0

for service in "${services[@]}"; do
    IFS=":" read -r script check_command <<< "$service"
    script_file="${script}.sh"

    ((current_service++))
    echo -e "\n=========="
    echo "Progress: $current_service/$total_services - Checking service $script..."
    echo "=========="

    if check_service "$script" "$check_command"; then
        if [[ -f "$script_file" ]]; then
            echo "Running script: $script_file"
            chmod +x "$script_file" && ./"$script_file"
            echo "Completed script: $script_file"
        else
            echo "Script file $script_file not found, skipping..."
        fi
    else
        echo "Service $script is not available in this AWS account, skipping..."
    fi
done

echo -e "\nTagging process completed for AWS Account ID: $AWS_ACCOUNT_ID"
