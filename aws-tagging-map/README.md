# AWS Interactive Tagging Tool

This project provides an interactive Python script to tag AWS resources across multiple services in bulk. It is designed to be safer and more user-friendly, offering resource previews, confirmation steps, and detailed logging.

## Features

- **Interactive Selection**: Choose specific services to scan or select all available services.
- **Resource Preview**: View a list of resources (ID, Name, ARN) that will be tagged *before* any changes are made.
- **Safety**: Detailed summary of resources and explicit confirmation prompt (`y/n`) prevents accidental tagging.
- **Logging**: detailed logs of every execution are saved in the `log/` directory, including resources found, tags applied, and any errors.
- **Account Verification**: Displays the Target AWS Account ID and Account Alias (name) to ensure you are operating in the correct environment.
- **Consistency**: Uses a central `tags.json` file to define tags, ensuring consistency across all resources.

## Prerequisites

- **Python 3**: The script requires Python 3.
- **Boto3**: The AWS SDK for Python.
  ```bash
  pip install boto3
  ```
- **AWS Credentials**: The script uses your environment's default AWS credentials (e.g., `~/.aws/credentials`, `AWS_PROFILE`, or environment variables). Ensure you have permissions to `describe` and `tag` resources for the services you are managing.

## Configuration

Define the tags you want to apply in the `tags.json` file in the root directory.

**Example `tags.json`:**
```json
{
  "Tags": {
    "Environment": "Production",
    "Project": "Migration",
    "ManagedBy": "AWS-Tagging-Script"
  }
}
```

## Usage

Run the script from the terminal:

```bash
python3 aws_tagging_interactive.py
```

### Execution Flow:
1. **Startup**: script initializes, verifies credentials, and loads tags.
2. **Operation Mode**: You are prompted to select:
   - `1`: Apply Tags (Add/Update)
   - `2`: Remove Tags
3. **Service Selection**: You are prompted to select services.
   - Enter numbers (e.g., `1, 5, 10`) for specific services.
   - Enter `a` to scan ALL supported services.
4. **Scanning**: The script scans selected services for resources.
5. **Preview**: A preview of found resources is displayed.
6. **Confirmation**: You must type `y` to proceed.
7. **Completion**: Operation is executed, and a log file is generated.

## Supported Services

The script currently supports tagging for the following services:

- API Gateway (REST & HTTP)
- AWS Backup (Vaults)
- CloudWatch Logs (Log Groups)
- Direct Connect
- DynamoDB Tables
- EBS (Volumes & Snapshots)
- EC2 Instances
- ECR Repositories
- ECS Clusters
- EFS File Systems
- EKS Clusters
- ElastiCache Clusters
- Elastic Load Balancing (Classic & Application/Network)
- FSx File Systems
- Lambda Functions
- Network Firewall
- OpenSearch Domains
- RDS Instances
- Route 53 Hosted Zones
- S3 Buckets
- Secrets Manager
- SNS Topics
- SQS Queues

## Directory Structure

```
├── aws_tagging_interactive.py  # Main Python script
├── tags.json                   # Configuration file for tags
├── log/                        # Directory for execution logs
```

## Logs

Logs are stored in the `log/` directory with the naming convention `aws_tagging_YYYY-MM-DD_HH-MM-SS.log`. These logs contain:
- Execution params (Account, Region)
- Selected services
- List of resources identified
- Success/Failure status of tagging operations
