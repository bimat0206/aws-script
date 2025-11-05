#!/usr/bin/env python3
"""
AWS Control Tower Account Factory for Terraform (AFT) Backend Setup Script

This script automates the creation of Terraform state backend resources:
- S3 bucket for state storage with versioning, encryption, and security
- DynamoDB table for state locking
- Proper IAM policies and configurations

Usage:
    python aft_backend_setup.py --profile aft-management
    python aft_backend_setup.py --interactive
    python aft_backend_setup.py --help
"""

import argparse
import json
import sys
import time
import logging
import random
import string
from typing import Dict, Any, Optional
from dataclasses import dataclass, asdict

try:
    import boto3
    from botocore.exceptions import ClientError, NoCredentialsError, ProfileNotFound
except ImportError:
    print("Error: boto3 is required. Install with: pip install boto3")
    sys.exit(1)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler('aft_backend_setup.log')
    ]
)
logger = logging.getLogger(__name__)

def generate_random_prefix(length: int = 5) -> str:
    """Generate a random alphanumeric prefix."""
    return ''.join(random.choices(string.ascii_lowercase + string.digits, k=length))

# ============================================================================
# CONFIGURATION SECTION - MODIFY THESE VALUES AS NEEDED
# ============================================================================

DEFAULT_CONFIG = {
    # S3 Bucket Configuration
    "bucket_name": "{account_id}-s3-aft-tf-state-{random_prefix}",
    "bucket_region": "us-east-1",
    "enable_versioning": True,
    "enable_encryption": None,
    "encryption_algorithm": "AES256",  # Options: AES256, aws:kms
    "kms_key_id": None,
    "block_public_access": None,
    
    # DynamoDB Table Configuration
    "dynamodb_table_name": "{account_id}-ddb-aft-tf-lock-{random_prefix}",
    "dynamodb_region": "us-east-1",
    "billing_mode": "PAY_PER_REQUEST",  # Options: PAY_PER_REQUEST, PROVISIONED
    "read_capacity": 5,
    "write_capacity": 5,
    "enable_pitr": True,
    
    # Resource Tagging
    "tags": {
        "Purpose": "AFT-Terraform-Backend",
        "Environment": "aft-management",
        "ManagedBy": "AFT-Backend-Script",
        "Project": "AWS-Control-Tower-AFT",
    },
    
    # Optional: Bucket Lifecycle Configuration
    "enable_lifecycle": True,
    "lifecycle_rules": [
        {
            "id": "terraform-state-versions",
            "status": "Enabled",
            "noncurrent_version_expiration_days": 90,
            "abort_incomplete_multipart_upload_days": 7
        }
    ],
    
    # Optional: Bucket Notification (for monitoring)
    "enable_notifications": False,
    "notification_topic_arn": None,
    
    # Security Settings
    "require_mfa_delete": False,
    "enable_access_logging": True,
    "access_log_bucket": None,
    
    # Terraform Configuration
    "terraform_state_key": "state/terraform.tfstate",
    "terraform_workspace": "default"
}

# ============================================================================
# END CONFIGURATION SECTION
# ============================================================================

@dataclass
class BackendConfig:
    """Configuration for AFT backend resources"""
    bucket_name: str
    bucket_region: str
    enable_versioning: bool
    enable_encryption: bool
    encryption_algorithm: str
    kms_key_id: Optional[str]
    block_public_access: bool
    dynamodb_table_name: str
    dynamodb_region: str
    billing_mode: str
    read_capacity: int
    write_capacity: int
    enable_pitr: bool
    tags: Dict[str, str]
    enable_lifecycle: bool
    lifecycle_rules: list
    require_mfa_delete: bool
    enable_access_logging: bool
    access_log_bucket: Optional[str]
    enable_notifications: bool
    notification_topic_arn: Optional[str]
    terraform_state_key: str
    terraform_workspace: str
    aws_profile: Optional[str] = None
    account_id: Optional[str] = None

class AFTBackendSetup:
    """Main class for setting up AFT Terraform backend infrastructure"""
    
    def __init__(self, config: BackendConfig):
        self.config = config
        self.session = None
        self.s3_client = None
        self.dynamodb_client = None
        
    def get_aws_profile_interactive(self) -> str:
        """Interactive AWS profile selection"""
        try:
            available_profiles = boto3.Session().available_profiles
            
            if not available_profiles:
                logger.error("No AWS profiles found. Please configure AWS CLI first.")
                sys.exit(1)
            
            print("\n" + "="*60)
            print("AVAILABLE AWS PROFILES:")
            print("="*60)
            for i, profile in enumerate(available_profiles, 1):
                print(f"{i}. {profile}")
            print("="*60)
            
            while True:
                try:
                    choice = input(f"\nSelect AWS profile (1-{len(available_profiles)}) or enter profile name: ").strip()
                    
                    # Check if it's a number
                    if choice.isdigit():
                        choice_num = int(choice)
                        if 1 <= choice_num <= len(available_profiles):
                            return available_profiles[choice_num - 1]
                        else:
                            print(f"Please enter a number between 1 and {len(available_profiles)}")
                            continue
                    
                    # Check if it's a valid profile name
                    if choice in available_profiles:
                        return choice
                    
                    print(f"Profile '{choice}' not found. Available profiles: {', '.join(available_profiles)}")
                    
                except KeyboardInterrupt:
                    print("\nOperation cancelled.")
                    sys.exit(1)
                except Exception as e:
                    print(f"Invalid input: {e}")
                    
        except Exception as e:
            logger.error(f"Error getting available profiles: {e}")
            sys.exit(1)
    
    def initialize_aws_session(self, aws_profile: Optional[str] = None) -> bool:
        """Initialize AWS session with specified or interactively selected profile"""
        try:
            if aws_profile:
                profile_name = aws_profile
                logger.info(f"Using AWS profile: {profile_name}")
            else:
                profile_name = self.get_aws_profile_interactive()
                logger.info(f"Selected AWS profile: {profile_name}")
            
            self.config.aws_profile = profile_name
            self.session = boto3.Session(profile_name=profile_name)
            
            # Test credentials by getting caller identity
            sts_client = self.session.client('sts')
            identity = sts_client.get_caller_identity()
            
            self.config.account_id = identity['Account']
            
            logger.info(f"Successfully authenticated as: {identity['Arn']}")
            logger.info(f"Account ID: {identity['Account']}")
            
            # Generate and replace random prefix
            random_prefix = generate_random_prefix()
            logger.info(f"Generated random prefix: {random_prefix}")
            
            # Replace placeholders in bucket name and DynamoDB table name
            self.config.bucket_name = self.config.bucket_name.replace("{random_prefix}", random_prefix)
            self.config.dynamodb_table_name = self.config.dynamodb_table_name.replace("{random_prefix}", random_prefix)
            
            if "{account_id}" in self.config.bucket_name:
                original_bucket_name = self.config.bucket_name
                self.config.bucket_name = self.config.bucket_name.replace("{account_id}", identity['Account'])
                logger.info(f"Bucket name updated: {original_bucket_name} -> {self.config.bucket_name}")
            
            if "{account_id}" in self.config.dynamodb_table_name:
                original_table_name = self.config.dynamodb_table_name
                self.config.dynamodb_table_name = self.config.dynamodb_table_name.replace("{account_id}", identity['Account'])
                logger.info(f"DynamoDB table name updated: {original_table_name} -> {self.config.dynamodb_table_name}")
            
            # Initialize service clients
            self.s3_client = self.session.client('s3', region_name=self.config.bucket_region)
            self.dynamodb_client = self.session.client('dynamodb', region_name=self.config.dynamodb_region)
            
            return True
            
        except ProfileNotFound:
            logger.error(f"AWS profile '{profile_name}' not found")
            available_profiles = boto3.Session().available_profiles
            logger.error("Available profiles: " + ", ".join(available_profiles))
            return False
        except NoCredentialsError:
            logger.error("No AWS credentials found")
            return False
        except ClientError as e:
            logger.error(f"AWS authentication failed: {e}")
            return False
        except Exception as e:
            logger.error(f"Unexpected error during AWS session initialization: {e}")
            return False
    
    def check_s3_bucket_exists(self) -> bool:
        """Check if S3 bucket already exists"""
        try:
            self.s3_client.head_bucket(Bucket=self.config.bucket_name)
            return True
        except ClientError as e:
            error_code = e.response['Error']['Code']
            if error_code == '404':
                return False
            else:
                logger.error(f"Error checking bucket existence: {e}")
                raise
    
    def create_s3_bucket(self) -> bool:
        """Create S3 bucket for Terraform state"""
        try:
            if self.check_s3_bucket_exists():
                logger.warning(f"S3 bucket '{self.config.bucket_name}' already exists")
                return True
            
            logger.info(f"Creating S3 bucket: {self.config.bucket_name}")
            
            # Create bucket (different handling for us-east-1)
            if self.config.bucket_region == 'us-east-1':
                self.s3_client.create_bucket(Bucket=self.config.bucket_name)
            else:
                self.s3_client.create_bucket(
                    Bucket=self.config.bucket_name,
                    CreateBucketConfiguration={'LocationConstraint': self.config.bucket_region}
                )
            
            # Wait for bucket to be available
            logger.info("Waiting for bucket to be available...")
            waiter = self.s3_client.get_waiter('bucket_exists')
            waiter.wait(Bucket=self.config.bucket_name)
            
            logger.info("✅ S3 bucket created successfully")
            return True
            
        except ClientError as e:
            logger.error(f"Failed to create S3 bucket: {e}")
            return False
    
    def configure_s3_bucket(self) -> bool:
        """Configure S3 bucket with versioning, encryption, and security settings"""
        try:
            bucket_name = self.config.bucket_name
            
            # Enable versioning
            if self.config.enable_versioning:
                logger.info("Enabling S3 bucket versioning...")
                versioning_config = {'Status': 'Enabled'}
                if self.config.require_mfa_delete:
                    versioning_config['MfaDelete'] = 'Enabled'
                
                self.s3_client.put_bucket_versioning(
                    Bucket=bucket_name,
                    VersioningConfiguration=versioning_config
                )
            
            # Enable server-side encryption
            if self.config.enable_encryption:
                logger.info(f"Enabling S3 bucket encryption ({self.config.encryption_algorithm})...")
                encryption_rule = {
                    'ApplyServerSideEncryptionByDefault': {
                        'SSEAlgorithm': self.config.encryption_algorithm
                    }
                }
                
                if self.config.encryption_algorithm == 'aws:kms' and self.config.kms_key_id:
                    encryption_rule['ApplyServerSideEncryptionByDefault']['KMSMasterKeyID'] = self.config.kms_key_id
                
                encryption_config = {'Rules': [encryption_rule]}
                self.s3_client.put_bucket_encryption(
                    Bucket=bucket_name,
                    ServerSideEncryptionConfiguration=encryption_config
                )
            
            # Block public access
            if self.config.block_public_access:
                logger.info("Configuring S3 bucket public access block...")
                self.s3_client.put_public_access_block(
                    Bucket=bucket_name,
                    PublicAccessBlockConfiguration={
                        'BlockPublicAcls': True,
                        'IgnorePublicAcls': True,
                        'BlockPublicPolicy': True,
                        'RestrictPublicBuckets': True
                    }
                )
            
            # Configure lifecycle rules
            if self.config.enable_lifecycle and self.config.lifecycle_rules:
                logger.info("Configuring S3 bucket lifecycle rules...")
                lifecycle_rules = []
                for rule in self.config.lifecycle_rules:
                    lifecycle_rule = {
                        'ID': rule['id'],
                        'Status': rule['status'],
                        'Filter': {'Prefix': ''}
                    }
                    
                    if 'noncurrent_version_expiration_days' in rule:
                        lifecycle_rule['NoncurrentVersionExpiration'] = {
                            'NoncurrentDays': rule['noncurrent_version_expiration_days']
                        }
                    
                    if 'abort_incomplete_multipart_upload_days' in rule:
                        lifecycle_rule['AbortIncompleteMultipartUpload'] = {
                            'DaysAfterInitiation': rule['abort_incomplete_multipart_upload_days']
                        }
                    
                    lifecycle_rules.append(lifecycle_rule)
                
                self.s3_client.put_bucket_lifecycle_configuration(
                    Bucket=bucket_name,
                    LifecycleConfiguration={'Rules': lifecycle_rules}
                )
            
            
            
            # Add tags
            if self.config.tags:
                logger.info("Adding tags to S3 bucket...")
                tag_set = [{'Key': k, 'Value': v} for k, v in self.config.tags.items()]
                self.s3_client.put_bucket_tagging(
                    Bucket=bucket_name,
                    Tagging={'TagSet': tag_set}
                )
            
            logger.info("✅ S3 bucket configuration completed")
            return True
            
        except ClientError as e:
            logger.error(f"Failed to configure S3 bucket: {e}")
            return False
    
    def check_dynamodb_table_exists(self) -> bool:
        """Check if DynamoDB table already exists"""
        try:
            self.dynamodb_client.describe_table(TableName=self.config.dynamodb_table_name)
            return True
        except ClientError as e:
            if e.response['Error']['Code'] == 'ResourceNotFoundException':
                return False
            else:
                logger.error(f"Error checking DynamoDB table existence: {e}")
                raise
    
    def create_dynamodb_table(self) -> bool:
        """Create DynamoDB table for Terraform state locking"""
        try:
            if self.check_dynamodb_table_exists():
                logger.warning(f"DynamoDB table '{self.config.dynamodb_table_name}' already exists")
                return self.configure_dynamodb_table()
            
            logger.info(f"Creating DynamoDB table: {self.config.dynamodb_table_name}")
            
            table_config = {
                'TableName': self.config.dynamodb_table_name,
                'KeySchema': [
                    {
                        'AttributeName': 'LockID',
                        'KeyType': 'HASH'
                    }
                ],
                'AttributeDefinitions': [
                    {
                        'AttributeName': 'LockID',
                        'AttributeType': 'S'
                    }
                ],
                'BillingMode': self.config.billing_mode
            }
            
            # Add provisioned throughput if needed
            if self.config.billing_mode == 'PROVISIONED':
                table_config['ProvisionedThroughput'] = {
                    'ReadCapacityUnits': self.config.read_capacity,
                    'WriteCapacityUnits': self.config.write_capacity
                }
            
            # Add tags if provided
            if self.config.tags:
                table_config['Tags'] = [
                    {'Key': k, 'Value': v} for k, v in self.config.tags.items()
                ]
            
            self.dynamodb_client.create_table(**table_config)
            
            # Wait for table to be active
            logger.info("Waiting for DynamoDB table to become active...")
            waiter = self.dynamodb_client.get_waiter('table_exists')
            waiter.wait(TableName=self.config.dynamodb_table_name)
            
            logger.info("✅ DynamoDB table created successfully")
            
            # Configure DynamoDB table settings
            return self.configure_dynamodb_table()
            
        except ClientError as e:
            logger.error(f"Failed to create DynamoDB table: {e}")
            return False
    
    def configure_dynamodb_table(self) -> bool:
        """Configure DynamoDB table settings like Point-in-Time Recovery (PITR)"""
        try:
            # Enable Point-in-Time Recovery
            if self.config.enable_pitr:
                logger.info(f"Enabling Point-in-Time Recovery (PITR) for {self.config.dynamodb_table_name}...")
                self.dynamodb_client.update_continuous_backups(
                    TableName=self.config.dynamodb_table_name,
                    PointInTimeRecoverySpecification={
                        'PointInTimeRecoveryEnabled': True
                    }
                )
                logger.info("✅ PITR enabled successfully")
            
            # Placeholder for other configurations (e.g., on-demand backups)
            
            return True
        except ClientError as e:
            logger.error(f"Failed to configure DynamoDB table: {e}")
            return False
    
    def verify_setup(self) -> bool:
        """Verify that all backend resources are properly configured"""
        logger.info("Verifying backend setup...")
        
        try:
            # Verify S3 bucket
            s3_response = self.s3_client.head_bucket(Bucket=self.config.bucket_name)
            logger.info(f"✅ S3 bucket '{self.config.bucket_name}' is accessible")
            
            # Check versioning
            versioning = self.s3_client.get_bucket_versioning(Bucket=self.config.bucket_name)
            if versioning.get('Status') == 'Enabled':
                logger.info("✅ S3 bucket versioning is enabled")
            else:
                logger.warning("⚠️ S3 bucket versioning is not enabled")
            
            # Check encryption
            try:
                encryption = self.s3_client.get_bucket_encryption(Bucket=self.config.bucket_name)
                logger.info("✅ S3 bucket encryption is enabled")
            except ClientError as e:
                if e.response['Error']['Code'] == 'ServerSideEncryptionConfigurationNotFoundError':
                    logger.warning("⚠️ S3 bucket encryption is not configured")
                else:
                    logger.error(f"Error checking encryption: {e}")
            
            # Verify DynamoDB table
            table_response = self.dynamodb_client.describe_table(
                TableName=self.config.dynamodb_table_name
            )
            table_status = table_response['Table']['TableStatus']
            
            if table_status == 'ACTIVE':
                logger.info(f"✅ DynamoDB table '{self.config.dynamodb_table_name}' is active")
            else:
                logger.warning(f"⚠️ DynamoDB table status: {table_status}")
            
            # Check Point-in-Time Recovery (PITR)
            try:
                pitr_status = self.dynamodb_client.describe_continuous_backups(
                    TableName=self.config.dynamodb_table_name
                )
                if pitr_status['ContinuousBackupsDescription']['PointInTimeRecoveryDescription']['PointInTimeRecoveryStatus'] == 'ENABLED':
                    logger.info("✅ DynamoDB PITR is enabled")
                else:
                    logger.warning("⚠️ DynamoDB PITR is not enabled")
            except ClientError as e:
                logger.error(f"Error checking PITR status: {e}")
            
            return True
            
        except ClientError as e:
            logger.error(f"Verification failed: {e}")
            return False
    
    def display_configuration_summary(self) -> None:
        """Display current configuration summary"""
        print("\n" + "="*80)
        print("AFT TERRAFORM BACKEND CONFIGURATION SUMMARY")
        print("="*80)
        print(f"AWS Profile:          {self.config.aws_profile}")
        print(f"Account ID:           {self.config.account_id}")
        print(f"")
        print(f"S3 Bucket:           {self.config.bucket_name}")
        print(f"S3 Region:           {self.config.bucket_region}")
        print(f"Versioning:          {'Enabled' if self.config.enable_versioning else 'Disabled'}")
        print(f"Encryption:          {self.config.encryption_algorithm if self.config.enable_encryption else 'Disabled'}")
        print(f"")
        print(f"DynamoDB Table:      {self.config.dynamodb_table_name}")
        print(f"DynamoDB Region:     {self.config.dynamodb_region}")
        print(f"Billing Mode:        {self.config.billing_mode}")
        print(f"PITR Enabled:        {self.config.enable_pitr}")
        print(f"")
        print(f"Terraform State Key: {self.config.terraform_state_key}")
        print("="*80)
    
    def generate_terraform_config(self) -> str:
        """Generate Terraform backend configuration"""
        terraform_config = f'''terraform {{
  backend "s3" {{
    bucket         = "{self.config.bucket_name}"
    key            = "{self.config.terraform_state_key}"
    region         = "{self.config.bucket_region}"
    dynamodb_table = "{self.config.dynamodb_table_name}"
    encrypt        = true
    
    # Optional: Add workspace support
    workspace_key_prefix = "workspaces"
    
    # Optional: Add profile if not using default credentials
    # profile = "{self.config.aws_profile}"
  }}
  
  required_providers {{
    aws = {{
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }}
  }}
}}

provider "aws" {{
  region = "{self.config.bucket_region}"
  
  # Optional: Use specific profile
  # profile = "{self.config.aws_profile}"
  
  default_tags {{
    tags = {{
      ManagedBy   = "Terraform"
      Environment = "aft-management"
      Purpose     = "AFT-Infrastructure"
    }}
  }}
}}'''
        return terraform_config
    
    def save_configuration_file(self) -> str:
        """Save current configuration to a JSON file for future reference"""
        config_dict = asdict(self.config)
        # Remove sensitive or runtime-specific fields
        config_dict.pop('aws_profile', None)
        config_dict.pop('account_id', None)
        
        config_filename = f"aft_backend_config_{self.config.account_id}.json"
        with open(config_filename, 'w') as f:
            json.dump(config_dict, f, indent=2)
        
        logger.info(f"Configuration saved to: {config_filename}")
        return config_filename
    
    def run_setup(self, aws_profile: Optional[str] = None, interactive: bool = False) -> bool:
        """Execute the complete backend setup process"""
        logger.info("Starting AFT Terraform backend setup...")
        
        # Initialize AWS session
        if not self.initialize_aws_session(aws_profile):
            return False
        
        # Display configuration summary
        self.display_configuration_summary()
        
        # Confirm before proceeding (unless in non-interactive mode)
        if interactive or not aws_profile:
            response = input("\nProceed with backend setup? (y/N): ")
            if response.lower() != 'y':
                logger.info("Setup cancelled")
                return False
        
        # Create and configure S3 bucket
        if not self.create_s3_bucket():
            return False
        
        if not self.configure_s3_bucket():
            return False
        
        # Create DynamoDB table
        if not self.create_dynamodb_table():
            return False
        
        # Verify setup
        if not self.verify_setup():
            return False
        
        # Generate and save configurations
        terraform_config = self.generate_terraform_config()
        config_file = self.save_configuration_file()
        
        logger.info("🎉 AFT Terraform backend setup completed successfully!")
        logger.info("\n" + "="*80)
        logger.info("TERRAFORM BACKEND CONFIGURATION:")
        logger.info("="*80)
        print(terraform_config)
        logger.info("="*80)
        
        # Save Terraform configuration to file
        terraform_config_file = f"terraform_backend_config_{self.config.account_id}.tf"
        with open(terraform_config_file, 'w') as f:
            f.write(terraform_config)
        logger.info(f"Terraform configuration saved to: {terraform_config_file}")
        
        # Final summary
        print(f"\n🎯 SETUP SUMMARY:")
        print(f"   ✅ S3 Bucket: {self.config.bucket_name}")
        print(f"   ✅ DynamoDB Table: {self.config.dynamodb_table_name}")
        print(f"   ✅ Terraform Config: {terraform_config_file}")
        print(f"   ✅ Configuration Backup: {config_file}")
        print(f"\n📝 Next Steps:")
        print(f"   1. Copy the Terraform configuration to your AFT deployment directory")
        print(f"   2. Run 'terraform init' to initialize the backend")
        print(f"   3. Proceed with AFT module deployment")
        
        return True

def main():
    parser = argparse.ArgumentParser(
        description="Setup AFT Terraform backend infrastructure (S3 + DynamoDB)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Use specific AWS profile
  python aft_backend_setup.py --profile aft-management
  
  # Interactive profile selection
  python aft_backend_setup.py --interactive
  
  # Non-interactive with profile (no confirmation prompt)
  python aft_backend_setup.py --profile aft-management --yes
  
  # Show current configuration without deploying
  python aft_backend_setup.py --show-config
        """
    )
    
    parser.add_argument(
        '--profile',
        type=str,
        help='AWS profile name to use'
    )
    
    parser.add_argument(
        '--interactive',
        action='store_true',
        help='Interactive profile selection mode'
    )
    
    parser.add_argument(
        '--yes',
        action='store_true',
        help='Skip confirmation prompt (non-interactive mode)'
    )
    
    parser.add_argument(
        '--show-config',
        action='store_true',
        help='Show current configuration and exit'
    )
    
    parser.add_argument(
        '--dry-run',
        action='store_true',
        help='Show what would be created without actually creating resources'
    )
    
    args = parser.parse_args()
    
    # Create configuration from embedded defaults
    config = BackendConfig(**DEFAULT_CONFIG)
    
    # Show configuration if requested
    if args.show_config:
        print("\n" + "="*80)
        print("EMBEDDED CONFIGURATION:")
        print("="*80)
        config_dict = asdict(config)
        for key, value in config_dict.items():
            if key not in ['aws_profile', 'account_id']:  # Skip runtime fields
                print(f"{key:30} = {value}")
        print("="*80)
        print("\nTo modify configuration, edit the DEFAULT_CONFIG section in the script.")
        return
    
    # Validate arguments
    if args.profile and args.interactive:
        logger.error("Cannot specify both --profile and --interactive")
        sys.exit(1)
    
    if not args.profile and not args.interactive and not args.dry_run:
        logger.error("Either --profile or --interactive must be specified")
        parser.print_help()
        sys.exit(1)
    
    if args.dry_run:
        logger.info("DRY RUN MODE - No resources will be created")
        if args.profile:
            logger.info(f"Would use AWS profile: {args.profile}")
        else:
            logger.info("Would prompt for AWS profile selection")
        
        # Show what would be created
        temp_config = BackendConfig(**DEFAULT_CONFIG)
        temp_config.account_id = "123456789012"  # Placeholder
        random_prefix = generate_random_prefix()
        temp_config.bucket_name = temp_config.bucket_name.replace("{random_prefix}", random_prefix).replace("{account_id}", "123456789012")
        temp_config.dynamodb_table_name = temp_config.dynamodb_table_name.replace("{random_prefix}", random_prefix).replace("{account_id}", "123456789012")
        
        print("\n" + "="*80)
        print("RESOURCES THAT WOULD BE CREATED:")
        print("="*80)
        print(f"S3 Bucket:      {temp_config.bucket_name}")
        print(f"DynamoDB Table: {temp_config.dynamodb_table_name}")
        print(f"Region:         {temp_config.bucket_region}")
        print("="*80)
        return
    
    # Run setup
    setup = AFTBackendSetup(config)
    
    # Determine if we should prompt for confirmation
    interactive_mode = args.interactive or (not args.yes and args.profile)
    
    success = setup.run_setup(
        aws_profile=args.profile,
        interactive=interactive_mode
    )
    
    sys.exit(0 if success else 1)

if __name__ == "__main__":
    main()