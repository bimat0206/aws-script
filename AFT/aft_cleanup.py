#!/usr/bin/env python3
"""
Comprehensive AFT Resource Cleanup Script
Dynamically discovers and cleans up ALL AWS resources with 'aft' in their names
that are preventing Terraform deployment across multiple AWS accounts.

Dry Run (Recommended First)
# See what would be deleted without actually deleting
python aft_cleanup.py --account-id 549118124188 --profile my-profile --dry-run

Single Account Cleanup
python aft_cleanup.py --account-id 549118124188 --profile my-profile --region us-east-1
"""

import boto3
import json
import logging
import sys
import argparse
import re
from typing import List, Dict, Any, Optional, Set
from botocore.exceptions import ClientError, NoCredentialsError
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('aft_cleanup.log'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

class ComprehensiveAFTCleaner:
    def __init__(self, account_id: str, region: str = 'us-east-1', role_name: str = None, profile_name: str = None):
        """
        Initialize the Comprehensive AFT Resource Cleaner
        
        Args:
            account_id: AWS Account ID to clean
            region: AWS region (default: us-east-1)
            role_name: IAM role name to assume for cross-account access
            profile_name: AWS profile name to use
        """
        self.account_id = account_id
        self.region = region
        self.role_name = role_name
        self.profile_name = profile_name
        self.session = None
        self.clients = {}
        self.resources_found = {
            'iam_roles': [],
            'iam_policies': [],
            'iam_users': [],
            'iam_groups': [],
            'iam_instance_profiles': [],
            's3_buckets': [],
            'lambda_functions': [],
            'lambda_layers': [],
            'cloudwatch_log_groups': [],
            'cloudwatch_alarms': [],
            'cloudwatch_dashboards': [],
            'cloudwatch_queries': [],
            'eventbridge_rules': [],
            'eventbridge_buses': [],
            'step_functions': [],
            'codebuild_projects': [],
            'codepipeline_pipelines': [],
            'codecommit_repos': [],
            'dynamodb_tables': [],
            'kms_keys': [],
            'kms_aliases': [],
            'ssm_parameters': [],
            'secrets_manager': [],
            'sns_topics': [],
            'sqs_queues': [],
            'cloudformation_stacks': [],
            'ec2_security_groups': [],
            'ec2_vpcs': [],
            'backup_vaults': [],
            'backup_plans': []
        }
        
        # Pattern to match AFT-related resources (case insensitive)
        self.aft_pattern = re.compile(r'.*aft.*', re.IGNORECASE)
    
    def _setup_session(self):
        """Setup AWS session with proper credentials and profile support"""
        try:
            # Start with specified profile or default
            if self.profile_name:
                logger.info(f"Using AWS profile: {self.profile_name}")
                base_session = boto3.Session(profile_name=self.profile_name)
            else:
                base_session = boto3.Session()
            
            if self.role_name:
                # Assume role for cross-account access
                sts_client = base_session.client('sts')
                role_arn = f"arn:aws:iam::{self.account_id}:role/{self.role_name}"
                
                logger.info(f"Assuming role: {role_arn}")
                response = sts_client.assume_role(
                    RoleArn=role_arn,
                    RoleSessionName=f"AFT-Cleanup-{self.account_id}"
                )
                
                credentials = response['Credentials']
                self.session = boto3.Session(
                    aws_access_key_id=credentials['AccessKeyId'],
                    aws_secret_access_key=credentials['SecretAccessKey'],
                    aws_session_token=credentials['SessionToken'],
                    region_name=self.region
                )
            else:
                # Use the base session with specified region
                self.session = boto3.Session(
                    profile_name=self.profile_name,
                    region_name=self.region
                )
            
            # Initialize all required clients
            services = [
                'iam', 's3', 'lambda', 'logs', 'cloudwatch', 'events', 'stepfunctions',
                'codebuild', 'codepipeline', 'codecommit', 'dynamodb', 'kms', 'ssm',
                'secretsmanager', 'sns', 'sqs', 'cloudformation', 'ec2', 'backup'
            ]
            
            self.clients = {}
            for service in services:
                try:
                    self.clients[service] = self.session.client(service)
                except Exception as e:
                    logger.warning(f"Could not initialize {service} client: {e}")
            
            logger.info(f"Successfully setup session for account: {self.account_id}")
            
        except NoCredentialsError:
            logger.error("No AWS credentials found. Please configure your credentials or specify a profile.")
            raise
        except ClientError as e:
            logger.error(f"Error setting up session: {e}")
            raise
    
    def _matches_aft_pattern(self, name: str) -> bool:
        """Check if a resource name matches the AFT pattern"""
        return bool(self.aft_pattern.match(name))
    
    def discover_iam_resources(self):
        """Discover all IAM resources with 'aft' in their names"""
        logger.info("Discovering IAM resources...")
        
        try:
            # IAM Roles
            paginator = self.clients['iam'].get_paginator('list_roles')
            for page in paginator.paginate():
                for role in page['Roles']:
                    if self._matches_aft_pattern(role['RoleName']):
                        self.resources_found['iam_roles'].append(role['RoleName'])
            
            # IAM Policies
            paginator = self.clients['iam'].get_paginator('list_policies')
            for page in paginator.paginate(Scope='Local'):
                for policy in page['Policies']:
                    if self._matches_aft_pattern(policy['PolicyName']):
                        self.resources_found['iam_policies'].append(policy['Arn'])
            
            # IAM Users
            paginator = self.clients['iam'].get_paginator('list_users')
            for page in paginator.paginate():
                for user in page['Users']:
                    if self._matches_aft_pattern(user['UserName']):
                        self.resources_found['iam_users'].append(user['UserName'])
            
            # IAM Groups
            paginator = self.clients['iam'].get_paginator('list_groups')
            for page in paginator.paginate():
                for group in page['Groups']:
                    if self._matches_aft_pattern(group['GroupName']):
                        self.resources_found['iam_groups'].append(group['GroupName'])
            
            # IAM Instance Profiles
            paginator = self.clients['iam'].get_paginator('list_instance_profiles')
            for page in paginator.paginate():
                for profile in page['InstanceProfiles']:
                    if self._matches_aft_pattern(profile['InstanceProfileName']):
                        self.resources_found['iam_instance_profiles'].append(profile['InstanceProfileName'])
            
        except ClientError as e:
            logger.error(f"Error discovering IAM resources: {e}")
    
    def discover_s3_resources(self):
        """Discover all S3 resources with 'aft' in their names"""
        logger.info("Discovering S3 resources...")
        
        try:
            response = self.clients['s3'].list_buckets()
            for bucket in response['Buckets']:
                if self._matches_aft_pattern(bucket['Name']):
                    # Check if bucket is in the correct region
                    try:
                        bucket_region = self.clients['s3'].head_bucket(Bucket=bucket['Name'])
                        self.resources_found['s3_buckets'].append(bucket['Name'])
                    except ClientError as e:
                        if e.response['Error']['Code'] not in ['404', 'NoSuchBucket']:
                            self.resources_found['s3_buckets'].append(bucket['Name'])
                            
        except ClientError as e:
            logger.error(f"Error discovering S3 resources: {e}")
    
    def discover_lambda_resources(self):
        """Discover all Lambda resources with 'aft' in their names"""
        logger.info("Discovering Lambda resources...")
        
        try:
            # Lambda Functions
            paginator = self.clients['lambda'].get_paginator('list_functions')
            for page in paginator.paginate():
                for function in page['Functions']:
                    if self._matches_aft_pattern(function['FunctionName']):
                        self.resources_found['lambda_functions'].append(function['FunctionName'])
            
            # Lambda Layers
            try:
                paginator = self.clients['lambda'].get_paginator('list_layers')
                for page in paginator.paginate():
                    for layer in page['Layers']:
                        if self._matches_aft_pattern(layer['LayerName']):
                            self.resources_found['lambda_layers'].append(layer['LayerArn'])
            except Exception as e:
                logger.debug(f"Could not list Lambda layers: {e}")
                
        except ClientError as e:
            logger.error(f"Error discovering Lambda resources: {e}")
    
    def discover_cloudwatch_resources(self):
        """Discover all CloudWatch resources with 'aft' in their names"""
        logger.info("Discovering CloudWatch resources...")
        
        try:
            # Log Groups
            paginator = self.clients['logs'].get_paginator('describe_log_groups')
            for page in paginator.paginate():
                for log_group in page['logGroups']:
                    if self._matches_aft_pattern(log_group['logGroupName']):
                        self.resources_found['cloudwatch_log_groups'].append(log_group['logGroupName'])
            
            # CloudWatch Alarms
            paginator = self.clients['cloudwatch'].get_paginator('describe_alarms')
            for page in paginator.paginate():
                for alarm in page['MetricAlarms']:
                    if self._matches_aft_pattern(alarm['AlarmName']):
                        self.resources_found['cloudwatch_alarms'].append(alarm['AlarmName'])
            
            # CloudWatch Dashboards
            try:
                paginator = self.clients['cloudwatch'].get_paginator('list_dashboards')
                for page in paginator.paginate():
                    for dashboard in page['DashboardEntries']:
                        if self._matches_aft_pattern(dashboard['DashboardName']):
                            self.resources_found['cloudwatch_dashboards'].append(dashboard['DashboardName'])
            except Exception as e:
                logger.debug(f"Could not list CloudWatch dashboards: {e}")
            
            # CloudWatch Insights Queries
            try:
                response = self.clients['logs'].describe_query_definitions()
                for query in response['queryDefinitions']:
                    if self._matches_aft_pattern(query['name']):
                        self.resources_found['cloudwatch_queries'].append(query['queryDefinitionId'])
            except Exception as e:
                logger.debug(f"Could not list CloudWatch queries: {e}")
                
        except ClientError as e:
            logger.error(f"Error discovering CloudWatch resources: {e}")
    
    def discover_eventbridge_resources(self):
        """Discover all EventBridge resources with 'aft' in their names"""
        logger.info("Discovering EventBridge resources...")
        
        try:
            # Event Buses
            response = self.clients['events'].list_event_buses()
            for bus in response['EventBuses']:
                if self._matches_aft_pattern(bus['Name']):
                    self.resources_found['eventbridge_buses'].append(bus['Name'])
            
            # Event Rules (check all event buses)
            for bus_name in [bus['Name'] for bus in response['EventBuses']]:
                try:
                    rules_response = self.clients['events'].list_rules(EventBusName=bus_name)
                    for rule in rules_response['Rules']:
                        if self._matches_aft_pattern(rule['Name']):
                            self.resources_found['eventbridge_rules'].append({
                                'name': rule['Name'],
                                'event_bus': bus_name
                            })
                except Exception as e:
                    logger.debug(f"Could not list rules for event bus {bus_name}: {e}")
                    
        except ClientError as e:
            logger.error(f"Error discovering EventBridge resources: {e}")
    
    def discover_step_functions(self):
        """Discover all Step Functions with 'aft' in their names"""
        logger.info("Discovering Step Functions...")
        
        try:
            paginator = self.clients['stepfunctions'].get_paginator('list_state_machines')
            for page in paginator.paginate():
                for sm in page['stateMachines']:
                    if self._matches_aft_pattern(sm['name']):
                        self.resources_found['step_functions'].append(sm['stateMachineArn'])
                        
        except ClientError as e:
            logger.error(f"Error discovering Step Functions: {e}")
    
    def discover_code_resources(self):
        """Discover all CodeBuild, CodePipeline, and CodeCommit resources with 'aft' in their names"""
        logger.info("Discovering Code resources...")
        
        try:
            # CodeBuild Projects
            paginator = self.clients['codebuild'].get_paginator('list_projects')
            for page in paginator.paginate():
                for project in page['projects']:
                    if self._matches_aft_pattern(project):
                        self.resources_found['codebuild_projects'].append(project)
            
            # CodePipeline Pipelines
            paginator = self.clients['codepipeline'].get_paginator('list_pipelines')
            for page in paginator.paginate():
                for pipeline in page['pipelines']:
                    if self._matches_aft_pattern(pipeline['name']):
                        self.resources_found['codepipeline_pipelines'].append(pipeline['name'])
            
            # CodeCommit Repositories
            try:
                paginator = self.clients['codecommit'].get_paginator('list_repositories')
                for page in paginator.paginate():
                    for repo in page['repositories']:
                        if self._matches_aft_pattern(repo['repositoryName']):
                            self.resources_found['codecommit_repos'].append(repo['repositoryName'])
            except Exception as e:
                logger.debug(f"Could not list CodeCommit repositories: {e}")
                
        except ClientError as e:
            logger.error(f"Error discovering Code resources: {e}")
    
    def discover_database_resources(self):
        """Discover all DynamoDB resources with 'aft' in their names"""
        logger.info("Discovering Database resources...")
        
        try:
            # DynamoDB Tables
            paginator = self.clients['dynamodb'].get_paginator('list_tables')
            for page in paginator.paginate():
                for table in page['TableNames']:
                    if self._matches_aft_pattern(table):
                        self.resources_found['dynamodb_tables'].append(table)
                        
        except ClientError as e:
            logger.error(f"Error discovering Database resources: {e}")
    
    def discover_kms_resources(self):
        """Discover all KMS resources with 'aft' in their names"""
        logger.info("Discovering KMS resources...")
        
        try:
            # KMS Keys
            paginator = self.clients['kms'].get_paginator('list_keys')
            for page in paginator.paginate():
                for key in page['Keys']:
                    try:
                        key_details = self.clients['kms'].describe_key(KeyId=key['KeyId'])
                        if key_details['KeyMetadata'].get('Description') and \
                           self._matches_aft_pattern(key_details['KeyMetadata']['Description']):
                            self.resources_found['kms_keys'].append(key['KeyId'])
                    except Exception as e:
                        logger.debug(f"Could not describe KMS key {key['KeyId']}: {e}")
            
            # KMS Aliases
            paginator = self.clients['kms'].get_paginator('list_aliases')
            for page in paginator.paginate():
                for alias in page['Aliases']:
                    if alias.get('AliasName') and self._matches_aft_pattern(alias['AliasName']):
                        self.resources_found['kms_aliases'].append(alias['AliasName'])
                        
        except ClientError as e:
            logger.error(f"Error discovering KMS resources: {e}")
    
    def discover_parameter_store_resources(self):
        """Discover all SSM Parameter Store resources with 'aft' in their names"""
        logger.info("Discovering Parameter Store resources...")
        
        try:
            paginator = self.clients['ssm'].get_paginator('describe_parameters')
            for page in paginator.paginate():
                for param in page['Parameters']:
                    if self._matches_aft_pattern(param['Name']):
                        self.resources_found['ssm_parameters'].append(param['Name'])
                        
        except ClientError as e:
            logger.error(f"Error discovering Parameter Store resources: {e}")
    
    def discover_secrets_manager_resources(self):
        """Discover all Secrets Manager resources with 'aft' in their names"""
        logger.info("Discovering Secrets Manager resources...")
        
        try:
            paginator = self.clients['secretsmanager'].get_paginator('list_secrets')
            for page in paginator.paginate():
                for secret in page['SecretList']:
                    if self._matches_aft_pattern(secret['Name']):
                        self.resources_found['secrets_manager'].append(secret['ARN'])
                        
        except ClientError as e:
            logger.error(f"Error discovering Secrets Manager resources: {e}")
    
    def discover_messaging_resources(self):
        """Discover all SNS and SQS resources with 'aft' in their names"""
        logger.info("Discovering Messaging resources...")
        
        try:
            # SNS Topics
            paginator = self.clients['sns'].get_paginator('list_topics')
            for page in paginator.paginate():
                for topic in page['Topics']:
                    topic_name = topic['TopicArn'].split(':')[-1]
                    if self._matches_aft_pattern(topic_name):
                        self.resources_found['sns_topics'].append(topic['TopicArn'])
            
            # SQS Queues
            response = self.clients['sqs'].list_queues()
            for queue_url in response.get('QueueUrls', []):
                queue_name = queue_url.split('/')[-1]
                if self._matches_aft_pattern(queue_name):
                    self.resources_found['sqs_queues'].append(queue_url)
                    
        except ClientError as e:
            logger.error(f"Error discovering Messaging resources: {e}")
    
    def discover_cloudformation_resources(self):
        """Discover all CloudFormation resources with 'aft' in their names"""
        logger.info("Discovering CloudFormation resources...")
        
        try:
            paginator = self.clients['cloudformation'].get_paginator('list_stacks')
            for page in paginator.paginate():
                for stack in page['StackSummaries']:
                    if stack['StackStatus'] != 'DELETE_COMPLETE' and \
                       self._matches_aft_pattern(stack['StackName']):
                        self.resources_found['cloudformation_stacks'].append(stack['StackName'])
                        
        except ClientError as e:
            logger.error(f"Error discovering CloudFormation resources: {e}")
    
    def discover_backup_resources(self):
        """Discover all AWS Backup resources with 'aft' in their names"""
        logger.info("Discovering AWS Backup resources...")
        
        try:
            # Backup Vaults
            try:
                paginator = self.clients['backup'].get_paginator('list_backup_vaults')
                for page in paginator.paginate():
                    for vault in page['BackupVaultList']:
                        if self._matches_aft_pattern(vault['BackupVaultName']):
                            self.resources_found['backup_vaults'].append(vault['BackupVaultName'])
            except Exception as e:
                logger.debug(f"Could not list backup vaults: {e}")
            
            # Backup Plans
            try:
                paginator = self.clients['backup'].get_paginator('list_backup_plans')
                for page in paginator.paginate():
                    for plan in page['BackupPlansList']:
                        if self._matches_aft_pattern(plan['BackupPlanName']):
                            self.resources_found['backup_plans'].append(plan['BackupPlanId'])
            except Exception as e:
                logger.debug(f"Could not list backup plans: {e}")
                
        except ClientError as e:
            logger.error(f"Error discovering Backup resources: {e}")
    
    def discover_all_resources(self):
        """Discover all AFT-related resources across all AWS services"""
        logger.info("Starting comprehensive resource discovery...")
        
        discovery_functions = [
            self.discover_iam_resources,
            self.discover_s3_resources,
            self.discover_lambda_resources,
            self.discover_cloudwatch_resources,
            self.discover_eventbridge_resources,
            self.discover_step_functions,
            self.discover_code_resources,
            self.discover_database_resources,
            self.discover_kms_resources,
            self.discover_parameter_store_resources,
            self.discover_secrets_manager_resources,
            self.discover_messaging_resources,
            self.discover_cloudformation_resources,
            self.discover_backup_resources
        ]
        
        # Run discovery functions in parallel for faster execution
        with ThreadPoolExecutor(max_workers=5) as executor:
            futures = [executor.submit(func) for func in discovery_functions]
            for future in as_completed(futures):
                try:
                    future.result()
                except Exception as e:
                    logger.error(f"Error in discovery function: {e}")
        
        # Log summary of discovered resources
        total_resources = sum(len(resources) for resources in self.resources_found.values())
        logger.info(f"Discovery complete. Found {total_resources} AFT-related resources:")
        
        for resource_type, resources in self.resources_found.items():
            if resources:
                logger.info(f"  {resource_type}: {len(resources)} items")
    
    def cleanup_discovered_resources(self):
        """Clean up all discovered AFT-related resources"""
        logger.info("Starting cleanup of discovered resources...")
        
        # Order matters - clean up in dependency order
        cleanup_order = [
            ('cloudformation_stacks', self._cleanup_cloudformation_stacks),
            ('codepipeline_pipelines', self._cleanup_codepipeline_pipelines),
            ('codebuild_projects', self._cleanup_codebuild_projects),
            ('step_functions', self._cleanup_step_functions),
            ('lambda_functions', self._cleanup_lambda_functions),
            ('eventbridge_rules', self._cleanup_eventbridge_rules),
            ('eventbridge_buses', self._cleanup_eventbridge_buses),
            ('cloudwatch_alarms', self._cleanup_cloudwatch_alarms),
            ('cloudwatch_dashboards', self._cleanup_cloudwatch_dashboards),
            ('cloudwatch_log_groups', self._cleanup_cloudwatch_log_groups),
            ('cloudwatch_queries', self._cleanup_cloudwatch_queries),
            ('backup_vaults', self._cleanup_backup_vaults),
            ('backup_plans', self._cleanup_backup_plans),
            ('secrets_manager', self._cleanup_secrets_manager),
            ('sns_topics', self._cleanup_sns_topics),
            ('sqs_queues', self._cleanup_sqs_queues),
            ('dynamodb_tables', self._cleanup_dynamodb_tables),
            ('codecommit_repos', self._cleanup_codecommit_repos),
            ('lambda_layers', self._cleanup_lambda_layers),
            ('ssm_parameters', self._cleanup_ssm_parameters),
            ('kms_aliases', self._cleanup_kms_aliases),
            ('s3_buckets', self._cleanup_s3_buckets),
            ('iam_instance_profiles', self._cleanup_iam_instance_profiles),
            ('iam_roles', self._cleanup_iam_roles),
            ('iam_policies', self._cleanup_iam_policies),
            ('iam_users', self._cleanup_iam_users),
            ('iam_groups', self._cleanup_iam_groups),
            ('kms_keys', self._cleanup_kms_keys)
        ]
        
        for resource_type, cleanup_func in cleanup_order:
            if self.resources_found[resource_type]:
                logger.info(f"Cleaning up {resource_type}...")
                try:
                    cleanup_func()
                except Exception as e:
                    logger.error(f"Error cleaning up {resource_type}: {e}")
    
    def _cleanup_iam_roles(self):
        """Clean up discovered IAM roles"""
        for role_name in self.resources_found['iam_roles']:
            try:
                # Detach managed policies
                try:
                    attached_policies = self.clients['iam'].list_attached_role_policies(RoleName=role_name)
                    for policy in attached_policies.get('AttachedPolicies', []):
                        self.clients['iam'].detach_role_policy(
                            RoleName=role_name,
                            PolicyArn=policy['PolicyArn']
                        )
                except ClientError:
                    pass
                
                # Delete inline policies
                try:
                    inline_policies = self.clients['iam'].list_role_policies(RoleName=role_name)
                    for policy_name in inline_policies.get('PolicyNames', []):
                        self.clients['iam'].delete_role_policy(
                            RoleName=role_name,
                            PolicyName=policy_name
                        )
                except ClientError:
                    pass
                
                # Remove from instance profiles
                try:
                    instance_profiles = self.clients['iam'].list_instance_profiles_for_role(RoleName=role_name)
                    for profile in instance_profiles.get('InstanceProfiles', []):
                        self.clients['iam'].remove_role_from_instance_profile(
                            InstanceProfileName=profile['InstanceProfileName'],
                            RoleName=role_name
                        )
                except ClientError:
                    pass
                
                # Delete the role
                self.clients['iam'].delete_role(RoleName=role_name)
                logger.info(f"Deleted IAM role: {role_name}")
                
            except ClientError as e:
                if e.response['Error']['Code'] != 'NoSuchEntity':
                    logger.error(f"Error deleting IAM role {role_name}: {e}")
    
    def _cleanup_iam_policies(self):
        """Clean up discovered IAM policies"""
        for policy_arn in self.resources_found['iam_policies']:
            try:
                # Detach from all entities
                policy_entities = self.clients['iam'].list_entities_for_policy(PolicyArn=policy_arn)
                
                # Detach from users
                for user in policy_entities.get('PolicyUsers', []):
                    self.clients['iam'].detach_user_policy(
                        UserName=user['UserName'],
                        PolicyArn=policy_arn
                    )
                
                # Detach from groups
                for group in policy_entities.get('PolicyGroups', []):
                    self.clients['iam'].detach_group_policy(
                        GroupName=group['GroupName'],
                        PolicyArn=policy_arn
                    )
                
                # Detach from roles
                for role in policy_entities.get('PolicyRoles', []):
                    self.clients['iam'].detach_role_policy(
                        RoleName=role['RoleName'],
                        PolicyArn=policy_arn
                    )
                
                # Delete policy versions except default
                policy_versions = self.clients['iam'].list_policy_versions(PolicyArn=policy_arn)
                for version in policy_versions['Versions']:
                    if not version['IsDefaultVersion']:
                        self.clients['iam'].delete_policy_version(
                            PolicyArn=policy_arn,
                            VersionId=version['VersionId']
                        )
                
                # Delete the policy
                self.clients['iam'].delete_policy(PolicyArn=policy_arn)
                logger.info(f"Deleted IAM policy: {policy_arn}")
                
            except ClientError as e:
                if e.response['Error']['Code'] != 'NoSuchEntity':
                    logger.error(f"Error deleting IAM policy {policy_arn}: {e}")
    
    def _cleanup_iam_users(self):
        """Clean up discovered IAM users"""
        for user_name in self.resources_found['iam_users']:
            try:
                # Remove from groups
                groups = self.clients['iam'].get_groups_for_user(UserName=user_name)
                for group in groups['Groups']:
                    self.clients['iam'].remove_user_from_group(
                        GroupName=group['GroupName'],
                        UserName=user_name
                    )
                
                # Detach managed policies
                attached_policies = self.clients['iam'].list_attached_user_policies(UserName=user_name)
                for policy in attached_policies.get('AttachedPolicies', []):
                    self.clients['iam'].detach_user_policy(
                        UserName=user_name,
                        PolicyArn=policy['PolicyArn']
                    )
                
                # Delete inline policies
                inline_policies = self.clients['iam'].list_user_policies(UserName=user_name)
                for policy_name in inline_policies.get('PolicyNames', []):
                    self.clients['iam'].delete_user_policy(
                        UserName=user_name,
                        PolicyName=policy_name
                    )
                
                # Delete access keys
                access_keys = self.clients['iam'].list_access_keys(UserName=user_name)
                for key in access_keys['AccessKeyMetadata']:
                    self.clients['iam'].delete_access_key(
                        UserName=user_name,
                        AccessKeyId=key['AccessKeyId']
                    )
                
                # Delete the user
                self.clients['iam'].delete_user(UserName=user_name)
                logger.info(f"Deleted IAM user: {user_name}")
                
            except ClientError as e:
                if e.response['Error']['Code'] != 'NoSuchEntity':
                    logger.error(f"Error deleting IAM user {user_name}: {e}")
    
    def _cleanup_iam_groups(self):
        """Clean up discovered IAM groups"""
        for group_name in self.resources_found['iam_groups']:
            try:
                # Remove all users from group
                users = self.clients['iam'].get_group(GroupName=group_name)
                for user in users['Users']:
                    self.clients['iam'].remove_user_from_group(
                        GroupName=group_name,
                        UserName=user['UserName']
                    )
                
                # Detach managed policies
                attached_policies = self.clients['iam'].list_attached_group_policies(GroupName=group_name)
                for policy in attached_policies.get('AttachedPolicies', []):
                    self.clients['iam'].detach_group_policy(
                        GroupName=group_name,
                        PolicyArn=policy['PolicyArn']
                    )
                
                # Delete inline policies
                inline_policies = self.clients['iam'].list_group_policies(GroupName=group_name)
                for policy_name in inline_policies.get('PolicyNames', []):
                    self.clients['iam'].delete_group_policy(
                        GroupName=group_name,
                        PolicyName=policy_name
                    )
                
                # Delete the group
                self.clients['iam'].delete_group(GroupName=group_name)
                logger.info(f"Deleted IAM group: {group_name}")
                
            except ClientError as e:
                if e.response['Error']['Code'] != 'NoSuchEntity':
                    logger.error(f"Error deleting IAM group {group_name}: {e}")
    
    def _cleanup_iam_instance_profiles(self):
        """Clean up discovered IAM instance profiles"""
        for profile_name in self.resources_found['iam_instance_profiles']:
            try:
                # Get instance profile details
                profile = self.clients['iam'].get_instance_profile(InstanceProfileName=profile_name)
                
                # Remove all roles from instance profile
                for role in profile['InstanceProfile']['Roles']:
                    self.clients['iam'].remove_role_from_instance_profile(
                        InstanceProfileName=profile_name,
                        RoleName=role['RoleName']
                    )
                
                # Delete the instance profile
                self.clients['iam'].delete_instance_profile(InstanceProfileName=profile_name)
                logger.info(f"Deleted IAM instance profile: {profile_name}")
                
            except ClientError as e:
                if e.response['Error']['Code'] != 'NoSuchEntity':
                    logger.error(f"Error deleting IAM instance profile {profile_name}: {e}")
    
    def _cleanup_s3_buckets(self):
        """Clean up discovered S3 buckets"""
        for bucket_name in self.resources_found['s3_buckets']:
            try:
                # Empty the bucket first
                logger.info(f"Emptying S3 bucket: {bucket_name}")
                paginator = self.clients['s3'].get_paginator('list_object_versions')
                
                for page in paginator.paginate(Bucket=bucket_name):
                    objects_to_delete = []
                    
                    # Add object versions
                    for version in page.get('Versions', []):
                        objects_to_delete.append({
                            'Key': version['Key'],
                            'VersionId': version['VersionId']
                        })
                    
                    # Add delete markers
                    for marker in page.get('DeleteMarkers', []):
                        objects_to_delete.append({
                            'Key': marker['Key'],
                            'VersionId': marker['VersionId']
                        })
                    
                    # Delete objects in batches
                    if objects_to_delete:
                        for i in range(0, len(objects_to_delete), 1000):
                            batch = objects_to_delete[i:i+1000]
                            self.clients['s3'].delete_objects(
                                Bucket=bucket_name,
                                Delete={'Objects': batch}
                            )
                
                # Delete the bucket
                self.clients['s3'].delete_bucket(Bucket=bucket_name)
                logger.info(f"Deleted S3 bucket: {bucket_name}")
                
            except ClientError as e:
                if e.response['Error']['Code'] not in ['NoSuchBucket', '404']:
                    logger.error(f"Error deleting S3 bucket {bucket_name}: {e}")
    
    def _cleanup_lambda_functions(self):
        """Clean up discovered Lambda functions"""
        for function_name in self.resources_found['lambda_functions']:
            try:
                self.clients['lambda'].delete_function(FunctionName=function_name)
                logger.info(f"Deleted Lambda function: {function_name}")
            except ClientError as e:
                if e.response['Error']['Code'] != 'ResourceNotFoundException':
                    logger.error(f"Error deleting Lambda function {function_name}: {e}")
    
    def _cleanup_lambda_layers(self):
        """Clean up discovered Lambda layers"""
        for layer_arn in self.resources_found['lambda_layers']:
            try:
                # Get all versions of the layer
                layer_name = layer_arn.split(':')[-1]
                response = self.clients['lambda'].list_layer_versions(LayerName=layer_name)
                
                # Delete all versions
                for version in response['LayerVersions']:
                    self.clients['lambda'].delete_layer_version(
                        LayerName=layer_name,
                        VersionNumber=version['Version']
                    )
                
                logger.info(f"Deleted Lambda layer: {layer_name}")
            except ClientError as e:
                if e.response['Error']['Code'] != 'ResourceNotFoundException':
                    logger.error(f"Error deleting Lambda layer {layer_arn}: {e}")
    
    def _cleanup_cloudwatch_log_groups(self):
        """Clean up discovered CloudWatch log groups"""
        for log_group_name in self.resources_found['cloudwatch_log_groups']:
            try:
                self.clients['logs'].delete_log_group(logGroupName=log_group_name)
                logger.info(f"Deleted CloudWatch log group: {log_group_name}")
            except ClientError as e:
                if e.response['Error']['Code'] != 'ResourceNotFoundException':
                    logger.error(f"Error deleting CloudWatch log group {log_group_name}: {e}")
    
    def _cleanup_cloudwatch_alarms(self):
        """Clean up discovered CloudWatch alarms"""
        if self.resources_found['cloudwatch_alarms']:
            try:
                self.clients['cloudwatch'].delete_alarms(
                    AlarmNames=self.resources_found['cloudwatch_alarms']
                )
                logger.info(f"Deleted CloudWatch alarms: {self.resources_found['cloudwatch_alarms']}")
            except ClientError as e:
                logger.error(f"Error deleting CloudWatch alarms: {e}")
    
    def _cleanup_cloudwatch_dashboards(self):
        """Clean up discovered CloudWatch dashboards"""
        for dashboard_name in self.resources_found['cloudwatch_dashboards']:
            try:
                self.clients['cloudwatch'].delete_dashboards(
                    DashboardNames=[dashboard_name]
                )
                logger.info(f"Deleted CloudWatch dashboard: {dashboard_name}")
            except ClientError as e:
                if e.response['Error']['Code'] != 'ResourceNotFound':
                    logger.error(f"Error deleting CloudWatch dashboard {dashboard_name}: {e}")
    
    def _cleanup_cloudwatch_queries(self):
        """Clean up discovered CloudWatch queries"""
        for query_id in self.resources_found['cloudwatch_queries']:
            try:
                self.clients['logs'].delete_query_definition(queryDefinitionId=query_id)
                logger.info(f"Deleted CloudWatch query: {query_id}")
            except ClientError as e:
                if e.response['Error']['Code'] != 'ResourceNotFoundException':
                    logger.error(f"Error deleting CloudWatch query {query_id}: {e}")
    
    def _cleanup_eventbridge_rules(self):
        """Clean up discovered EventBridge rules"""
        for rule_info in self.resources_found['eventbridge_rules']:
            try:
                rule_name = rule_info['name']
                event_bus = rule_info['event_bus']
                
                # Remove targets first
                targets = self.clients['events'].list_targets_by_rule(
                    Rule=rule_name,
                    EventBusName=event_bus
                )
                
                if targets.get('Targets'):
                    target_ids = [target['Id'] for target in targets['Targets']]
                    self.clients['events'].remove_targets(
                        Rule=rule_name,
                        EventBusName=event_bus,
                        Ids=target_ids
                    )
                
                # Delete the rule
                self.clients['events'].delete_rule(
                    Name=rule_name,
                    EventBusName=event_bus
                )
                logger.info(f"Deleted EventBridge rule: {rule_name}")
                
            except ClientError as e:
                if e.response['Error']['Code'] != 'ResourceNotFoundException':
                    logger.error(f"Error deleting EventBridge rule {rule_info}: {e}")
    
    def _cleanup_eventbridge_buses(self):
        """Clean up discovered EventBridge event buses"""
        for bus_name in self.resources_found['eventbridge_buses']:
            if bus_name != 'default':  # Don't delete the default event bus
                try:
                    self.clients['events'].delete_event_bus(Name=bus_name)
                    logger.info(f"Deleted EventBridge event bus: {bus_name}")
                except ClientError as e:
                    if e.response['Error']['Code'] != 'ResourceNotFoundException':
                        logger.error(f"Error deleting EventBridge event bus {bus_name}: {e}")
    
    def _cleanup_step_functions(self):
        """Clean up discovered Step Functions"""
        for sm_arn in self.resources_found['step_functions']:
            try:
                # Stop running executions
                executions = self.clients['stepfunctions'].list_executions(
                    stateMachineArn=sm_arn,
                    statusFilter='RUNNING'
                )
                
                for execution in executions.get('executions', []):
                    self.clients['stepfunctions'].stop_execution(
                        executionArn=execution['executionArn']
                    )
                
                # Wait a bit for executions to stop
                if executions.get('executions'):
                    time.sleep(5)
                
                # Delete the state machine
                self.clients['stepfunctions'].delete_state_machine(stateMachineArn=sm_arn)
                logger.info(f"Deleted Step Function: {sm_arn}")
                
            except ClientError as e:
                if e.response['Error']['Code'] != 'StateMachineDoesNotExist':
                    logger.error(f"Error deleting Step Function {sm_arn}: {e}")
    
    def _cleanup_codebuild_projects(self):
        """Clean up discovered CodeBuild projects"""
        for project_name in self.resources_found['codebuild_projects']:
            try:
                self.clients['codebuild'].delete_project(name=project_name)
                logger.info(f"Deleted CodeBuild project: {project_name}")
            except ClientError as e:
                if e.response['Error']['Code'] != 'ResourceNotFoundException':
                    logger.error(f"Error deleting CodeBuild project {project_name}: {e}")
    
    def _cleanup_codepipeline_pipelines(self):
        """Clean up discovered CodePipeline pipelines"""
        for pipeline_name in self.resources_found['codepipeline_pipelines']:
            try:
                self.clients['codepipeline'].delete_pipeline(name=pipeline_name)
                logger.info(f"Deleted CodePipeline pipeline: {pipeline_name}")
            except ClientError as e:
                if e.response['Error']['Code'] != 'PipelineNotFoundException':
                    logger.error(f"Error deleting CodePipeline pipeline {pipeline_name}: {e}")
    
    def _cleanup_codecommit_repos(self):
        """Clean up discovered CodeCommit repositories"""
        for repo_name in self.resources_found['codecommit_repos']:
            try:
                self.clients['codecommit'].delete_repository(repositoryName=repo_name)
                logger.info(f"Deleted CodeCommit repository: {repo_name}")
            except ClientError as e:
                if e.response['Error']['Code'] != 'RepositoryDoesNotExistException':
                    logger.error(f"Error deleting CodeCommit repository {repo_name}: {e}")
    
    def _cleanup_dynamodb_tables(self):
        """Clean up discovered DynamoDB tables"""
        for table_name in self.resources_found['dynamodb_tables']:
            try:
                self.clients['dynamodb'].delete_table(TableName=table_name)
                logger.info(f"Deleted DynamoDB table: {table_name}")
                
                # Wait for table to be deleted
                waiter = self.clients['dynamodb'].get_waiter('table_not_exists')
                waiter.wait(TableName=table_name, WaiterConfig={'Delay': 10, 'MaxAttempts': 30})
                
            except ClientError as e:
                if e.response['Error']['Code'] != 'ResourceNotFoundException':
                    logger.error(f"Error deleting DynamoDB table {table_name}: {e}")
    
    def _cleanup_kms_aliases(self):
        """Clean up discovered KMS aliases"""
        for alias_name in self.resources_found['kms_aliases']:
            try:
                self.clients['kms'].delete_alias(AliasName=alias_name)
                logger.info(f"Deleted KMS alias: {alias_name}")
            except ClientError as e:
                if e.response['Error']['Code'] != 'NotFoundException':
                    logger.error(f"Error deleting KMS alias {alias_name}: {e}")
    
    def _cleanup_kms_keys(self):
        """Clean up discovered KMS keys"""
        for key_id in self.resources_found['kms_keys']:
            try:
                # Schedule key for deletion
                self.clients['kms'].schedule_key_deletion(
                    KeyId=key_id,
                    PendingWindowInDays=7  # Minimum deletion window
                )
                logger.info(f"Scheduled KMS key for deletion: {key_id}")
            except ClientError as e:
                if e.response['Error']['Code'] not in ['NotFoundException', 'KMSInvalidStateException']:
                    logger.error(f"Error scheduling KMS key deletion {key_id}: {e}")
    
    def _cleanup_ssm_parameters(self):
        """Clean up discovered SSM parameters"""
        for param_name in self.resources_found['ssm_parameters']:
            try:
                self.clients['ssm'].delete_parameter(Name=param_name)
                logger.info(f"Deleted SSM parameter: {param_name}")
            except ClientError as e:
                if e.response['Error']['Code'] != 'ParameterNotFound':
                    logger.error(f"Error deleting SSM parameter {param_name}: {e}")
    
    def _cleanup_secrets_manager(self):
        """Clean up discovered Secrets Manager secrets"""
        for secret_arn in self.resources_found['secrets_manager']:
            try:
                self.clients['secretsmanager'].delete_secret(
                    SecretId=secret_arn,
                    ForceDeleteWithoutRecovery=True
                )
                logger.info(f"Deleted Secrets Manager secret: {secret_arn}")
            except ClientError as e:
                if e.response['Error']['Code'] != 'ResourceNotFoundException':
                    logger.error(f"Error deleting Secrets Manager secret {secret_arn}: {e}")
    
    def _cleanup_sns_topics(self):
        """Clean up discovered SNS topics"""
        for topic_arn in self.resources_found['sns_topics']:
            try:
                self.clients['sns'].delete_topic(TopicArn=topic_arn)
                logger.info(f"Deleted SNS topic: {topic_arn}")
            except ClientError as e:
                if e.response['Error']['Code'] != 'NotFound':
                    logger.error(f"Error deleting SNS topic {topic_arn}: {e}")
    
    def _cleanup_sqs_queues(self):
        """Clean up discovered SQS queues"""
        for queue_url in self.resources_found['sqs_queues']:
            try:
                self.clients['sqs'].delete_queue(QueueUrl=queue_url)
                logger.info(f"Deleted SQS queue: {queue_url}")
            except ClientError as e:
                if e.response['Error']['Code'] != 'AWS.SimpleQueueService.NonExistentQueue':
                    logger.error(f"Error deleting SQS queue {queue_url}: {e}")
    
    def _cleanup_cloudformation_stacks(self):
        """Clean up discovered CloudFormation stacks"""
        for stack_name in self.resources_found['cloudformation_stacks']:
            try:
                self.clients['cloudformation'].delete_stack(StackName=stack_name)
                logger.info(f"Deleted CloudFormation stack: {stack_name}")
                
                # Wait for stack deletion to complete
                waiter = self.clients['cloudformation'].get_waiter('stack_delete_complete')
                waiter.wait(StackName=stack_name, WaiterConfig={'Delay': 30, 'MaxAttempts': 120})
                
            except ClientError as e:
                if e.response['Error']['Code'] not in ['ValidationError', 'ResourceNotFound']:
                    logger.error(f"Error deleting CloudFormation stack {stack_name}: {e}")
    
    def _cleanup_backup_vaults(self):
        """Clean up discovered AWS Backup vaults"""
        for vault_name in self.resources_found['backup_vaults']:
            try:
                # First, delete all recovery points in the vault
                try:
                    recovery_points = self.clients['backup'].list_recovery_points_by_backup_vault(
                        BackupVaultName=vault_name
                    )
                    
                    for rp in recovery_points.get('RecoveryPoints', []):
                        try:
                            self.clients['backup'].delete_recovery_point(
                                BackupVaultName=vault_name,
                                RecoveryPointArn=rp['RecoveryPointArn']
                            )
                        except ClientError:
                            pass  # Continue even if some recovery points can't be deleted
                except ClientError:
                    pass
                
                # Delete the backup vault
                self.clients['backup'].delete_backup_vault(BackupVaultName=vault_name)
                logger.info(f"Deleted AWS Backup vault: {vault_name}")
                
            except ClientError as e:
                if e.response['Error']['Code'] != 'ResourceNotFoundException':
                    logger.error(f"Error deleting AWS Backup vault {vault_name}: {e}")
    
    def _cleanup_backup_plans(self):
        """Clean up discovered AWS Backup plans"""
        for plan_id in self.resources_found['backup_plans']:
            try:
                self.clients['backup'].delete_backup_plan(BackupPlanId=plan_id)
                logger.info(f"Deleted AWS Backup plan: {plan_id}")
            except ClientError as e:
                if e.response['Error']['Code'] != 'ResourceNotFoundException':
                    logger.error(f"Error deleting AWS Backup plan {plan_id}: {e}")
    
    def run_comprehensive_cleanup(self):
        """Run the complete comprehensive cleanup process"""
        logger.info(f"Starting comprehensive AFT resource cleanup for account: {self.account_id}")
        
        try:
            self._setup_session()
            
            # Phase 1: Discovery
            self.discover_all_resources()
            
            # Phase 2: Cleanup
            self.cleanup_discovered_resources()
            
            logger.info(f"Completed comprehensive AFT resource cleanup for account: {self.account_id}")
            
        except Exception as e:
            logger.error(f"Error during comprehensive cleanup for account {self.account_id}: {e}")
            raise

def load_config_from_file(config_file: str) -> List[Dict]:
    """Load account configuration from JSON file"""
    try:
        with open(config_file, 'r') as f:
            config = json.load(f)
        return config.get('accounts', [])
    except FileNotFoundError:
        logger.error(f"Configuration file not found: {config_file}")
        sys.exit(1)
    except json.JSONDecodeError as e:
        logger.error(f"Invalid JSON in configuration file: {e}")
        sys.exit(1)

def main():
    """Main function to orchestrate comprehensive cleanup across multiple accounts"""
    
    parser = argparse.ArgumentParser(description='Comprehensive AFT Resource Cleanup Script')
    parser.add_argument('--config', '-c', help='JSON configuration file path')
    parser.add_argument('--profile', '-p', help='AWS profile name to use')
    parser.add_argument('--account-id', help='Single account ID to clean (alternative to config file)')
    parser.add_argument('--region', default='us-east-1', help='AWS region (default: us-east-1)')
    parser.add_argument('--role-name', help='IAM role name to assume for cross-account access')
    parser.add_argument('--dry-run', action='store_true', help='Show what would be deleted without actually deleting')
    
    args = parser.parse_args()
    
    # Load configuration
    if args.config:
        accounts_config = load_config_from_file(args.config)
    elif args.account_id:
        accounts_config = [{
            "account_id": args.account_id,
            "region": args.region,
            "role_name": args.role_name,
            "profile_name": args.profile
        }]
    else:
        # Default configuration - update these values for your environment
        accounts_config = [
            {
                "account_id": "549118124188",  # From the S3 bucket name in the log
                "region": "us-east-1",
                "role_name": "OrganizationAccountAccessRole",  # Role to assume, or None for current credentials
                "profile_name": args.profile  # Use profile from command line
            }
            # Add more accounts as needed
        ]
    
    if args.dry_run:
        logger.info("DRY RUN MODE: Discovery only - no resources will be deleted")
        # In dry run mode, we'll only run discovery
        for config in accounts_config:
            try:
                cleaner = ComprehensiveAFTCleaner(
                    account_id=config["account_id"],
                    region=config.get("region", args.region),
                    role_name=config.get("role_name", args.role_name),
                    profile_name=config.get("profile_name", args.profile)
                )
                
                cleaner._setup_session()
                cleaner.discover_all_resources()
                
                # Print what would be deleted
                logger.info(f"=== DRY RUN RESULTS for Account {config['account_id']} ===")
                total = 0
                for resource_type, resources in cleaner.resources_found.items():
                    if resources:
                        logger.info(f"Would delete {len(resources)} {resource_type}:")
                        for resource in resources[:5]:  # Show first 5 items
                            logger.info(f"  - {resource}")
                        if len(resources) > 5:
                            logger.info(f"  ... and {len(resources) - 5} more")
                        total += len(resources)
                logger.info(f"Total resources that would be deleted: {total}")
                
            except Exception as e:
                logger.error(f"Error in dry run for account {config['account_id']}: {e}")
        
        return
    
    logger.info("Starting Comprehensive AFT Resource Cleanup Script")
    logger.info(f"Using AWS profile: {args.profile or 'default'}")
    
    failed_accounts = []
    
    for config in accounts_config:
        try:
            cleaner = ComprehensiveAFTCleaner(
                account_id=config["account_id"],
                region=config.get("region", args.region),
                role_name=config.get("role_name", args.role_name),
                profile_name=config.get("profile_name", args.profile)
            )
            
            cleaner.run_comprehensive_cleanup()
            
        except Exception as e:
            logger.error(f"Failed to cleanup account {config['account_id']}: {e}")
            failed_accounts.append(config["account_id"])
    
    # Summary
    logger.info("="*60)
    logger.info("COMPREHENSIVE CLEANUP SUMMARY")
    logger.info("="*60)
    
    successful_accounts = [config["account_id"] for config in accounts_config 
                          if config["account_id"] not in failed_accounts]
    
    if successful_accounts:
        logger.info(f"Successfully cleaned up accounts: {', '.join(successful_accounts)}")
    
    if failed_accounts:
        logger.error(f"Failed to clean up accounts: {', '.join(failed_accounts)}")
        sys.exit(1)
    else:
        logger.info("All accounts cleaned up successfully!")

if __name__ == "__main__":
    main()