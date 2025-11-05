#!/usr/bin/env python3
"""
S3 Bucket Replication Status Checker

This script checks the replication status of S3 buckets including:
- Replication configuration
- Replication metrics
- Failed replication objects
- Cross-Region Replication (CRR) and Same-Region Replication (SRR) status
"""

import boto3
import json
import os
import configparser
from datetime import datetime, timedelta, UTC
from botocore.exceptions import ClientError, NoCredentialsError
import argparse
import sys

class S3ReplicationChecker:
    def __init__(self, region_name='us-east-1', profile_name=None):
        """Initialize S3 client"""
        try:
            # Create session with optional profile
            if profile_name:
                session = boto3.Session(profile_name=profile_name)
                print(f"Using AWS profile: {profile_name}")
            else:
                session = boto3.Session()
                print("Using default AWS profile")
            
            self.s3_client = session.client('s3', region_name=region_name)
            self.cloudwatch = session.client('cloudwatch', region_name=region_name)
            
        except NoCredentialsError:
            print("Error: AWS credentials not found. Please configure your credentials.")
            sys.exit(1)
        except Exception as e:
            if "could not be found" in str(e).lower():
                print(f"Error: AWS profile '{profile_name}' not found.")
                print("Available profiles can be listed with: aws configure list-profiles")
            else:
                print(f"Error initializing AWS session: {e}")
            sys.exit(1)
    
    def get_bucket_replication_config(self, bucket_name):
        """Get replication configuration for a bucket"""
        try:
            response = self.s3_client.get_bucket_replication(Bucket=bucket_name)
            return response.get('ReplicationConfiguration', {})
        except ClientError as e:
            error_code = e.response['Error']['Code']
            if error_code == 'ReplicationConfigurationNotFoundError':
                return None
            else:
                print(f"Error getting replication config for {bucket_name}: {e}")
                return None
    
    def get_replication_metrics(self, bucket_name, days_back=7):
        """Get CloudWatch metrics for replication from source account"""
        end_time = datetime.now(UTC)
        start_time = end_time - timedelta(days=days_back)
        
        metrics = {
            'ReplicationLatency': 0,
            'ObjectsFailedToReplicate': 0,
            'ObjectsPendingReplication': 0,
            'ReplicatedBytes': 0
        }
        
        # Define replication metrics to check
        metric_queries = [
            {
                'name': 'ReplicationLatency',
                'metric_name': 'ReplicationLatency',
                'statistic': 'Average',
                'unit': 'Seconds'
            },
            {
                'name': 'ObjectsFailedToReplicate',
                'metric_name': 'NumberOfObjectsFailedToReplicate',
                'statistic': 'Sum',
                'unit': 'Count'
            },
            {
                'name': 'ObjectsPendingReplication',
                'metric_name': 'NumberOfObjectsPendingReplication',
                'statistic': 'Average',
                'unit': 'Count'
            },
            {
                'name': 'ReplicatedBytes',
                'metric_name': 'BytesPendingReplication',
                'statistic': 'Average',
                'unit': 'Bytes'
            }
        ]
        
        for query in metric_queries:
            try:
                response = self.cloudwatch.get_metric_statistics(
                    Namespace='AWS/S3',
                    MetricName=query['metric_name'],
                    Dimensions=[
                        {
                            'Name': 'SourceBucket',
                            'Value': bucket_name
                        }
                    ],
                    StartTime=start_time,
                    EndTime=end_time,
                    Period=3600,  # 1 hour
                    Statistics=[query['statistic']],
                    Unit=query['unit']
                )
                
                datapoints = response.get('Datapoints', [])
                if datapoints:
                    # Get the most recent datapoint
                    latest = max(datapoints, key=lambda x: x['Timestamp'])
                    value = latest.get(query['statistic'], 0)
                    
                    # Format the value based on unit
                    if query['unit'] == 'Bytes' and value > 0:
                        # Convert bytes to human readable format
                        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
                            if value < 1024.0:
                                metrics[query['name']] = f"{value:.2f} {unit}"
                                break
                            value /= 1024.0
                    elif query['unit'] == 'Seconds' and value > 0:
                        metrics[query['name']] = f"{value:.2f} seconds"
                    else:
                        metrics[query['name']] = int(value) if isinstance(value, float) and value.is_integer() else value
                else:
                    metrics[query['name']] = 0
                    
            except ClientError as e:
                print(f"Warning: Could not get {query['name']} metrics: {e}")
                metrics[query['name']] = "N/A"
        
    def get_replication_metrics_by_destination(self, bucket_name, destination_bucket, days_back=7):
        """Get replication metrics for a specific destination"""
        end_time = datetime.now(UTC)
        start_time = end_time - timedelta(days=days_back)
        
        metrics = {}
        
        try:
            # Get metrics with destination dimension
            response = self.cloudwatch.get_metric_statistics(
                Namespace='AWS/S3',
                MetricName='NumberOfObjectsFailedToReplicate',
                Dimensions=[
                    {'Name': 'SourceBucket', 'Value': bucket_name},
                    {'Name': 'DestinationBucket', 'Value': destination_bucket}
                ],
                StartTime=start_time,
                EndTime=end_time,
                Period=3600,
                Statistics=['Sum']
            )
            
            datapoints = response.get('Datapoints', [])
            if datapoints:
                latest = max(datapoints, key=lambda x: x['Timestamp'])
                metrics['FailedObjects'] = int(latest.get('Sum', 0))
            else:
                metrics['FailedObjects'] = 0
                
        except ClientError as e:
            metrics['FailedObjects'] = "N/A"
        
        return metrics
    
    def check_bucket_exists(self, bucket_name):
        """Check if bucket exists and is accessible"""
        try:
            self.s3_client.head_bucket(Bucket=bucket_name)
            return True
        except ClientError as e:
            error_code = e.response['Error']['Code']
            if error_code == '404':
                print(f"Error: Bucket '{bucket_name}' does not exist or you don't have access")
            else:
                print(f"Error accessing bucket '{bucket_name}': {e}")
            return False
    
    def format_replication_rules(self, rules):
        """Format replication rules for display"""
        formatted_rules = []
        
        for i, rule in enumerate(rules, 1):
            rule_info = {
                'Rule': i,
                'ID': rule.get('ID', 'N/A'),
                'Status': rule.get('Status', 'N/A'),
                'Priority': rule.get('Priority', 'N/A'),
                'Filter': 'All objects',  # Default value
                'Destination': {
                    'Bucket': rule.get('Destination', {}).get('Bucket', 'N/A'),
                    'StorageClass': rule.get('Destination', {}).get('StorageClass', 'STANDARD')
                }
            }
            
            # Check for filters and override default
            if 'Filter' in rule:
                filter_info = rule['Filter']
                if 'Prefix' in filter_info:
                    rule_info['Filter'] = f"Prefix: {filter_info['Prefix']}"
                elif 'Tag' in filter_info:
                    tag = filter_info['Tag']
                    rule_info['Filter'] = f"Tag: {tag['Key']}={tag['Value']}"
                elif 'And' in filter_info:
                    and_conditions = filter_info['And']
                    conditions = []
                    if 'Prefix' in and_conditions:
                        conditions.append(f"Prefix: {and_conditions['Prefix']}")
                    if 'Tags' in and_conditions:
                        for tag in and_conditions['Tags']:
                            conditions.append(f"Tag: {tag['Key']}={tag['Value']}")
                    rule_info['Filter'] = f"Multiple: {', '.join(conditions)}"
                else:
                    rule_info['Filter'] = "Complex filter"
            
            formatted_rules.append(rule_info)
        
        return formatted_rules
    
    def check_replication_status(self, bucket_name, detailed=False):
        """Main method to check replication status"""
        print(f"\n{'='*60}")
        print(f"Checking replication status for bucket: {bucket_name}")
        print(f"{'='*60}")
        
        # Check if bucket exists
        if not self.check_bucket_exists(bucket_name):
            return
        
        # Get replication configuration
        replication_config = self.get_bucket_replication_config(bucket_name)
        
        if not replication_config:
            print(f"❌ No replication configuration found for bucket '{bucket_name}'")
            return
        
        print(f"✅ Replication is configured for bucket '{bucket_name}'")
        print(f"Role ARN: {replication_config.get('Role', 'N/A')}")
        
        # Display replication rules
        rules = replication_config.get('Rules', [])
        print(f"\nReplication Rules ({len(rules)} total):")
        print("-" * 50)
        
        formatted_rules = self.format_replication_rules(rules)
        for rule in formatted_rules:
            print(f"Rule {rule['Rule']}: {rule['ID']}")
            print(f"  Status: {rule['Status']}")
            print(f"  Priority: {rule['Priority']}")
            print(f"  Filter: {rule['Filter']}")
            print(f"  Destination: {rule['Destination']['Bucket']}")
            print(f"  Storage Class: {rule['Destination']['StorageClass']}")
            print()
        
        # Always show replication metrics from source account
        print("\nReplication Health Metrics (Last 7 days from source account):")
        print("-" * 65)
        
        try:
            metrics = self.get_replication_metrics(bucket_name)
            if not metrics:
                print("⚠️  Unable to retrieve replication metrics")
                metrics = {}
        except Exception as e:
            print(f"❌ Error retrieving replication metrics: {e}")
            metrics = {}
        
        # Display metrics with status indicators and explanations
        if metrics:
            for metric_name, value in metrics.items():
                if metric_name == 'ObjectsFailedToReplicate':
                    if isinstance(value, (int, float)) and value > 0:
                        print(f"❌ Failed Objects: {value} (objects that couldn't be replicated)")
                    else:
                        print(f"✅ Failed Objects: {value} (no replication failures)")
                elif metric_name == 'ObjectsPendingReplication':
                    if isinstance(value, (int, float)) and value > 100:
                        print(f"⚠️  Pending Objects: {value} (high backlog - check capacity)")
                    elif isinstance(value, (int, float)) and value > 0:
                        print(f"📊 Pending Objects: {value} (objects waiting for replication)")
                    else:
                        print(f"✅ Pending Objects: {value} (no replication backlog)")
                elif metric_name == 'ReplicationLatency':
                    if isinstance(value, str) and 'seconds' in value:
                        latency_val = float(value.split()[0])
                        if latency_val > 900:
                            print(f"⚠️  Replication Latency: {value} (high latency)")
                        else:
                            print(f"📊 Replication Latency: {value}")
                    else:
                        print(f"📊 Replication Latency: {value}")
                elif metric_name == 'ReplicatedBytes':
                    print(f"📊 Bytes Pending: {value} (data volume waiting for replication)")
                else:
                    print(f"📊 {metric_name}: {value}")
        else:
            print("⚠️  No replication metrics available")
        
        # Show destination bucket status only if detailed view requested
        if detailed:
            print("\nPer-Destination Replication Analysis:")
            print("-" * 50)
            for rule in formatted_rules:
                dest_bucket_arn = rule['Destination']['Bucket']
                dest_bucket = dest_bucket_arn.replace('arn:aws:s3:::', '')
                
                print(f"\n📋 Rule: {rule['ID']}")
                print(f"   Destination: {dest_bucket}")
                
                # Get per-destination metrics
                dest_metrics = self.get_replication_metrics_by_destination(bucket_name, dest_bucket_arn)
                failed = dest_metrics.get('FailedObjects', 0)
                
                if isinstance(failed, int) and failed > 0:
                    print(f"   ❌ Failed objects: {failed}")
                else:
                    print(f"   ✅ Failed objects: {failed}")
                
                # Check accessibility (optional)
                if self.check_bucket_exists(dest_bucket):
                    print(f"   ✅ Bucket accessible")
                else:
                    print(f"   ⚠️  Bucket not accessible (may be in different account)")
        
        # Add replication health summary
        print(f"\n📊 Overall Replication Health:")
        print("-" * 35)
        
        if metrics:
            failed_objects = metrics.get('ObjectsFailedToReplicate', 0)
            pending_objects = metrics.get('ObjectsPendingReplication', 0)
            latency = metrics.get('ReplicationLatency', 0)
            
            if isinstance(failed_objects, (int, float)) and failed_objects > 0:
                print(f"⚠️  {failed_objects} objects failed to replicate in last 7 days")
            else:
                print("✅ No replication failures detected in last 7 days")
                
            if isinstance(pending_objects, (int, float)) and pending_objects > 0:
                print(f"📊 {pending_objects} objects currently pending replication")
            else:
                print("✅ No objects currently pending replication")
                
            if isinstance(latency, (int, float)) and latency > 0:
                if latency > 900:  # 15 minutes
                    print(f"⚠️  Average replication latency: {latency} (consider investigating)")
                else:
                    print(f"✅ Average replication latency: {latency}")
            else:
                print("📊 Replication latency: No recent data")
        else:
            print("⚠️  Unable to determine replication health - metrics unavailable")
    
    def list_buckets_with_replication(self):
        """List all buckets with replication enabled"""
        try:
            response = self.s3_client.list_buckets()
            buckets_with_replication = []
            
            print("Scanning buckets for replication configuration...")
            print("-" * 50)
            
            for bucket in response['Buckets']:
                bucket_name = bucket['Name']
                replication_config = self.get_bucket_replication_config(bucket_name)
                
                if replication_config:
                    rules_count = len(replication_config.get('Rules', []))
                    buckets_with_replication.append({
                        'name': bucket_name,
                        'rules_count': rules_count,
                        'created': bucket['CreationDate']
                    })
                    print(f"✅ {bucket_name} ({rules_count} rules)")
                else:
                    print(f"❌ {bucket_name} (no replication)")
            
            return buckets_with_replication
            
        except ClientError as e:
            print(f"Error listing buckets: {e}")
            return []

def list_aws_profiles():
    """List available AWS profiles"""
    profiles = []
    
    # Check AWS credentials file
    credentials_path = os.path.expanduser('~/.aws/credentials')
    config_path = os.path.expanduser('~/.aws/config')
    
    try:
        # Parse credentials file
        if os.path.exists(credentials_path):
            config = configparser.ConfigParser()
            config.read(credentials_path)
            profiles.extend(config.sections())
        
        # Parse config file
        if os.path.exists(config_path):
            config = configparser.ConfigParser()
            config.read(config_path)
            for section in config.sections():
                if section.startswith('profile '):
                    profile_name = section.replace('profile ', '')
                    if profile_name not in profiles:
                        profiles.append(profile_name)
                elif section == 'default' and 'default' not in profiles:
                    profiles.append('default')
    
    except Exception as e:
        print(f"Error reading AWS configuration files: {e}")
    
    return sorted(profiles)

def main():
    parser = argparse.ArgumentParser(description='Check S3 bucket replication status')
    parser.add_argument('--bucket', '-b', help='Specific bucket name to check')
    parser.add_argument('--list-all', '-l', action='store_true', 
                       help='List all buckets with replication enabled')
    parser.add_argument('--detailed', '-d', action='store_true', 
                       help='Show detailed info including destination bucket accessibility')
    parser.add_argument('--region', '-r', default='us-east-1', 
                       help='AWS region (default: us-east-1)')
    parser.add_argument('--profile', '-p', 
                       help='AWS profile name (default: use default profile)')
    parser.add_argument('--list-profiles', action='store_true',
                       help='List available AWS profiles')
    
    args = parser.parse_args()
    
    # Handle list profiles option
    if args.list_profiles:
        profiles = list_aws_profiles()
        if profiles:
            print("Available AWS profiles:")
            for profile in profiles:
                print(f"  - {profile}")
        else:
            print("No AWS profiles found.")
            print("Create profiles with: aws configure --profile <profile-name>")
        return
    
    # Initialize checker
    checker = S3ReplicationChecker(region_name=args.region, profile_name=args.profile)
    
    if args.list_all:
        print("Listing all buckets with replication enabled:")
        buckets = checker.list_buckets_with_replication()
        
        if buckets:
            print(f"\nFound {len(buckets)} bucket(s) with replication enabled:")
            for bucket in buckets:
                print(f"- {bucket['name']} ({bucket['rules_count']} rules)")
        else:
            print("No buckets with replication configuration found.")
    
    elif args.bucket:
        checker.check_replication_status(args.bucket, detailed=args.detailed)
    
    else:
        parser.print_help()
        print("\nExample usage:")
        print("  python s3_replication_checker.py --list-profiles")
        print("  python s3_replication_checker.py --bucket my-source-bucket")
        print("  python s3_replication_checker.py --list-all")
        print("  python s3_replication_checker.py --bucket my-bucket --detailed  # includes per-destination analysis")
        print("  python s3_replication_checker.py --bucket my-bucket --profile production")
        print("  python s3_replication_checker.py --list-all --profile dev --region us-west-2")

if __name__ == "__main__":
    main()