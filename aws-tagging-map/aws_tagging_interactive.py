import boto3
import json
import os
import sys
import logging
import time
from datetime import datetime
from botocore.exceptions import ClientError, NoCredentialsError

# Configuration
TAGS_FILE = 'tags.json'
LOG_DIR = 'log'

def setup_logging():
    """Setup logging to file."""
    if not os.path.exists(LOG_DIR):
        os.makedirs(LOG_DIR)
    
    timestamp = datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
    log_filename = os.path.join(LOG_DIR, f'aws_tagging_{timestamp}.log')
    
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(log_filename),
            # functionality: logs go to file, print goes to console. 
            # We won't add StreamHandler to avoid double printing in interactive mode.
        ]
    )
    return log_filename

def get_account_id():
    """Get the current AWS Account ID."""
    try:
        sts = boto3.client('sts')
        return sts.get_caller_identity()['Account']
    except Exception as e:
        print(f"Error getting Account ID: {e}")
        sys.exit(1)

def get_account_name():
    """Get the AWS Account Alias (Name)."""
    try:
        iam = boto3.client('iam')
        aliases = iam.list_account_aliases()
        if aliases['AccountAliases']:
            return aliases['AccountAliases'][0]
        return "None (Alias not set)"
    except Exception as e:
        logging.warning(f"Could not retrieve account alias: {e}")
        return "Unknown"

def get_region():
    """Get the current AWS Region."""
    session = boto3.session.Session()
    return session.region_name

def load_tags():
    """Load tags from the JSON file."""
    if not os.path.exists(TAGS_FILE):
        print(f"Error: {TAGS_FILE} not found.")
        sys.exit(1)
    
    try:
        with open(TAGS_FILE, 'r') as f:
            data = json.load(f)
            return data.get('Tags', {})
    except json.JSONDecodeError:
        print(f"Error: Invalid JSON in {TAGS_FILE}.")
        sys.exit(1)

def get_resources_ec2(session, account_id, region):
    ec2 = session.client('ec2')
    resources = []
    paginator = ec2.get_paginator('describe_instances')
    for page in paginator.paginate():
        for reservation in page['Reservations']:
            for instance in reservation['Instances']:
                # EC2 instances are regional
                arn = f"arn:aws:ec2:{region}:{account_id}:instance/{instance['InstanceId']}"
                resources.append({'Id': instance['InstanceId'], 'Arn': arn, 'Type': 'EC2 Instance'})
    return resources

def get_resources_s3(session, account_id, region):
    s3 = session.client('s3')
    resources = []
    try:
        response = s3.list_buckets()
        for bucket in response.get('Buckets', []):
            arn = f"arn:aws:s3:::{bucket['Name']}"
            resources.append({'Id': bucket['Name'], 'Arn': arn, 'Type': 'S3 Bucket'})
    except Exception as e:
        print(f"Error listing S3 buckets: {e}")
    return resources

def get_resources_lambda(session, account_id, region):
    # Lambda ARNs are returned directly
    awslambda = session.client('lambda')
    resources = []
    paginator = awslambda.get_paginator('list_functions')
    for page in paginator.paginate():
        for func in page['Functions']:
            resources.append({'Id': func['FunctionName'], 'Arn': func['FunctionArn'], 'Type': 'Lambda Function'})
    return resources

def get_resources_ebs(session, account_id, region):
    ec2 = session.client('ec2')
    resources = []
    paginator = ec2.get_paginator('describe_volumes')
    for page in paginator.paginate():
        for vol in page['Volumes']:
            arn = f"arn:aws:ec2:{region}:{account_id}:volume/{vol['VolumeId']}"
            resources.append({'Id': vol['VolumeId'], 'Arn': arn, 'Type': 'EBS Volume'})
    return resources

def get_resources_ebs_snapshot(session, account_id, region):
    ec2 = session.client('ec2')
    resources = []
    # Only snapshots owned by self
    paginator = ec2.get_paginator('describe_snapshots')
    for page in paginator.paginate(OwnerIds=['self']):
        for snap in page['Snapshots']:
            arn = f"arn:aws:ec2:{region}:{account_id}:snapshot/{snap['SnapshotId']}"
            resources.append({'Id': snap['SnapshotId'], 'Arn': arn, 'Type': 'EBS Snapshot'})
    return resources

def get_resources_rds(session, account_id, region):
    rds = session.client('rds')
    resources = []
    paginator = rds.get_paginator('describe_db_instances')
    for page in paginator.paginate():
        for db in page['DBInstances']:
            # RDS ARNs usually are provided or can be constructed
            arn = db['DBInstanceArn']
            resources.append({'Id': db['DBInstanceIdentifier'], 'Arn': arn, 'Type': 'RDS Instance'})
    return resources

def get_resources_sns(session, account_id, region):
    sns = session.client('sns')
    resources = []
    paginator = sns.get_paginator('list_topics')
    for page in paginator.paginate():
        for topic in page['Topics']:
            resources.append({'Id': topic['TopicArn'].split(':')[-1], 'Arn': topic['TopicArn'], 'Type': 'SNS Topic'})
    return resources

def get_resources_sqs(session, account_id, region):
    sqs = session.client('sqs')
    resources = []
    paginator = sqs.get_paginator('list_queues')
    for page in paginator.paginate():
        for url in page.get('QueueUrls', []):
            # SQS ARN logic: arn:aws:sqs:region:account_id:queue_name
            queue_name = url.split('/')[-1]
            arn = f"arn:aws:sqs:{region}:{account_id}:{queue_name}"
            resources.append({'Id': queue_name, 'Arn': arn, 'Type': 'SQS Queue'})
    return resources

def get_resources_ecr(session, account_id, region):
    ecr = session.client('ecr')
    resources = []
    try:
        # Use describe_repositories with pagination to get all repositories
        paginator = ecr.get_paginator('describe_repositories')
        all_repos = []

        for page in paginator.paginate():
            all_repos.extend(page.get('repositories', []))

        for repo in all_repos:
            resources.append({
                'Id': repo['repositoryName'],
                'Arn': repo['repositoryArn'],
                'Type': 'ECR Repository'
            })
    except Exception as e:
        logging.error(f"Failed to list ECR repositories: {e}")
        # Don't raise the exception to continue execution
        pass
    return resources

def get_resources_secretsmanager(session, account_id, region):
    sm = session.client('secretsmanager')
    resources = []
    paginator = sm.get_paginator('list_secrets')
    for page in paginator.paginate():
        for secret in page['SecretList']:
            resources.append({'Id': secret['Name'], 'Arn': secret['ARN'], 'Type': 'Secrets Manager Secret'})
    return resources

def get_resources_elb(session, account_id, region):
    resources = []
    
    # Classic ELB
    try:
        elb = session.client('elb')
        paginator = elb.get_paginator('describe_load_balancers')
        for page in paginator.paginate():
            for lb in page['LoadBalancerDescriptions']:
                # Construct ARN for CLB: arn:aws:elasticloadbalancing:region:account-id:loadbalancer/name
                name = lb['LoadBalancerName']
                arn = f"arn:aws:elasticloadbalancing:{region}:{account_id}:loadbalancer/{name}"
                resources.append({'Id': name, 'Arn': arn, 'Type': 'Classic Load Balancer'})
    except Exception as e:
        print(f"Error scanning Classic ELB: {e}")

    # ALB/NLB/GLB (ELBv2)
    try:
        elbv2 = session.client('elbv2')
        paginator = elbv2.get_paginator('describe_load_balancers')
        for page in paginator.paginate():
            for lb in page['LoadBalancers']:
                # ARN is provided directly in ELBv2
                arn = lb['LoadBalancerArn']
                name = lb['LoadBalancerName']
                lb_type = lb.get('Type', 'application').capitalize() + ' Load Balancer' # application, network, gateway
                resources.append({'Id': name, 'Arn': arn, 'Type': lb_type})
    except Exception as e:
         print(f"Error scanning ELBv2: {e}")
         
    return resources

def get_resources_ecs(session, account_id, region):
    ecs = session.client('ecs')
    resources = []
    paginator = ecs.get_paginator('list_clusters')
    for page in paginator.paginate():
        for cluster_arn in page['clusterArns']:
             resources.append({'Id': cluster_arn.split('/')[-1], 'Arn': cluster_arn, 'Type': 'ECS Cluster'})
    return resources

def get_resources_eks(session, account_id, region):
    eks = session.client('eks')
    resources = []
    paginator = eks.get_paginator('list_clusters')
    for page in paginator.paginate():
        for cluster_name in page['clusters']:
            cluster = eks.describe_cluster(name=cluster_name)['cluster']
            resources.append({'Id': cluster_name, 'Arn': cluster['arn'], 'Type': 'EKS Cluster'})
    return resources

def get_resources_efs(session, account_id, region):
    efs = session.client('efs')
    resources = []
    try:
        paginator = efs.get_paginator('describe_file_systems')
        for page in paginator.paginate():
            for fs in page.get('FileSystems', []):
                 # Name tag is optional, fallback to FileSystemId
                 name = fs.get('Name', fs.get('FileSystemId', 'Unknown'))
                 resources.append({'Id': name, 'Arn': fs['FileSystemArn'], 'Type': 'EFS File System'})
    except Exception as e:
        logging.error(f"Failed to list EFS file systems: {e}")
        # Don't raise the exception to continue execution
        pass
    return resources

def get_resources_direct_connect(session, account_id, region):
    dc = session.client('directconnect')
    resources = []
    try:
        paginator = dc.get_paginator('describe_connections')
        for page in paginator.paginate():
            for conn in page['connections']:
                arn = f"arn:aws:directconnect:{region}:{account_id}:dxcon/{conn['connectionId']}"
                resources.append({'Id': conn['connectionId'], 'Arn': arn, 'Type': 'Direct Connect Connection'})
    except Exception as e:
        print(f"Error scanning Direct Connect: {e}")
    return resources

def get_resources_fsx(session, account_id, region):
    fsx = session.client('fsx')
    resources = []
    try:
        paginator = fsx.get_paginator('describe_file_systems')
        for page in paginator.paginate():
            for fs in page['FileSystems']:
                 resources.append({'Id': fs['FileSystemId'], 'Arn': fs['ResourceARN'], 'Type': 'FSx File System'})
    except ClientError as e:
        # FSx might not be available in all regions
        print(f"Error scanning FSx: {e}")
    return resources

def get_resources_apigateway(session, account_id, region):
    resources = []
    apigw = session.client('apigateway', region_name=region)
    
    # REST APIs
    try:
        paginator = apigw.get_paginator('get_rest_apis')
        for page in paginator.paginate():
            for item in page['items']:
                arn = f"arn:aws:apigateway:{region}::/restapis/{item['id']}"
                resources.append({'Id': item['name'], 'Arn': arn, 'Type': 'API Gateway REST API'})
    except Exception as e:
        print(f"Error scanning API Gateway (REST): {e}")

    # Start checking HTTP APIs (v2) only if needed or requested, but let's stick to v1 as per map if needed.
    # But master.sh only checked v1 'get-rest-apis' for availability check but executed apigateway.sh 
    # which checked REST, HTTP, Custom Domains, VPC Links. So I should add those too.
    
    apigw2 = session.client('apigatewayv2', region_name=region)
    try:
        # HTTP APIs
        # get_apis doesn't support pagination in some older boto3 versions? check... it does.
        # But paginator might not be available for all.
        next_token = None
        while True:
            kwargs = {'NextToken': next_token} if next_token else {}
            response = apigw2.get_apis(**kwargs)
            for item in response.get('Items', []):
                arn = f"arn:aws:apigateway:{region}::/apis/{item['ApiId']}"
                resources.append({'Id': item['Name'], 'Arn': arn, 'Type': 'API Gateway HTTP API'})
            next_token = response.get('NextToken')
            if not next_token:
                break
    except Exception as e:
        pass # V2 might not be used or error 

    return resources

def get_resources_network_firewall(session, account_id, region):
    nf = session.client('network-firewall')
    resources = []
    try:
        paginator = nf.get_paginator('list_firewalls')
        for page in paginator.paginate():
            for fw in page['Firewalls']:
                 resources.append({'Id': fw['FirewallName'], 'Arn': fw['FirewallArn'], 'Type': 'Network Firewall'})
    except Exception as e:
        print(f"Error scanning Network Firewall: {e}")
    return resources

def get_resources_opensearch(session, account_id, region):
    opensearch = session.client('opensearch')
    resources = []
    try:
        # list_domain_names returns simple list of names
        names = opensearch.list_domain_names().get('DomainNames', [])
        # Construct ARN: arn:aws:es:region:account:domain/domain-name
        for domain in names:
            name = domain['DomainName']
            arn = f"arn:aws:es:{region}:{account_id}:domain/{name}"
            resources.append({'Id': name, 'Arn': arn, 'Type': 'OpenSearch Domain'})
    except Exception as e:
        print(f"Error scanning OpenSearch: {e}")
    return resources

def get_resources_route53(session, account_id, region):
    r53 = session.client('route53')
    resources = []
    try:
        paginator = r53.get_paginator('list_hosted_zones')
        for page in paginator.paginate():
            for zone in page['HostedZones']:
                # Id is like /hostedzone/Z12345
                clean_id = zone['Id'].replace('/hostedzone/', '')
                arn = f"arn:aws:route53:::hostedzone/{clean_id}"
                resources.append({'Id': zone['Name'], 'Arn': arn, 'Type': 'Route53 Hosted Zone'})
    except Exception as e:
        print(f"Error scanning Route53: {e}")
    return resources

def get_resources_backup(session, account_id, region):
    backup = session.client('backup')
    resources = []
    try:
        paginator = backup.get_paginator('list_backup_vaults')
        for page in paginator.paginate():
            for vault in page['BackupVaultList']:
                 resources.append({'Id': vault['BackupVaultName'], 'Arn': vault['BackupVaultArn'], 'Type': 'Backup Vault'})
    except Exception as e:
        print(f"Error scanning AWS Backup: {e}")
    return resources

def get_resources_logs(session, account_id, region):
    logs = session.client('logs')
    resources = []
    try:
        paginator = logs.get_paginator('describe_log_groups')
        for page in paginator.paginate():
            for lg in page['logGroups']:
                 arn = lg['arn']
                 if arn.endswith(':*'):
                     arn = arn[:-2]
                 resources.append({'Id': lg['logGroupName'], 'Arn': arn, 'Type': 'CloudWatch Log Group'})
    except Exception as e:
        print(f"Error scanning CloudWatch Logs: {e}")
    return resources

def get_resources_elasticache(session, account_id, region):
    ec = session.client('elasticache')
    resources = []
    try:
        paginator = ec.get_paginator('describe_cache_clusters')
        for page in paginator.paginate():
            for cluster in page['CacheClusters']:
                 resources.append({'Id': cluster['CacheClusterId'], 'Arn': cluster['ARN'], 'Type': 'ElastiCache Cluster'})
    except Exception as e:
        print(f"Error scanning ElastiCache: {e}")
    return resources

def get_resources_dynamodb(session, account_id, region):
    dynamodb = session.client('dynamodb')
    resources = []
    try:
        paginator = dynamodb.get_paginator('list_tables')
        for page in paginator.paginate():
            for table_name in page['TableNames']:
                arn = f"arn:aws:dynamodb:{region}:{account_id}:table/{table_name}"
                resources.append({'Id': table_name, 'Arn': arn, 'Type': 'DynamoDB Table'})
    except Exception as e:
        print(f"Error scanning DynamoDB: {e}")
    return resources

# Map service names to their getter functions
SERVICE_MAP = {
    'ec2': get_resources_ec2,
    's3': get_resources_s3,
    'lambda': get_resources_lambda,
    'ebs_volume': get_resources_ebs,
    'ebs_snapshot': get_resources_ebs_snapshot,
    'rds': get_resources_rds,
    'sns': get_resources_sns,
    'sqs': get_resources_sqs,
    'ecr': get_resources_ecr,
    'secretsmanager': get_resources_secretsmanager,
    'elb': get_resources_elb,
    'ecs': get_resources_ecs,
    'eks': get_resources_eks,
    'efs': get_resources_efs,
    'direct_connect': get_resources_direct_connect,
    'fsx': get_resources_fsx,
    'apigateway': get_resources_apigateway,
    'network_firewall': get_resources_network_firewall,
    'opensearch': get_resources_opensearch,
    'route53': get_resources_route53,
    'aws_backup': get_resources_backup,
    'cloudwatch_logs_groups': get_resources_logs,
    'elasticache': get_resources_elasticache,
    'dynamodb': get_resources_dynamodb,
}

def print_progress(iteration, total, prefix='', suffix='', decimals=1, length=50, fill='█'):
    """
    Call in a loop to create terminal progress bar
    """
    percent = ("{0:." + str(decimals) + "f}").format(100 * (iteration / float(total)))
    filled_length = int(length * iteration // total)
    bar = fill * filled_length + '-' * (length - filled_length)
    sys.stdout.write(f'\r{prefix} |{bar}| {percent}% {suffix}')
    sys.stdout.flush()
    if iteration == total:
        sys.stdout.write('\n')

def tag_resources(session, resources, tags):
    """
    Tags resources using the Resource Groups Tagging API.
    """
    tagging_api = session.client('resourcegroupstaggingapi')
    
    # Split resources into chunks of 20 (API limit)
    arn_list = [r['Arn'] for r in resources]
    total_resources = len(arn_list)
    
    chunk_size = 10
    processed_count = 0
    success_count = 0
    error_count = 0
    errors = []
    
    # Helper for suffix formatting
    def get_suffix(success, error, total):
        return f"- Success: {success} | Failed: {error} | Total: {total}"
    
    print_progress(0, total_resources, prefix=PROGRESS_PREFIX, suffix=get_suffix(0, 0, total_resources), length=40)
    
    for i in range(0, len(arn_list), chunk_size):
        chunk = arn_list[i:i + chunk_size]
        chunk_len = len(chunk)
        
        current_chunk = chunk
        chunk_success = 0
        chunk_failed_permanent = 0
        
        for attempt in range(MAX_RETRIES):
            if not current_chunk:
                break
                
            try:
                response = tagging_api.tag_resources(
                    ResourceARNList=current_chunk,
                    Tags=tags
                )
                failed = response.get('FailedResourcesMap', {})
                
                # If no failures, we are done with this chunk substep
                if not failed:
                    chunk_success += len(current_chunk)
                    break
                
                # Separate throttled vs permanent errors
                throttled_arns = []
                for arn, error in failed.items():
                    if error.get('ErrorCode') == 'ThrottlingException':
                        throttled_arns.append(arn)
                    else:
                        msg = f"Warning: Failed to tag {arn}: {error}"
                        errors.append(msg)
                        logging.warning(msg)
                        chunk_failed_permanent += 1

                # Calculate successes in this iteration: (Attempted - Failed)
                # Note: 'Failed' here includes both throttled and permanent for this specific call
                # But we only count 'success' for items that didn't fail at all logic is tricky.
                # Simpler: Success = Total in Chunk - Permanent Errors - Final/Given Up Throttled Errors
                
                # actually, easier: Just count successfully processed ones in this iteration
                iteration_success = len(current_chunk) - len(failed)
                chunk_success += iteration_success

                if throttled_arns:
                    if attempt < MAX_RETRIES - 1:
                        sleep_time = BACKOFF_FACTOR * (2 ** attempt)
                        logging.info(f"Throttling detected on {len(throttled_arns)} resources. Retrying in {sleep_time}s...")
                        time.sleep(sleep_time)
                        current_chunk = throttled_arns
                    else:
                        msg = f"Error: Rate limit exceeded for {len(throttled_arns)} resources after {MAX_RETRIES} attempts. Failed ARNs: {throttled_arns}"
                        errors.append(msg)
                        logging.error(msg)
                        # We count these as errors now
                        chunk_failed_permanent += len(throttled_arns)
                else:
                    # No throttled items, just permanent errors, or empty
                    break
                    
            except Exception as e:
                msg = f"Error tagging chunk: {e}"
                errors.append(msg)
                logging.error(msg)
                # If the API call itself crashed, we assume whole current_chunk failed
                chunk_failed_permanent += len(current_chunk)
                break
        
        success_count += chunk_success
        error_count += chunk_failed_permanent
        
        logging.info(f"Processed chunk of {chunk_len}. Success: {chunk_success}, Failed: {chunk_failed_permanent}")
        
        # Standard rate limiting between chunks
        time.sleep(1)
        
        processed_count += chunk_len
        print_progress(processed_count, total_resources, prefix=PROGRESS_PREFIX, suffix=get_suffix(success_count, error_count, total_resources), length=40)

    if errors:
        print("\nWarnings/Errors occurred during tagging:")
        for err in errors:
            print(err)

def untag_resources(session, resources, tag_keys):
    """
    Untags resources using the Resource Groups Tagging API.
    """
    tagging_api = session.client('resourcegroupstaggingapi')
    
    # Split resources into chunks of 20 (API limit)
    arn_list = [r['Arn'] for r in resources]
    total_resources = len(arn_list)
    
    chunk_size = 10
    processed_count = 0
    success_count = 0
    error_count = 0
    errors = []
    
    # Helper for suffix formatting
    def get_suffix(success, error, total):
        return f"- Success: {success} | Failed: {error} | Total: {total}"
    
    print_progress(0, total_resources, prefix=PROGRESS_PREFIX, suffix=get_suffix(0, 0, total_resources), length=40)
    
    for i in range(0, len(arn_list), chunk_size):
        chunk = arn_list[i:i + chunk_size]
        chunk_len = len(chunk)
        
        current_chunk = chunk
        chunk_success = 0
        chunk_failed_permanent = 0

        for attempt in range(MAX_RETRIES):
            if not current_chunk:
                break
                
            try:
                response = tagging_api.untag_resources(
                    ResourceARNList=current_chunk,
                    TagKeys=tag_keys
                )
                failed = response.get('FailedResourcesMap', {})
                
                if not failed:
                    chunk_success += len(current_chunk)
                    break
                    
                throttled_arns = []
                for arn, error in failed.items():
                    if error.get('ErrorCode') == 'ThrottlingException':
                        throttled_arns.append(arn)
                    else:
                        msg = f"Warning: Failed to untag {arn}: {error}"
                        errors.append(msg)
                        logging.warning(msg)
                        chunk_failed_permanent += 1
                
                iteration_success = len(current_chunk) - len(failed)
                chunk_success += iteration_success

                if throttled_arns:
                    if attempt < MAX_RETRIES - 1:
                        sleep_time = BACKOFF_FACTOR * (2 ** attempt)
                        logging.info(f"Throttling detected on {len(throttled_arns)} resources. Retrying in {sleep_time}s...")
                        time.sleep(sleep_time)
                        current_chunk = throttled_arns
                    else:
                        msg = f"Error: Rate limit exceeded for {len(throttled_arns)} resources after {MAX_RETRIES} attempts. Failed ARNs: {throttled_arns}"
                        errors.append(msg)
                        logging.error(msg)
                        chunk_failed_permanent += len(throttled_arns)
                else:
                    break
                    
            except Exception as e:
                msg = f"Error untagging chunk: {e}"
                errors.append(msg)
                logging.error(msg)
                chunk_failed_permanent += len(current_chunk)
                break
            
        success_count += chunk_success
        error_count += chunk_failed_permanent
        
        logging.info(f"Processed chunk of {chunk_len}. Success: {chunk_success}, Failed: {chunk_failed_permanent}")
            
        # Rate limiting to avoid ThrottlingException
        time.sleep(1)
        
        processed_count += chunk_len
        print_progress(processed_count, total_resources, prefix=PROGRESS_PREFIX, suffix=get_suffix(success_count, error_count, total_resources), length=40)

    if errors:
        print("\nWarnings/Errors occurred during untagging:")
        for err in errors:
            print(err)

DIVIDER = "=" * 43
PROGRESS_PREFIX = 'Progress:'
MAX_RETRIES = 5
BACKOFF_FACTOR = 1.0 

def select_services(available_services):
    """
    Prompt user to select services.
    Returns a list of selected service names.
    """
    while True:
        choice = input("\nEnter service numbers (comma-separated, e.g., 1,3) or 'a' for all: ").strip().lower()
        
        if choice == 'q':
            sys.exit(0)
        
        if choice == 'a':
            return available_services
        
        try:
            indices = [int(x.strip()) - 1 for x in choice.split(',')]
            valid_indices = [i for i in indices if 0 <= i < len(available_services)]
            if not valid_indices:
                print("No valid services selected. Try again.")
                continue
            return [available_services[i] for i in valid_indices]
        except ValueError:
            print("Invalid input. Please enter numbers or 'a'.")

def select_mode():
    """Prompt user to select operation mode."""
    print("\nSelect Operation Mode:")
    print("1. Apply Tags (Add/Update)")
    print("2. Remove Tags")
    while True:
        choice = input("Enter choice (1 or 2): ").strip()
        if choice == '1':
            return 'apply'
        elif choice == '2':
            return 'remove'
        else:
            print("Invalid input. Please enter 1 or 2.")

def main():
    log_file = setup_logging()
    
    print("Welcome to the Interactive AWS Tagging Script")
    print(DIVIDER)
    
    logging.info("Session started")
    account_id = get_account_id()
    account_alias = get_account_name()
    region = get_region()
    print(f"Target Account: {account_id} ({account_alias})")
    print(f"Target Region:  {region}")
    logging.info(f"Target Account: {account_id} ({account_alias}), Region: {region}")
    print(DIVIDER)

    print(DIVIDER)
    
    mode = select_mode()
    mode_long = "Apply Tags" if mode == 'apply' else "Remove Tags"
    logging.info(f"Operation Mode: {mode_long}")

    tags = load_tags()
    action_str = "applied" if mode == 'apply' else "removed"
    print(f"Tags to be {action_str}: {json.dumps(tags, indent=2)}")
    logging.info(f"Tags loaded: {json.dumps(tags)}")
    print(DIVIDER)

    available_services = sorted(SERVICE_MAP.keys())
    
    print("\nAvailable Services:")
    for idx, service in enumerate(available_services):
        print(f"{idx + 1}. {service}")
    
    print("a. All Services")
    print("q. Quit")
    
    selected_services = select_services(available_services)

    logging.info(f"Selected Services: {selected_services}")
    print(f"\nSelected Services: {', '.join(selected_services)}")
    
    session = boto3.session.Session()
    all_resources = []
    
    for service_name in selected_services:
        print(f"Scanning {service_name}...")
        getter = SERVICE_MAP[service_name]
        try:
            resources = getter(session, account_id, region)
            count = len(resources)
            print(f"  Found {count} resources for {service_name}")
            logging.info(f"Found {count} resources for {service_name}")
            all_resources.extend(resources)
        except Exception as e:
            msg = f"  Error scanning {service_name}: {e}"
            print(msg)
            logging.error(msg)

    if not all_resources:
        print("\nNo resources found to tag.")
        logging.info("No resources found. Exiting.")
        sys.exit(0)

    print("\nResource Preview:")
    print("=================")
    preview_limit = 20
    for i, r in enumerate(all_resources):
        if i < preview_limit:
            print(f"[{r['Type']}] {r['Id']} ({r['Arn']})")
    
    if len(all_resources) > preview_limit:
        print(f"... and {len(all_resources) - preview_limit} more.")

    print(f"\nTotal Resources to Tag: {len(all_resources)}")
    logging.info(f"Total Resources identificated for tagging: {len(all_resources)}")
    
    action_verb = "applying" if mode == 'apply' else "removing"
    confirm = input(f"\nProceed with {action_verb} tags? (y/n): ").strip().lower()
    
    if confirm == 'y':
        print(f"\n{action_verb.capitalize()} tags...")
        logging.info(f"User confirmed {action_verb} operation.")
        
        if mode == 'apply':
            tag_resources(session, all_resources, tags)
        else:
            untag_resources(session, all_resources, list(tags.keys()))
            
        print("Done!")
        logging.info(f"{action_verb.capitalize()} operation completed.")
        print(f"Log saved to: {log_file}")
    else:
        print("Operation cancelled.")
        logging.info("User cancelled operation.")

if __name__ == "__main__":
    main()
