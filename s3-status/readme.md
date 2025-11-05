Perfect! I've modified the script to support different AWS profiles. Here are the key changes:

## New Features Added:

1. **Profile Support** - Use `--profile` or `-p` to specify an AWS profile
2. **List Available Profiles** - Use `--list-profiles` to see all configured profiles
3. **Better Error Handling** - Clear messages when profiles don't exist

## Updated Usage Examples:

```bash
# List available AWS profiles
python s3_replication_checker.py --list-profiles

# Use a specific profile
python s3_replication_checker.py --bucket my-bucket --profile production

# Combine profile with region
python s3_replication_checker.py --list-all --profile dev --region us-west-2

# Check bucket with staging profile and detailed metrics
python s3_replication_checker.py --bucket my-bucket --profile staging --detailed
```

## How AWS Profiles Work:

The script now uses `boto3.Session(profile_name=profile_name)` which allows you to:

- **Use different AWS accounts** - Each profile can have different access keys
- **Switch between environments** - Have separate profiles for dev, staging, production
- **Use different regions as default** - Each profile can have its own default region
- **Use different credential methods** - Profiles can use access keys, roles, or SSO

## Setting Up AWS Profiles:

```bash
# Configure a new profile
aws configure --profile production

# Configure with SSO
aws configure sso --profile dev

# List existing profiles  
aws configure list-profiles
```

## Profile Configuration Files:

The script reads from standard AWS configuration files:
- `~/.aws/credentials` - Contains access keys
- `~/.aws/config` - Contains profile settings and regions

The script will automatically detect and list all available profiles from these files.