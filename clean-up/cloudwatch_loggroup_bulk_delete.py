import boto3

def print_table(log_groups):
    idx_width = len(str(len(log_groups))) + 2
    name_width = max(len("Log Group Name"), *(len(lg['logGroupName']) for lg in log_groups)) + 2
    creation_width = len("Creation Time") + 2

    # Header
    header = f"{'No.':<{idx_width}}{'Log Group Name':<{name_width}}{'Creation Time':<{creation_width}}"
    print(header)
    print('-' * (idx_width + name_width + creation_width))

    # Rows
    for idx, lg in enumerate(log_groups, 1):
        # CreationTime is in milliseconds since epoch
        from datetime import datetime
        creation = datetime.utcfromtimestamp(lg['creationTime'] / 1000.0).strftime("%Y-%m-%d %H:%M:%S")
        print(f"{idx:<{idx_width}}{lg['logGroupName']:<{name_width}}{creation:<{creation_width}}")

def delete_log_group(client, log_group_name):
    try:
        client.delete_log_group(logGroupName=log_group_name)
        print(f"Log group {log_group_name} deleted successfully.")
    except Exception as e:
        print(f"Failed to delete log group {log_group_name}: {e}")

def main():
    client = boto3.client('logs')
    prefix = input("Enter the prefix of the log group names to search: ").strip()
    paginator = client.get_paginator('describe_log_groups')
    log_groups = []
    for page in paginator.paginate(logGroupNamePrefix=prefix):
        log_groups.extend(page.get('logGroups', []))

    if not log_groups:
        print("No log groups found with prefix:", prefix)
        return

    print("\nThe following log groups will be deleted:\n")
    print_table(log_groups)

    confirm = input("Are you sure you want to delete these log groups? (yes/no): ")
    if confirm.lower() != 'yes':
        print("Aborted.")
        return

    for lg in log_groups:
        print(f"Deleting log group: {lg['logGroupName']}")
        delete_log_group(client, lg['logGroupName'])

if __name__ == "__main__":
    main()
