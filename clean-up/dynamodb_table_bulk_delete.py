import boto3

def print_table(tables):
    idx_width = len(str(len(tables))) + 2
    name_width = max(len("Table Name"), *(len(table['TableName']) for table in tables)) + 2
    status_width = max(len("Status"), *(len(table['TableStatus']) for table in tables)) + 2
    creation_width = len("Creation Time") + 2

    # Header
    header = f"{'No.':<{idx_width}}{'Table Name':<{name_width}}{'Status':<{status_width}}{'Creation Time':<{creation_width}}"
    print(header)
    print('-' * (idx_width + name_width + status_width + creation_width))

    # Rows
    for idx, table in enumerate(tables, 1):
        # CreationDateTime is a datetime object
        from datetime import datetime
        creation = table['CreationDateTime'].strftime("%Y-%m-%d %H:%M:%S")
        print(f"{idx:<{idx_width}}{table['TableName']:<{name_width}}{table['TableStatus']:<{status_width}}{creation:<{creation_width}}")

def delete_table(client, table_name):
    try:
        client.delete_table(TableName=table_name)
        print(f"Table {table_name} deletion initiated successfully.")
    except Exception as e:
        print(f"Failed to delete table {table_name}: {e}")

def main():
    client = boto3.client('dynamodb')
    search_term = input("Enter the search term to find in table names (leave empty for all tables): ").strip()
    
    # Get all tables
    paginator = client.get_paginator('list_tables')
    table_names = []
    for page in paginator.paginate():
        table_names.extend(page.get('TableNames', []))
    
    # Filter by search term if provided (search anywhere in the name)
    if search_term:
        table_names = [name for name in table_names if search_term in name]
    
    if not table_names:
        if search_term:
            print(f"No tables found containing: {search_term}")
        else:
            print("No tables found.")
        return

    # Get detailed table information
    tables = []
    for table_name in table_names:
        try:
            response = client.describe_table(TableName=table_name)
            tables.append(response['Table'])
        except Exception as e:
            print(f"Warning: Could not describe table {table_name}: {e}")

    if not tables:
        print("No tables could be described.")
        return

    print(f"\nThe following {len(tables)} table(s) will be deleted:\n")
    print_table(tables)

    confirm = input("\nAre you sure you want to delete these tables? (yes/no): ")
    if confirm.lower() != 'yes':
        print("Aborted.")
        return

    for table in tables:
        print(f"Deleting table: {table['TableName']}")
        delete_table(client, table['TableName'])

    print(f"\nDeletion initiated for {len(tables)} table(s).")
    print("Note: DynamoDB table deletion is asynchronous and may take some time to complete.")

if __name__ == "__main__":
    main()