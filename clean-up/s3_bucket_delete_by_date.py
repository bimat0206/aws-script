import boto3
from datetime import datetime
from collections import defaultdict

def get_buckets_by_year(client, year):
    """Get all buckets created in the specified year, grouped by month"""
    try:
        response = client.list_buckets()
        buckets = response.get('Buckets', [])
        
        # Group buckets by month for the specified year
        monthly_buckets = defaultdict(list)
        
        for bucket in buckets:
            creation_date = bucket['CreationDate']
            if creation_date.year == year:
                month = creation_date.month
                monthly_buckets[month].append(bucket)
        
        return monthly_buckets
    except Exception as e:
        print(f"Error retrieving buckets: {e}")
        return {}

def print_monthly_summary(monthly_buckets, year):
    """Print summary of buckets by month"""
    month_names = [
        "January", "February", "March", "April", "May", "June",
        "July", "August", "September", "October", "November", "December"
    ]
    
    print(f"\nBucket summary for year {year}:")
    print("-" * 40)
    print(f"{'Month':<12} {'Count':<8} {'Option'}")
    print("-" * 40)
    
    total_buckets = 0
    for month in range(1, 13):
        count = len(monthly_buckets.get(month, []))
        total_buckets += count
        if count > 0:
            print(f"{month_names[month-1]:<12} {count:<8} [{month}]")
    
    print("-" * 40)
    print(f"{'Total':<12} {total_buckets}")
    print()

def print_bucket_list(buckets, month_name):
    """Print detailed list of buckets for selection"""
    print(f"\nBuckets created in {month_name}:")
    print("-" * 80)
    
    idx_width = len(str(len(buckets))) + 2
    name_width = max(len("Bucket Name"), *(len(bucket['Name']) for bucket in buckets)) + 2
    date_width = len("Creation Date") + 2
    
    # Header
    header = f"{'No.':<{idx_width}}{'Bucket Name':<{name_width}}{'Creation Date':<{date_width}}"
    print(header)
    print('-' * (idx_width + name_width + date_width))
    
    # Rows
    for idx, bucket in enumerate(buckets, 1):
        creation_date = bucket['CreationDate'].strftime("%Y-%m-%d %H:%M:%S")
        print(f"{idx:<{idx_width}}{bucket['Name']:<{name_width}}{creation_date:<{date_width}}")
    
    print()

def get_bucket_selection(buckets):
    """Get user selection of buckets to delete"""
    while True:
        selection = input("Enter bucket numbers to delete (comma-separated, e.g., 1,3,5) or 'all' for all buckets: ").strip()
        
        if selection.lower() == 'all':
            return buckets
        
        try:
            indices = [int(x.strip()) for x in selection.split(',')]
            selected_buckets = []
            
            for idx in indices:
                if 1 <= idx <= len(buckets):
                    selected_buckets.append(buckets[idx - 1])
                else:
                    print(f"Invalid bucket number: {idx}. Please try again.")
                    break
            else:
                return selected_buckets
                
        except ValueError:
            print("Invalid input. Please enter numbers separated by commas or 'all'.")

def check_bucket_empty(client, bucket_name):
    """Check if bucket is empty"""
    try:
        response = client.list_objects_v2(Bucket=bucket_name, MaxKeys=1)
        return response.get('KeyCount', 0) == 0
    except Exception as e:
        print(f"Warning: Could not check if bucket {bucket_name} is empty: {e}")
        return False

def delete_bucket(client, bucket_name):
    """Delete a single bucket"""
    try:
        # Check if bucket is empty
        if not check_bucket_empty(client, bucket_name):
            print(f"Warning: Bucket {bucket_name} is not empty. Skipping deletion.")
            print("Note: S3 buckets must be empty before they can be deleted.")
            return False
        
        client.delete_bucket(Bucket=bucket_name)
        print(f"Bucket {bucket_name} deleted successfully.")
        return True
    except Exception as e:
        print(f"Failed to delete bucket {bucket_name}: {e}")
        return False

def main():
    client = boto3.client('s3')
    
    # Get year input
    while True:
        try:
            year_input = input("Enter the year to search for buckets (e.g., 2023): ").strip()
            year = int(year_input)
            if year < 2000 or year > datetime.now().year:
                print(f"Please enter a valid year between 2000 and {datetime.now().year}")
                continue
            break
        except ValueError:
            print("Please enter a valid year (numeric value)")
    
    # Get buckets grouped by month
    print(f"Retrieving buckets created in {year}...")
    monthly_buckets = get_buckets_by_year(client, year)
    
    if not monthly_buckets:
        print(f"No buckets found created in {year}")
        return
    
    # Show monthly summary
    print_monthly_summary(monthly_buckets, year)
    
    # Get month selection
    while True:
        try:
            month_input = input("Enter the month number to view buckets (1-12): ").strip()
            month = int(month_input)
            if 1 <= month <= 12:
                if month in monthly_buckets:
                    break
                else:
                    print(f"No buckets found for month {month}")
                    continue
            else:
                print("Please enter a month number between 1 and 12")
        except ValueError:
            print("Please enter a valid month number")
    
    # Show buckets for selected month
    month_names = [
        "January", "February", "March", "April", "May", "June",
        "July", "August", "September", "October", "November", "December"
    ]
    selected_buckets = monthly_buckets[month]
    month_name = month_names[month - 1]
    
    print_bucket_list(selected_buckets, month_name)
    
    # Get bucket selection for deletion
    buckets_to_delete = get_bucket_selection(selected_buckets)
    
    if not buckets_to_delete:
        print("No buckets selected for deletion.")
        return
    
    # Show selected buckets and confirm
    print(f"\nThe following {len(buckets_to_delete)} bucket(s) will be deleted:")
    print("-" * 50)
    for bucket in buckets_to_delete:
        creation_date = bucket['CreationDate'].strftime("%Y-%m-%d %H:%M:%S")
        print(f"- {bucket['Name']} (created: {creation_date})")
    
    print("\nWARNING: This action cannot be undone!")
    print("Note: Only empty buckets can be deleted. Non-empty buckets will be skipped.")
    
    confirm = input("\nAre you sure you want to delete these buckets? (yes/no): ")
    if confirm.lower() != 'yes':
        print("Aborted.")
        return
    
    # Delete selected buckets
    successful_deletions = 0
    for bucket in buckets_to_delete:
        print(f"\nDeleting bucket: {bucket['Name']}")
        if delete_bucket(client, bucket['Name']):
            successful_deletions += 1
    
    print(f"\nDeletion completed. {successful_deletions} out of {len(buckets_to_delete)} bucket(s) deleted successfully.")
    
    if successful_deletions < len(buckets_to_delete):
        print("Some buckets could not be deleted. Common reasons:")
        print("- Bucket is not empty (contains objects)")
        print("- Insufficient permissions")
        print("- Bucket has versioning enabled with versions")
        print("- Bucket has delete protection enabled")

if __name__ == "__main__":
    main()