import boto3
import time


def _chunks(lst, n):
    """Yield successive n-sized chunks from lst."""
    for i in range(0, len(lst), n):
        yield lst[i:i + n]


def delete_bucket_contents(s3, bucket_name, max_retries=5, sleep_seconds=1):
    """Delete all objects in a bucket, including all versions and delete markers.

    This function will:
    - Attempt to delete object versions and delete markers using list_object_versions.
    - Also delete any remaining current objects using list_objects_v2.
    - Repeat up to `max_retries` times to handle eventual consistency.
    """
    for attempt in range(1, max_retries + 1):
        made_change = False

        # Try deleting versions and delete markers (if any)
        try:
            paginator = s3.get_paginator('list_object_versions')
            for page in paginator.paginate(Bucket=bucket_name):
                versions = page.get('Versions', [])
                delete_markers = page.get('DeleteMarkers', [])
                items = []
                for v in versions:
                    items.append({'Key': v['Key'], 'VersionId': v['VersionId']})
                for dm in delete_markers:
                    items.append({'Key': dm['Key'], 'VersionId': dm['VersionId']})

                if items:
                    made_change = True
                    # delete_objects supports up to 1000 objects per call
                    for chunk in _chunks(items, 1000):
                        try:
                            resp = s3.delete_objects(Bucket=bucket_name, Delete={'Objects': chunk, 'Quiet': True})
                        except Exception as e:
                            print(f"Error deleting versions/delete markers in {bucket_name}: {e}")
        except Exception as e:
            # list_object_versions can fail for non-versioned buckets or permissions issues
            # We'll ignore and fall back to list_objects_v2 below
            # Print for visibility but continue
            print(f"Warning: could not list object versions for {bucket_name}: {e}")

        # Delete non-versioned (current) objects
        try:
            paginator2 = s3.get_paginator('list_objects_v2')
            for page in paginator2.paginate(Bucket=bucket_name):
                contents = page.get('Contents', [])
                if contents:
                    made_change = True
                    objects_to_delete = [{'Key': obj['Key']} for obj in contents]
                    for chunk in _chunks(objects_to_delete, 1000):
                        try:
                            s3.delete_objects(Bucket=bucket_name, Delete={'Objects': chunk, 'Quiet': True})
                        except Exception as e:
                            print(f"Error deleting objects in {bucket_name}: {e}")
        except Exception as e:
            print(f"Warning: could not list objects for {bucket_name}: {e}")

        # If nothing was found to delete, bucket is likely empty
        if not made_change:
            # Double-check there's truly nothing left (versions or objects)
            try:
                # Check versions
                v_resp = s3.list_object_versions(Bucket=bucket_name)
                has_versions = bool(v_resp.get('Versions') or v_resp.get('DeleteMarkers'))
            except Exception:
                has_versions = False

            try:
                o_resp = s3.list_objects_v2(Bucket=bucket_name)
                has_objects = 'Contents' in o_resp and bool(o_resp['Contents'])
            except Exception:
                has_objects = False

            if not has_versions and not has_objects:
                return
            else:
                # If there are still items, mark that we should retry
                made_change = True

        # If we made deletions or found items, sleep briefly before retrying
        if made_change:
            # Small backoff to allow S3 eventual consistency
            time.sleep(sleep_seconds)

    # After retries, still might have items; one last attempt to report remaining objects
    try:
        v_resp = s3.list_object_versions(Bucket=bucket_name)
        remaining = (v_resp.get('Versions', []) + v_resp.get('DeleteMarkers', []))
        if remaining:
            print(f"Warning: after retries there are still {len(remaining)} versioned items in {bucket_name}")
    except Exception:
        pass

    try:
        o_resp = s3.list_objects_v2(Bucket=bucket_name)
        if 'Contents' in o_resp and o_resp['Contents']:
            print(f"Warning: after retries there are still {len(o_resp['Contents'])} objects in {bucket_name}")
    except Exception:
        pass

def delete_bucket(s3, bucket_name):
    delete_bucket_contents(s3, bucket_name)
    try:
        s3.delete_bucket(Bucket=bucket_name)
        print(f"Bucket {bucket_name} deleted successfully.")
    except Exception as e:
        print(f"Failed to delete bucket {bucket_name}: {e}")

def print_table(buckets):
    # Determine column widths
    idx_width = len(str(len(buckets))) + 2
    name_width = max(len("Bucket Name"), *(len(b['Name']) for b in buckets)) + 2
    date_width = len("Creation Date") + 2

    # Header
    header = f"{'No.':<{idx_width}}{'Bucket Name':<{name_width}}{'Creation Date':<{date_width}}"
    print(header)
    print('-' * (idx_width + name_width + date_width))

    # Rows
    for idx, bucket in enumerate(buckets, 1):
        creation = bucket['CreationDate'].strftime("%Y-%m-%d %H:%M:%S")
        print(f"{idx:<{idx_width}}{bucket['Name']:<{name_width}}{creation:<{date_width}}")

def main():
    s3 = boto3.client('s3')
    prefix = input("Enter the prefix of the bucket names to search: ").strip()
    response = s3.list_buckets()
    buckets = response['Buckets']
    buckets_to_delete = [
        {
            'Name': bucket['Name'],
            'CreationDate': bucket['CreationDate']
        }
        for bucket in buckets if prefix in bucket['Name']
    ]

    if not buckets_to_delete:
        print("No buckets found with prefix:", prefix)
        return

    print("\nThe following buckets will be deleted:\n")
    print_table(buckets_to_delete)

    print("\n*Note: AWS does not store the 'created by' information in S3 bucket metadata. "
          "To find out who created a bucket, you must query CloudTrail logs if logging was enabled at the time of creation.*\n")

    confirm = input("Are you sure you want to delete these buckets? (yes/no): ")
    if confirm.lower() != 'yes':
        print("Aborted.")
        return

    for bucket in buckets_to_delete:
        print(f"Deleting bucket: {bucket['Name']}")
        delete_bucket(s3, bucket['Name'])

if __name__ == "__main__":
    main()
