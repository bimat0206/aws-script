import boto3

def delete_all_images(ecr, repo_name):
    try:
        paginator = ecr.get_paginator('list_images')
        for page in paginator.paginate(repositoryName=repo_name):
            image_ids = page.get('imageIds', [])
            if image_ids:
                try:
                    ecr.batch_delete_image(repositoryName=repo_name, imageIds=image_ids)
                except Exception as e:
                    print(f"Error deleting images in {repo_name}: {e}")
    except Exception as e:
        print(f"Error listing images for {repo_name}: {e}")

def delete_repository(ecr, repo_name):
    delete_all_images(ecr, repo_name)
    try:
        ecr.delete_repository(repositoryName=repo_name, force=True)
        print(f"Repository {repo_name} deleted successfully.")
    except Exception as e:
        print(f"Failed to delete repository {repo_name}: {e}")

def print_table(repos):
    # Determine column widths
    idx_width = len(str(len(repos))) + 2
    name_width = max(len("Repository Name"), *(len(r['repositoryName']) for r in repos)) + 2
    uri_width = max(len("Repository URI"), *(len(r['repositoryUri']) for r in repos)) + 2

    # Header
    header = f"{'No.':<{idx_width}}{'Repository Name':<{name_width}}{'Repository URI':<{uri_width}}"
    print(header)
    print('-' * (idx_width + name_width + uri_width))

    # Rows
    for idx, repo in enumerate(repos, 1):
        print(f"{idx:<{idx_width}}{repo['repositoryName']:<{name_width}}{repo['repositoryUri']:<{uri_width}}")

def main():
    ecr = boto3.client('ecr')
    
    # First, list all ECR repositories
    print("Fetching all ECR repositories...\n")
    all_repos = []
    paginator = ecr.get_paginator('describe_repositories')
    for page in paginator.paginate():
        all_repos.extend(page['repositories'])
    
    if not all_repos:
        print("No ECR repositories found in this AWS account/region.")
        return
    
    # Display all repositories
    print(f"Found {len(all_repos)} ECR repositories:\n")
    print_table(all_repos)
    
    # Ask user for prefix
    print("\n" + "="*80)
    prefix = input("\nEnter the prefix of the ECR repository names to delete (or press Enter to cancel): ").strip()
    
    if not prefix:
        print("No prefix entered. Aborted.")
        return
    
    # Filter repositories by prefix
    repos = [repo for repo in all_repos if repo['repositoryName'].startswith(prefix)]

    if not repos:
        print(f"\nNo repositories found with prefix: '{prefix}'")
        return

    print(f"\nThe following {len(repos)} ECR repositories will be deleted:\n")
    print_table(repos)

    print("\n*Note: AWS ECR does not store the 'created by' information in repository metadata. "
          "To find out who created a repository, you must query CloudTrail logs if logging was enabled at the time of creation.*\n")

    confirm = input("Are you sure you want to delete these repositories? (yes/no): ")
    if confirm.lower() != 'yes':
        print("Aborted.")
        return

    for repo in repos:
        print(f"Deleting repository: {repo['repositoryName']}")
        delete_repository(ecr, repo['repositoryName'])

if __name__ == "__main__":
    main()
