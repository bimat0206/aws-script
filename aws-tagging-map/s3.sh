#!/bin/bash

set -e

# Ensure jq is installed
if ! command -v jq &>/dev/null; then
    echo "Error: jq could not be found. Please install jq to proceed." >&2
    exit 1
fi

# Load tags from the JSON file
if [[ ! -f ./tags.json ]]; then
    echo "Error: tags.json file not found." >&2
    exit 1
fi

tags=$(jq -r '.Tags' ./tags.json)

# Function to format tags for aws resourcegroupstaggingapi
format_tags() {
    jq -r '.Tags | to_entries | map("\(.key)=\(.value)") | join(",")' ./tags.json
}

# Function to tag resources
tag_resources() {
    local bucket_name=$1
    local tag_set=$(format_tags)
    local arn="arn:aws:s3:::$bucket_name"

    echo "Tagging bucket: $bucket_name"
    if ! aws resourcegroupstaggingapi tag-resources --resource-arn-list "$arn" --tags "$tag_set" >/dev/null 2>&1; then
        echo "Warning: Failed to tag bucket $bucket_name" >&2
    fi
}

# Function to calculate and display progress
show_progress() {
    local current=$1
    local total=$2
    local percent=$(printf "%.2f" $(echo "scale=4; $current / $total * 100" | bc))
    printf "\rProgress: %d/%d (%.2f%%)" "$current" "$total" "$percent"
}

# Function to handle script interruption
cleanup() {
    echo -e "\nScript interrupted. Exiting gracefully..."
    exit 1
}

# Trap the interrupt signal (Ctrl+C)
trap cleanup SIGINT

# Get all S3 bucket names
buckets=$(aws s3api list-buckets --query 'Buckets[*].Name' --output text)
if [[ -z "$buckets" ]]; then
    echo "No S3 buckets found." >&2
    exit 1
fi

total_buckets=$(echo "$buckets" | wc -w)
current_count=0

# Tag all S3 buckets and show progress
for bucket in $buckets; do
    tag_resources "$bucket"
    ((current_count++))
    show_progress "$current_count" "$total_buckets"
done

echo -e "\nAll S3 buckets have been tagged."
