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

# Function to tag RDS instance
tag_rds_instance() {
    local instance_arn=$1
    local tag_set=$(format_tags)

    echo "Tagging RDS instance: $instance_arn"
    if ! aws resourcegroupstaggingapi tag-resources --resource-arn-list "$instance_arn" --tags "$tag_set" >/dev/null 2>&1; then
        echo "Warning: Failed to tag RDS instance $instance_arn" >&2
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

# Get all RDS instance ARNs
instances=$(aws rds describe-db-instances --query 'DBInstances[*].DBInstanceArn' --output text)
if [[ -z "$instances" ]]; then
    echo "No RDS instances found." >&2
    exit 1
fi

total_instances=$(echo "$instances" | wc -w)
current_count=0

# Tag all RDS instances and show progress
for instance in $instances; do
    tag_rds_instance "$instance"
    ((current_count++))
    show_progress "$current_count" "$total_instances"
done

echo -e "\nAll RDS instances have been tagged."
