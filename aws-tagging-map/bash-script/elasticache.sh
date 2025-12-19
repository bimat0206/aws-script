#!/bin/bash

AWS_ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
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

# Function to format tags for aws resourcegroupstaggingapi
format_tags() {
    jq -r '.Tags | to_entries | map("\(.key)=\(.value)") | join(",")' ./tags.json
}

# Function to tag resources
tag_resources() {
    local resource_arn=$1
    local tag_set=$(format_tags)

    echo "Tagging resource: $resource_arn"
    if ! aws resourcegroupstaggingapi tag-resources --resource-arn-list "$resource_arn" --tags "$tag_set" >/dev/null 2>&1; then
        echo "Warning: Failed to tag resource $resource_arn" >&2
    fi
}

# Function to get ElastiCache clusters
get_elasticache_clusters() {
    aws elasticache describe-cache-clusters --query 'CacheClusters[*].ARN' --output text
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

# Get all ElastiCache clusters
clusters=$(get_elasticache_clusters)
if [[ -z "$clusters" ]]; then
    echo "No ElastiCache clusters found." >&2
    exit 1
fi

total_clusters=$(echo "$clusters" | wc -w)
current_count=0

# Tag all ElastiCache clusters and show progress
for cluster in $clusters; do
    tag_resources "$cluster"
    ((current_count++))
    show_progress "$current_count" "$total_clusters"
done

echo -e "\nAll ElastiCache clusters have been tagged."
