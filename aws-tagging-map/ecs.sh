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

tags=$(jq -r '.Tags' ./tags.json)

# Function to format tags for aws resourcegroupstaggingapi
format_tags() {
    jq -r '.Tags | to_entries | map("\(.key)=\(.value)") | join(",")' ./tags.json
}

# Function to tag resources
tag_resources() {
    local resource_arn=$1
    local tag_set=$(jq -r '.Tags | to_entries | map({Key: .key, Value: .value}) | from_entries' ./tags.json)

    echo "Tagging resource: $resource_arn"
    if ! aws resourcegroupstaggingapi tag-resources --resource-arn-list "$resource_arn" --tags "$tag_set" >/dev/null 2>&1; then
        echo "Warning: Failed to tag resource $resource_arn" >&2
    fi
}

# Function to get ECS clusters
get_ecs_clusters() {
    aws ecs list-clusters --query 'clusterArns' --output text
}

# Function to get ECS services in a cluster
get_ecs_services() {
    local cluster_arn=$1
    aws ecs list-services --cluster "$cluster_arn" --query 'serviceArns' --output text
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

# Get all ECS clusters
clusters=$(get_ecs_clusters)
if [[ -z "$clusters" ]]; then
    echo "No ECS clusters found." >&2
    exit 1
fi

total_clusters=$(echo "$clusters" | wc -w)
current_count=0

# Tag all ECS clusters and their services and show progress
for cluster in $clusters; do
    tag_resources "$cluster"
    services=$(get_ecs_services "$cluster")
    for service in $services; do
        tag_resources "$service"
    done
    ((current_count++))
    show_progress "$current_count" "$total_clusters"
done

echo -e "\nAll ECS clusters and services have been tagged."
