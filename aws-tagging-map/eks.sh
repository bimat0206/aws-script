#!/bin/bash

set -e

# Ensure jq is installed
if ! command -v jq &> /dev/null; then
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

# Function to tag EKS cluster
tag_eks_cluster() {
    local cluster_name=$1
    local tag_set=$(format_tags)
    local arn=$(aws eks describe-cluster --name "$cluster_name" --query 'cluster.arn' --output text)
    
    echo "Tagging EKS cluster: $cluster_name"
    if ! aws resourcegroupstaggingapi tag-resources --resource-arn-list "$arn" --tags "$tag_set" > /dev/null 2>&1; then
        echo "Warning: Failed to tag EKS cluster $cluster_name" >&2
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

# Get all EKS cluster names
clusters=$(aws eks list-clusters --query 'clusters[]' --output text)
if [[ -z "$clusters" ]]; then
    echo "No EKS clusters found." >&2
    exit 1
fi

total_clusters=$(echo "$clusters" | wc -w)
current_count=0

# Tag all EKS clusters and show progress
for cluster in $clusters; do
    tag_eks_cluster "$cluster"
    ((current_count++))
    show_progress "$current_count" "$total_clusters"
done

echo -e "\nAll EKS clusters have been tagged."