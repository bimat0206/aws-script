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
    local tag_set=$(jq -r '.Tags | to_entries | map({Key: .key, Value: .value})' ./tags.json)

    echo "Tagging resource: $resource_arn"
    if ! aws resourcegroupstaggingapi tag-resources --resource-arn-list "$resource_arn" --tags "$(format_tags)" >/dev/null 2>&1; then
        echo "Warning: Failed to tag resource $resource_arn" >&2
    fi
}

# Function to get OpenSearch domains
get_opensearch_domains() {
    aws opensearch list-domain-names --query 'DomainNames[*].DomainName' --output text
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

# Get all OpenSearch domains
domains=$(get_opensearch_domains)
if [[ -z "$domains" ]]; then
    echo "No OpenSearch domains found." >&2
    exit 1
fi

total_domains=$(echo "$domains" | wc -w)
current_count=0

# Tag all OpenSearch domains and show progress
for domain in $domains; do
    resource_arn="arn:aws:es:$(aws configure get region):$AWS_ACCOUNT_ID:domain/$domain"
    tag_resources "$resource_arn"
    ((current_count++))
    show_progress "$current_count" "$total_domains"
done

echo -e "\nAll OpenSearch domains have been tagged."
