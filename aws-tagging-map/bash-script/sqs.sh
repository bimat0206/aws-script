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
    local tag_set=$(format_tags)

    echo "Tagging resource: $resource_arn"
    if ! aws resourcegroupstaggingapi tag-resources --resource-arn-list "$resource_arn" --tags "$tag_set" >/dev/null 2>&1; then
        echo "Warning: Failed to tag resource $resource_arn" >&2
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

# Get all SQS queue URLs
sqs_queue_urls=$(aws sqs list-queues --query 'QueueUrls' --output text)
if [[ -z "$sqs_queue_urls" ]]; then
    echo "No SQS queues found." >&2
    exit 1
fi

sqs_queue_url_array=($sqs_queue_urls)
total_queues=${#sqs_queue_url_array[@]}
current_count=0

# Tag all SQS queues and show progress
for sqs_queue_url in "${sqs_queue_url_array[@]}"; do
    sqs_queue_arn=$(aws sqs get-queue-attributes --queue-url "$sqs_queue_url" --attribute-names QueueArn --query 'Attributes.QueueArn' --output text)
    tag_resources "$sqs_queue_arn"
    ((current_count++))
    show_progress "$current_count" "$total_queues"
done

echo -e "\nAll SQS queues have been tagged."
