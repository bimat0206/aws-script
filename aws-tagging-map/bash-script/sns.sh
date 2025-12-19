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

# Function to tag SNS topic
tag_sns_topic() {
    local topic_arn=$1
    local tag_set=$(format_tags)

    echo "Tagging SNS topic: $topic_arn"
    if ! aws resourcegroupstaggingapi tag-resources --resource-arn-list "$topic_arn" --tags "$tag_set" >/dev/null 2>&1; then
        echo "Warning: Failed to tag SNS topic $topic_arn" >&2
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

# Get all SNS topic ARNs
topics=$(aws sns list-topics --query 'Topics[*].TopicArn' --output text)
if [[ -z "$topics" ]]; then
    echo "No SNS topics found." >&2
    exit 1
fi

total_topics=$(echo "$topics" | wc -w)
current_count=0

# Tag all SNS topics and show progress
for topic in $topics; do
    tag_sns_topic "$topic"
    ((current_count++))
    show_progress "$current_count" "$total_topics"
done

echo -e "\nAll SNS topics have been tagged."
