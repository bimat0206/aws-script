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

# Function to format tags for aws network firewall
format_tags() {
    jq -r '.Tags | to_entries | map("{Key: \(.key), Value: \(.value)}") | join(",")' ./tags.json
}

# Function to tag resources
tag_resources() {
    local resource_arn=$1
    local tag_set=$(jq -r '.Tags | to_entries | map({Key: .key, Value: .value})' ./tags.json)

    echo "Tagging resource: $resource_arn"
    if ! aws network-firewall tag-resource --resource-arn "$resource_arn" --tags "$tag_set" >/dev/null 2>&1; then
        echo "Warning: Failed to tag resource $resource_arn" >&2
    fi
}

# Function to get Network Firewall resources
get_network_firewall_resources() {
    local firewalls=$(aws network-firewall list-firewalls --query 'Firewalls[*].FirewallArn' --output text)
    echo "$firewalls"
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

# Get all Network Firewall resources
firewall_resources=$(get_network_firewall_resources)
if [[ -z "$firewall_resources" ]]; then
    echo "No Network Firewall resources found." >&2
    exit 1
fi

total_firewalls=$(echo "$firewall_resources" | wc -w)
current_count=0

# Tag all Network Firewall resources and show progress
for firewall in $firewall_resources; do
    tag_resources "$firewall"
    ((current_count++))
    show_progress "$current_count" "$total_firewalls"
done

echo -e "\nAll Network Firewall resources have been tagged."
