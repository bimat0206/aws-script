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

# Specify the regions to process
regions=("ap-southeast-1" "us-east-1" "us-west-2")

total_load_balancers=0
current_count=0

# Tag all ALBs and NLBs in the specified regions
for region in "${regions[@]}"; do
    echo "Region: $region"

    # Get all ALB ARNs
    alb_arns=$(aws elbv2 describe-load-balancers --region "$region" --query 'LoadBalancers[*].LoadBalancerArn' --output text)
    if [[ -n "$alb_arns" ]]; then
        alb_arn_array=($alb_arns)
        total_load_balancers=$((total_load_balancers + ${#alb_arn_array[@]}))

        for alb_arn in "${alb_arn_array[@]}"; do
            tag_resources "$alb_arn"
            ((current_count++))
            show_progress "$current_count" "$total_load_balancers"
        done
    fi

    # Get all NLB ARNs
    nlb_arns=$(aws elbv2 describe-load-balancers --region "$region" --query 'LoadBalancers[?Type==`network`].LoadBalancerArn' --output text)
    if [[ -n "$nlb_arns" ]]; then
        nlb_arn_array=($nlb_arns)
        total_load_balancers=$((total_load_balancers + ${#nlb_arn_array[@]}))

        for nlb_arn in "${nlb_arn_array[@]}"; do
            tag_resources "$nlb_arn"
            ((current_count++))
            show_progress "$current_count" "$total_load_balancers"
        done
    fi
done

echo -e "\nAll Application Load Balancers and Network Load Balancers have been tagged."
