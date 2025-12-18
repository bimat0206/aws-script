#!/bin/bash

AWS_ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
AWS_REGION=$(aws configure get region)
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

# Function to get all API Gateway REST APIs
get_rest_apis() {
    aws apigateway get-rest-apis --query 'items[*].id' --output text
}

# Function to get all API Gateway HTTP APIs
get_http_apis() {
    aws apigatewayv2 get-apis --query 'Items[?ProtocolType==`HTTP`].ApiId' --output text
}

# Function to get all API Gateway custom domain names
get_custom_domain_names() {
    aws apigateway get-domain-names --query 'items[*].domainName' --output text
}

# Function to get all API Gateway VPC links
get_vpc_links() {
    aws apigateway get-vpc-links --query 'items[*].id' --output text
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

# Get all API Gateway REST APIs
rest_apis=$(get_rest_apis)
if [[ -z "$rest_apis" ]]; then
    echo "No API Gateway REST APIs found." >&2
    exit 1
fi

# Get all API Gateway HTTP APIs
http_apis=$(get_http_apis)
if [[ -z "$http_apis" ]]; then
    echo "No API Gateway HTTP APIs found." >&2
    exit 1
fi

# Get all API Gateway custom domain names
custom_domains=$(get_custom_domain_names)
if [[ -z "$custom_domains" ]]; then
    echo "No API Gateway custom domain names found." >&2
fi

# Get all API Gateway VPC links
vpc_links=$(get_vpc_links)
if [[ -z "$vpc_links" ]]; then
    echo "No API Gateway VPC links found." >&2
fi

total_resources=$(echo "$rest_apis $http_apis $custom_domains $vpc_links" | wc -w)
current_count=0

# Tag all API Gateway REST APIs and show progress
for api in $rest_apis; do
    resource_arn="arn:aws:apigateway:$AWS_REGION::/restapis/$api"
    tag_resources "$resource_arn"
    ((current_count++))
    show_progress "$current_count" "$total_resources"
done

# Tag all API Gateway HTTP APIs and show progress
for api in $http_apis; do
    resource_arn="arn:aws:apigateway:$AWS_REGION::/apis/$api"
    tag_resources "$resource_arn"
    ((current_count++))
    show_progress "$current_count" "$total_resources"
done

# Tag all API Gateway custom domain names and show progress
if [[ -n "$custom_domains" ]]; then
    for domain in $custom_domains; do
        resource_arn="arn:aws:apigateway:$AWS_REGION::/domainnames/$domain"
        tag_resources "$resource_arn"
        ((current_count++))
        show_progress "$current_count" "$total_resources"
    done
fi

# Tag all API Gateway VPC links and show progress
if [[ -n "$vpc_links" ]]; then
    for vpc_link in $vpc_links; do
        resource_arn="arn:aws:apigateway:$AWS_REGION::/vpclinks/$vpc_link"
        tag_resources "$resource_arn"
        ((current_count++))
        show_progress "$current_count" "$total_resources"
    done
fi

echo -e "\nAll API Gateway resources have been tagged."
