# ============================================================================
# Logging Account - Backend Configuration
# ============================================================================
# This file configures the Terraform state backend for the Logging account
# ============================================================================

terraform {
  backend "s3" {
    # S3 bucket for storing Terraform state
    # This bucket should be created in the Management account
    bucket = "myapp-terraform-state"
    
    # State file path for Logging account
    key = "logging/terraform.tfstate"
    
    # AWS region where the state bucket is located
    region = "us-east-1"
    
    # Enable encryption at rest
    encrypt = true
    
    # DynamoDB table for state locking
    # Prevents concurrent Terraform runs from corrupting state
    dynamodb_table = "terraform-state-lock"
    
    # Assume role in Logging account for state operations
    # This allows Terraform to write state even when running from Management account
    role_arn = "arn:aws:iam::LOGGING_ACCOUNT_ID:role/TerraformStateRole"
    
    # Optional: Enable versioning on the state file
    # workspace_key_prefix = "logging"
  }
}

# ============================================================================
# Backend Configuration Notes
# ============================================================================
# 
# Prerequisites:
# 1. S3 bucket 'myapp-terraform-state' must exist in Management account
# 2. DynamoDB table 'terraform-state-lock' must exist in Management account
# 3. IAM role 'TerraformStateRole' must exist in Logging account
# 4. Replace LOGGING_ACCOUNT_ID with actual account ID
#
# The state bucket and DynamoDB table should be created once in the
# Management account and shared across all accounts via cross-account roles.
#
# ============================================================================
