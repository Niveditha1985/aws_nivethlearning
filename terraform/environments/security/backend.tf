# ============================================================================
# Security Account - Backend Configuration
# ============================================================================
# This file configures the Terraform state backend for the Security account
# ============================================================================

terraform {
  backend "s3" {
    # S3 bucket for storing Terraform state
    # This bucket should be created in the Management account
    bucket = "myapp-terraform-state"
    
    # State file path for Security account
    key = "security/terraform.tfstate"
    
    # AWS region where the state bucket is located
    region = "us-east-1"
    
    # Enable encryption at rest
    encrypt = true
    
    # DynamoDB table for state locking
    # Prevents concurrent Terraform runs from corrupting state
    dynamodb_table = "terraform-state-lock"
    
    # Assume role in Security account for state operations
    # This allows Terraform to write state even when running from Management account
    role_arn = "arn:aws:iam::SECURITY_ACCOUNT_ID:role/TerraformStateRole"
    
    # Optional: Enable versioning on the state file
    # workspace_key_prefix = "security"
  }
}

# ============================================================================
# Backend Configuration Notes
# ============================================================================
# 
# Prerequisites:
# 1. S3 bucket 'myapp-terraform-state' must exist in Management account
# 2. DynamoDB table 'terraform-state-lock' must exist in Management account
# 3. IAM role 'TerraformStateRole' must exist in Security account
# 4. Replace SECURITY_ACCOUNT_ID with actual account ID
#
# State Bucket Setup (run once in Management account):
#
# resource "aws_s3_bucket" "terraform_state" {
#   bucket = "myapp-terraform-state"
#   
#   lifecycle {
#     prevent_destroy = true
#   }
# }
#
# resource "aws_s3_bucket_versioning" "terraform_state" {
#   bucket = aws_s3_bucket.terraform_state.id
#   
#   versioning_configuration {
#     status = "Enabled"
#   }
# }
#
# resource "aws_s3_bucket_server_side_encryption_configuration" "terraform_state" {
#   bucket = aws_s3_bucket.terraform_state.id
#   
#   rule {
#     apply_server_side_encryption_by_default {
#       sse_algorithm = "AES256"
#     }
#   }
# }
#
# DynamoDB Table Setup (run once in Management account):
#
# resource "aws_dynamodb_table" "terraform_locks" {
#   name         = "terraform-state-lock"
#   billing_mode = "PAY_PER_REQUEST"
#   hash_key     = "LockID"
#   
#   attribute {
#     name = "LockID"
#     type = "S"
#   }
# }
#
# ============================================================================
