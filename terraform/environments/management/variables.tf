variable "aws_region" {
  description = "Primary AWS region for the infrastructure"
  type        = string
  default     = "us-east-1"
}

variable "organization_name" {
  description = "Name of the AWS Organization"
  type        = string
  default     = "MyApp"
}

variable "management_account_email" {
  description = "Email address for the management account (root account)"
  type        = string
}

variable "security_account_email" {
  description = "Email address for the security & audit account"
  type        = string
}

variable "shared_services_account_email" {
  description = "Email address for the shared services account"
  type        = string
}

variable "prod_apps_account_email" {
  description = "Email address for the production apps account"
  type        = string
}

variable "prod_data_account_email" {
  description = "Email address for the production data account"
  type        = string
}

variable "nonprod_apps_account_email" {
  description = "Email address for the non-production apps account"
  type        = string
}

variable "nonprod_data_account_email" {
  description = "Email address for the non-production data account"
  type        = string
}

variable "logging_account_email" {
  description = "Email address for the logging account"
  type        = string
}

variable "monthly_budget_limit" {
  description = "Monthly budget limit in USD for cost alerts"
  type        = number
  default     = 3000
}

variable "project_name" {
  description = "Project name for tagging"
  type        = string
  default     = "myapp"
}

variable "environment" {
  description = "Environment name"
  type        = string
  default     = "management"
}

variable "common_tags" {
  description = "Common tags to apply to all resources"
  type        = map(string)
  default = {
    Project    = "myapp"
    ManagedBy  = "terraform"
    Team       = "devops"
    CostCenter = "engineering-ops"
  }
}

# ============================================================================
# CloudTrail Configuration (Centralized in Security Account)
# ============================================================================

variable "cloudtrail_bucket_name" {
  description = "Name of the S3 bucket for CloudTrail logs (created in Security account)"
  type        = string
}

variable "cloudtrail_kms_key_arn" {
  description = "ARN of the KMS key for CloudTrail encryption (from Security account)"
  type        = string
}
