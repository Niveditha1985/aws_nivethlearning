# ============================================================================
# Logging Account Variables
# ============================================================================

variable "aws_region" {
  description = "AWS region for logging resources"
  type        = string
  default     = "us-east-1"
}

variable "logging_account_id" {
  description = "AWS Account ID for Logging account"
  type        = string
}

variable "management_account_id" {
  description = "AWS Account ID for Management account"
  type        = string
}

variable "member_account_ids" {
  description = "List of member account IDs that will send logs to this account"
  type        = list(string)
  default     = []
}

variable "bucket_prefix" {
  description = "Prefix for S3 bucket names (must be globally unique)"
  type        = string
  default     = "myapp-logging"
}

variable "production_log_retention_days" {
  description = "Number of days to retain production logs in CloudWatch"
  type        = number
  default     = 365  # 1 year
  
  validation {
    condition = contains([
      0, 1, 3, 5, 7, 14, 30, 60, 90, 120, 150, 180,
      365, 400, 545, 731, 1827, 3653
    ], var.production_log_retention_days)
    error_message = "Log retention must be a valid CloudWatch Logs retention period."
  }
}

variable "nonproduction_log_retention_days" {
  description = "Number of days to retain non-production logs in CloudWatch"
  type        = number
  default     = 90  # 3 months
  
  validation {
    condition = contains([
      0, 1, 3, 5, 7, 14, 30, 60, 90, 120, 150, 180,
      365, 400, 545, 731, 1827, 3653
    ], var.nonproduction_log_retention_days)
    error_message = "Log retention must be a valid CloudWatch Logs retention period."
  }
}

variable "cross_account_external_id" {
  description = "External ID for cross-account CloudWatch Logs access"
  type        = string
  default     = "cloudwatch-logs-cross-account"
  sensitive   = true
}

variable "analytics_external_id" {
  description = "External ID for log analytics read-only access"
  type        = string
  default     = "log-analytics-readonly"
  sensitive   = true
}

variable "enable_cloudwatch_to_s3_export" {
  description = "Enable automatic export of CloudWatch Logs to S3 via Kinesis Firehose"
  type        = bool
  default     = true
}

variable "firehose_buffer_size_mb" {
  description = "Buffer size in MB for Kinesis Firehose (1-128)"
  type        = number
  default     = 5
  
  validation {
    condition     = var.firehose_buffer_size_mb >= 1 && var.firehose_buffer_size_mb <= 128
    error_message = "Firehose buffer size must be between 1 and 128 MB."
  }
}

variable "firehose_buffer_interval_seconds" {
  description = "Buffer interval in seconds for Kinesis Firehose (60-900)"
  type        = number
  default     = 300
  
  validation {
    condition     = var.firehose_buffer_interval_seconds >= 60 && var.firehose_buffer_interval_seconds <= 900
    error_message = "Firehose buffer interval must be between 60 and 900 seconds."
  }
}

variable "s3_archive_glacier_transition_days" {
  description = "Number of days before transitioning logs to Glacier storage"
  type        = number
  default     = 90
}

variable "s3_archive_deep_archive_transition_days" {
  description = "Number of days before transitioning logs to Deep Archive storage"
  type        = number
  default     = 365
}

variable "s3_archive_expiration_days" {
  description = "Number of days before expiring archived logs"
  type        = number
  default     = 2555  # 7 years
}

variable "vpc_flowlog_retention_days" {
  description = "Number of days to retain VPC flow logs before deletion"
  type        = number
  default     = 730  # 2 years
}

variable "alb_log_retention_days" {
  description = "Number of days to retain ALB access logs"
  type        = number
  default     = 90
}

variable "enable_log_encryption" {
  description = "Enable KMS encryption for CloudWatch Logs"
  type        = bool
  default     = true
}

variable "tags" {
  description = "Additional tags to apply to all resources"
  type        = map(string)
  default     = {}
}
