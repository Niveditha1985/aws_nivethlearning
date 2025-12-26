# ============================================================================
# Security Account Variables
# ============================================================================

variable "aws_region" {
  description = "AWS region for security resources"
  type        = string
  default     = "us-east-1"
}

variable "security_account_id" {
  description = "AWS Account ID for Security & Audit account"
  type        = string
}

variable "management_account_id" {
  description = "AWS Account ID for Management account"
  type        = string
}

variable "member_account_ids" {
  description = "List of member account IDs in the organization"
  type        = list(string)
  default     = []
}

variable "bucket_prefix" {
  description = "Prefix for S3 bucket names (must be globally unique)"
  type        = string
  default     = "myapp-security"
}

variable "security_alert_emails" {
  description = "Email addresses to receive critical security alerts"
  type        = list(string)
  default     = []
  
  validation {
    condition = alltrue([
      for email in var.security_alert_emails :
      can(regex("^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$", email))
    ])
    error_message = "All email addresses must be valid."
  }
}

variable "cloudwatch_external_id" {
  description = "External ID for CloudWatch cross-account access"
  type        = string
  default     = "cloudwatch-security-logs"
  sensitive   = true
}

variable "security_readonly_external_id" {
  description = "External ID for security read-only role"
  type        = string
  default     = "security-readonly-access"
  sensitive   = true
}

variable "security_admin_external_id" {
  description = "External ID for security admin role"
  type        = string
  default     = "security-admin-access"
  sensitive   = true
}

variable "config_snapshot_frequency" {
  description = "Delivery frequency for AWS Config snapshots"
  type        = string
  default     = "TwentyFour_Hours"
  
  validation {
    condition = contains([
      "One_Hour",
      "Three_Hours",
      "Six_Hours",
      "Twelve_Hours",
      "TwentyFour_Hours"
    ], var.config_snapshot_frequency)
    error_message = "Config snapshot frequency must be a valid value."
  }
}

variable "guardduty_finding_frequency" {
  description = "Frequency to publish GuardDuty findings"
  type        = string
  default     = "FIFTEEN_MINUTES"
  
  validation {
    condition = contains([
      "FIFTEEN_MINUTES",
      "ONE_HOUR",
      "SIX_HOURS"
    ], var.guardduty_finding_frequency)
    error_message = "GuardDuty finding frequency must be FIFTEEN_MINUTES, ONE_HOUR, or SIX_HOURS."
  }
}

variable "enable_guardduty_s3_protection" {
  description = "Enable GuardDuty S3 protection"
  type        = bool
  default     = true
}

variable "enable_guardduty_kubernetes_protection" {
  description = "Enable GuardDuty Kubernetes protection"
  type        = bool
  default     = true
}

variable "enable_guardduty_malware_protection" {
  description = "Enable GuardDuty malware protection"
  type        = bool
  default     = true
}

variable "cloudtrail_log_retention_days" {
  description = "Number of days to retain CloudTrail logs before archiving"
  type        = number
  default     = 2555  # 7 years
}

variable "enable_access_analyzer" {
  description = "Enable IAM Access Analyzer"
  type        = bool
  default     = true
}

variable "tags" {
  description = "Additional tags to apply to all resources"
  type        = map(string)
  default     = {}
}
