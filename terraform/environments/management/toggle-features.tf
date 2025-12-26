# ============================================================================
# Feature Toggles - Turn expensive features on/off for cost control
# ============================================================================

# Toggle for AWS Config (saves ~$9/month when disabled)
variable "enable_aws_config" {
  description = "Enable AWS Config for compliance monitoring"
  type        = bool
  default     = false  # Set to true when ready for production
}

# Toggle for CloudTrail (saves ~$0.25/month when disabled, but NOT RECOMMENDED)
variable "enable_cloudtrail" {
  description = "Enable organization-wide CloudTrail"
  type        = bool
  default     = true  # Always keep enabled for security audit
}

# Toggle for AWS Budgets (free, but can disable email spam during testing)
variable "enable_budgets" {
  description = "Enable budget alerts"
  type        = bool
  default     = true  # Keep enabled to monitor costs
}

# Toggle for Config Rules individually
variable "enable_config_rule_encrypted_volumes" {
  description = "Enable config rule: encrypted-volumes"
  type        = bool
  default     = false
}

variable "enable_config_rule_rds_encryption" {
  description = "Enable config rule: rds-encryption"
  type        = bool
  default     = false
}

variable "enable_config_rule_s3_public_access" {
  description = "Enable config rules: s3 public access checks"
  type        = bool
  default     = false
}

variable "enable_config_rule_required_tags" {
  description = "Enable config rule: required-tags"
  type        = bool
  default     = false
}

variable "enable_config_rule_iam_password_policy" {
  description = "Enable config rule: iam-password-policy"
  type        = bool
  default     = false
}

# IMPORTANT: SCPs should ALWAYS be enabled for security
# They are FREE and protect your accounts
# If you want to disable for testing, set this to false
variable "enable_scps" {
  description = "Enable Service Control Policies (FREE, highly recommended)"
  type        = bool
  default     = true  # Keep enabled - SCPs are your safety net!
}
