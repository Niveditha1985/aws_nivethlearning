# ============================================================================
# Security Account Outputs
# ============================================================================

# ============================================================================
# S3 Bucket Outputs
# ============================================================================

output "cloudtrail_bucket_name" {
  description = "Name of the S3 bucket for CloudTrail logs"
  value       = aws_s3_bucket.cloudtrail_logs.id
}

output "cloudtrail_bucket_arn" {
  description = "ARN of the S3 bucket for CloudTrail logs"
  value       = aws_s3_bucket.cloudtrail_logs.arn
}

output "config_bucket_name" {
  description = "Name of the S3 bucket for AWS Config logs"
  value       = aws_s3_bucket.config_logs.id
}

output "config_bucket_arn" {
  description = "ARN of the S3 bucket for AWS Config logs"
  value       = aws_s3_bucket.config_logs.arn
}

output "guardduty_bucket_name" {
  description = "Name of the S3 bucket for GuardDuty findings"
  value       = aws_s3_bucket.guardduty_findings.id
}

output "guardduty_bucket_arn" {
  description = "ARN of the S3 bucket for GuardDuty findings"
  value       = aws_s3_bucket.guardduty_findings.arn
}

# ============================================================================
# KMS Key Outputs
# ============================================================================

output "cloudtrail_kms_key_id" {
  description = "ID of the KMS key for CloudTrail encryption"
  value       = aws_kms_key.cloudtrail.id
}

output "cloudtrail_kms_key_arn" {
  description = "ARN of the KMS key for CloudTrail encryption"
  value       = aws_kms_key.cloudtrail.arn
}

output "guardduty_kms_key_id" {
  description = "ID of the KMS key for GuardDuty encryption"
  value       = aws_kms_key.guardduty.id
}

output "guardduty_kms_key_arn" {
  description = "ARN of the KMS key for GuardDuty encryption"
  value       = aws_kms_key.guardduty.arn
}

output "sns_kms_key_id" {
  description = "ID of the KMS key for SNS encryption"
  value       = aws_kms_key.sns.id
}

output "sns_kms_key_arn" {
  description = "ARN of the KMS key for SNS encryption"
  value       = aws_kms_key.sns.arn
}

# ============================================================================
# Security Service Outputs
# ============================================================================

output "guardduty_detector_id" {
  description = "ID of the GuardDuty detector"
  value       = aws_guardduty_detector.main.id
}

output "securityhub_account_id" {
  description = "Security Hub account ID"
  value       = aws_securityhub_account.main.id
}

output "config_recorder_name" {
  description = "Name of the AWS Config recorder"
  value       = aws_config_configuration_recorder.main.name
}

output "config_aggregator_arn" {
  description = "ARN of the AWS Config aggregator"
  value       = aws_config_configuration_aggregator.organization.arn
}

output "access_analyzer_arn" {
  description = "ARN of the IAM Access Analyzer"
  value       = aws_accessanalyzer_analyzer.organization.arn
}

# ============================================================================
# SNS Topic Outputs
# ============================================================================

output "critical_findings_topic_arn" {
  description = "ARN of the SNS topic for critical security findings"
  value       = aws_sns_topic.critical_findings.arn
}

output "high_findings_topic_arn" {
  description = "ARN of the SNS topic for high severity findings"
  value       = aws_sns_topic.high_findings.arn
}

# ============================================================================
# IAM Role Outputs
# ============================================================================

output "config_role_arn" {
  description = "ARN of the AWS Config IAM role"
  value       = aws_iam_role.config.arn
}

output "config_aggregator_role_arn" {
  description = "ARN of the AWS Config aggregator IAM role"
  value       = aws_iam_role.config_aggregator.arn
}

output "cloudwatch_cross_account_role_arn" {
  description = "ARN of the CloudWatch cross-account access role"
  value       = aws_iam_role.cloudwatch_cross_account.arn
}

output "security_readonly_role_arn" {
  description = "ARN of the security read-only role"
  value       = aws_iam_role.security_readonly.arn
}

output "security_admin_role_arn" {
  description = "ARN of the security admin role"
  value       = aws_iam_role.security_admin.arn
}

# ============================================================================
# EventBridge Rule Outputs
# ============================================================================

output "guardduty_event_rule_arn" {
  description = "ARN of the EventBridge rule for GuardDuty findings"
  value       = aws_cloudwatch_event_rule.guardduty_findings.arn
}

output "securityhub_event_rule_arn" {
  description = "ARN of the EventBridge rule for Security Hub findings"
  value       = aws_cloudwatch_event_rule.securityhub_findings.arn
}

# ============================================================================
# Config Rule Outputs
# ============================================================================

output "config_rules" {
  description = "Map of AWS Config rule names and ARNs"
  value = {
    encrypted_volumes                  = aws_config_config_rule.encrypted_volumes.arn
    rds_encryption_enabled            = aws_config_config_rule.rds_encryption_enabled.arn
    s3_bucket_public_read_prohibited  = aws_config_config_rule.s3_bucket_public_read_prohibited.arn
    s3_bucket_public_write_prohibited = aws_config_config_rule.s3_bucket_public_write_prohibited.arn
    required_tags                     = aws_config_config_rule.required_tags.arn
    iam_password_policy               = aws_config_config_rule.iam_password_policy.arn
  }
}
