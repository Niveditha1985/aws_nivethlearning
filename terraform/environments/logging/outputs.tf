# ============================================================================
# Logging Account Outputs
# ============================================================================

# ============================================================================
# CloudWatch Log Group Outputs
# ============================================================================

output "eks_prod_application_log_group" {
  description = "Name of the EKS production application log group"
  value       = aws_cloudwatch_log_group.eks_prod_application.name
}

output "eks_prod_dataplane_log_group" {
  description = "Name of the EKS production dataplane log group"
  value       = aws_cloudwatch_log_group.eks_prod_dataplane.name
}

output "eks_nonprod_application_log_group" {
  description = "Name of the EKS non-prod application log group"
  value       = aws_cloudwatch_log_group.eks_nonprod_application.name
}

output "rds_prod_log_group" {
  description = "Name of the RDS production log group"
  value       = aws_cloudwatch_log_group.rds_prod_postgres.name
}

output "vpc_flowlogs_prod_apps_log_group" {
  description = "Name of the VPC flow logs group for production apps"
  value       = aws_cloudwatch_log_group.vpc_flowlogs_prod_apps.name
}

output "vpc_flowlogs_prod_data_log_group" {
  description = "Name of the VPC flow logs group for production data"
  value       = aws_cloudwatch_log_group.vpc_flowlogs_prod_data.name
}

# Map of all log groups for easy reference
output "log_groups" {
  description = "Map of all CloudWatch Log Groups"
  value = {
    eks_prod_application      = aws_cloudwatch_log_group.eks_prod_application.name
    eks_prod_dataplane        = aws_cloudwatch_log_group.eks_prod_dataplane.name
    eks_prod_host            = aws_cloudwatch_log_group.eks_prod_host.name
    eks_nonprod_application   = aws_cloudwatch_log_group.eks_nonprod_application.name
    eks_nonprod_dataplane     = aws_cloudwatch_log_group.eks_nonprod_dataplane.name
    rds_prod_postgres         = aws_cloudwatch_log_group.rds_prod_postgres.name
    rds_nonprod_postgres      = aws_cloudwatch_log_group.rds_nonprod_postgres.name
    vpc_flowlogs_prod_apps    = aws_cloudwatch_log_group.vpc_flowlogs_prod_apps.name
    vpc_flowlogs_prod_data    = aws_cloudwatch_log_group.vpc_flowlogs_prod_data.name
    vpc_flowlogs_nonprod_apps = aws_cloudwatch_log_group.vpc_flowlogs_nonprod_apps.name
    vpc_flowlogs_nonprod_data = aws_cloudwatch_log_group.vpc_flowlogs_nonprod_data.name
    lambda                    = aws_cloudwatch_log_group.lambda_logs.name
    api_gateway               = aws_cloudwatch_log_group.api_gateway_logs.name
  }
}

# ============================================================================
# S3 Bucket Outputs
# ============================================================================

output "cloudwatch_archive_bucket_name" {
  description = "Name of the S3 bucket for CloudWatch Logs archive"
  value       = aws_s3_bucket.cloudwatch_archive.id
}

output "cloudwatch_archive_bucket_arn" {
  description = "ARN of the S3 bucket for CloudWatch Logs archive"
  value       = aws_s3_bucket.cloudwatch_archive.arn
}

output "vpc_flowlogs_bucket_name" {
  description = "Name of the S3 bucket for VPC flow logs"
  value       = aws_s3_bucket.vpc_flowlogs.id
}

output "vpc_flowlogs_bucket_arn" {
  description = "ARN of the S3 bucket for VPC flow logs"
  value       = aws_s3_bucket.vpc_flowlogs.arn
}

output "alb_accesslogs_bucket_name" {
  description = "Name of the S3 bucket for ALB access logs"
  value       = aws_s3_bucket.alb_accesslogs.id
}

output "alb_accesslogs_bucket_arn" {
  description = "ARN of the S3 bucket for ALB access logs"
  value       = aws_s3_bucket.alb_accesslogs.arn
}

# ============================================================================
# KMS Key Outputs
# ============================================================================

output "cloudwatch_logs_kms_key_id" {
  description = "ID of the KMS key for CloudWatch Logs encryption"
  value       = aws_kms_key.cloudwatch_logs.id
}

output "cloudwatch_logs_kms_key_arn" {
  description = "ARN of the KMS key for CloudWatch Logs encryption"
  value       = aws_kms_key.cloudwatch_logs.arn
}

# ============================================================================
# IAM Role Outputs
# ============================================================================

output "cross_account_logs_role_arn" {
  description = "ARN of the cross-account CloudWatch Logs write role"
  value       = aws_iam_role.allow_member_accounts_write_logs.arn
}

output "vpc_flow_logs_role_arn" {
  description = "ARN of the VPC Flow Logs role"
  value       = aws_iam_role.vpc_flow_logs.arn
}

output "log_analytics_readonly_role_arn" {
  description = "ARN of the log analytics read-only role"
  value       = aws_iam_role.log_analytics_readonly.arn
}

# ============================================================================
# Kinesis Firehose Outputs
# ============================================================================

output "firehose_delivery_stream_name" {
  description = "Name of the Kinesis Firehose delivery stream"
  value       = aws_kinesis_firehose_delivery_stream.cloudwatch_to_s3.name
}

output "firehose_delivery_stream_arn" {
  description = "ARN of the Kinesis Firehose delivery stream"
  value       = aws_kinesis_firehose_delivery_stream.cloudwatch_to_s3.arn
}

# ============================================================================
# Cross-Account Configuration Outputs
# ============================================================================

output "cross_account_configuration" {
  description = "Configuration details for member accounts to send logs"
  value = {
    role_arn    = aws_iam_role.allow_member_accounts_write_logs.arn
    external_id = var.cross_account_external_id
    region      = var.aws_region
    
    log_group_examples = {
      eks_application = aws_cloudwatch_log_group.eks_prod_application.name
      vpc_flowlogs    = aws_cloudwatch_log_group.vpc_flowlogs_prod_apps.name
      rds_logs        = aws_cloudwatch_log_group.rds_prod_postgres.name
    }
  }
  sensitive = true
}

# ============================================================================
# Summary Output
# ============================================================================

output "logging_account_summary" {
  description = "Summary of logging account resources"
  value = {
    account_id           = var.logging_account_id
    region               = var.aws_region
    total_log_groups     = 13
    s3_buckets_created   = 3
    retention_production = "${var.production_log_retention_days} days"
    retention_nonprod    = "${var.nonproduction_log_retention_days} days"
  }
}
