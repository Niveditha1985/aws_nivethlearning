# ============================================================================
# Outputs
# ============================================================================

output "organization_id" {
  description = "AWS Organization ID"
  value       = aws_organizations_organization.main.id
}

output "organization_arn" {
  description = "AWS Organization ARN"
  value       = aws_organizations_organization.main.arn
}

output "organization_root_id" {
  description = "Root ID of the organization"
  value       = aws_organizations_organization.main.roots[0].id
}

# ============================================================================
# Organizational Units
# ============================================================================

output "ou_security_id" {
  description = "Security OU ID"
  value       = aws_organizations_organizational_unit.security.id
}

output "ou_infrastructure_id" {
  description = "Infrastructure OU ID"
  value       = aws_organizations_organizational_unit.infrastructure.id
}

output "ou_workloads_production_id" {
  description = "Workloads-Production OU ID"
  value       = aws_organizations_organizational_unit.workloads_production.id
}

output "ou_workloads_nonproduction_id" {
  description = "Workloads-NonProduction OU ID"
  value       = aws_organizations_organizational_unit.workloads_nonproduction.id
}

# ============================================================================
# Account IDs
# ============================================================================

output "management_account_id" {
  description = "Management account ID"
  value       = local.account_id
}

output "security_account_id" {
  description = "Security & Audit account ID"
  value       = aws_organizations_account.security.id
}

output "shared_services_account_id" {
  description = "Shared Services account ID"
  value       = aws_organizations_account.shared_services.id
}

output "logging_account_id" {
  description = "Logging account ID"
  value       = aws_organizations_account.logging.id
}

output "prod_apps_account_id" {
  description = "Production Apps account ID"
  value       = aws_organizations_account.prod_apps.id
}

output "prod_data_account_id" {
  description = "Production Data account ID"
  value       = aws_organizations_account.prod_data.id
}

output "nonprod_apps_account_id" {
  description = "NonProd Apps account ID"
  value       = aws_organizations_account.nonprod_apps.id
}

output "nonprod_data_account_id" {
  description = "NonProd Data account ID"
  value       = aws_organizations_account.nonprod_data.id
}

# ============================================================================
# S3 Buckets
# ============================================================================

output "cloudtrail_bucket_name" {
  description = "CloudTrail S3 bucket name"
  value       = aws_s3_bucket.cloudtrail.id
}

output "cloudtrail_bucket_arn" {
  description = "CloudTrail S3 bucket ARN"
  value       = aws_s3_bucket.cloudtrail.arn
}

output "config_bucket_name" {
  description = "Config S3 bucket name"
  value       = aws_s3_bucket.config.id
}

output "config_bucket_arn" {
  description = "Config S3 bucket ARN"
  value       = aws_s3_bucket.config.arn
}

# ============================================================================
# CloudTrail
# ============================================================================

output "cloudtrail_name" {
  description = "CloudTrail name"
  value       = aws_cloudtrail.organization.name
}

output "cloudtrail_arn" {
  description = "CloudTrail ARN"
  value       = aws_cloudtrail.organization.arn
}

# ============================================================================
# SNS Topics
# ============================================================================

output "budget_alerts_topic_arn" {
  description = "SNS topic ARN for budget alerts"
  value       = aws_sns_topic.budget_alerts.arn
}

# ============================================================================
# Important Information
# ============================================================================

output "important_notes" {
  description = "Important information about next steps"
  value = {
    message = "Bootstrap complete! Next steps:"
    step_1  = "Save these outputs to a secure location"
    step_2  = "Subscribe to the budget alerts SNS topic via email"
    step_3  = "Access member accounts using OrganizationAccountAccessRole"
    step_4  = "Begin configuring individual accounts (start with Security account)"
    step_5  = "Set up MFA on all account root users"
  }
}

# ============================================================================
# Account Access Commands
# ============================================================================

output "account_access_commands" {
  description = "AWS CLI commands to assume roles in member accounts"
  value = {
    security_account = "aws sts assume-role --role-arn arn:aws:iam::${aws_organizations_account.security.id}:role/OrganizationAccountAccessRole --role-session-name SecurityAccess"
    shared_services  = "aws sts assume-role --role-arn arn:aws:iam::${aws_organizations_account.shared_services.id}:role/OrganizationAccountAccessRole --role-session-name SharedServicesAccess"
    logging_account  = "aws sts assume-role --role-arn arn:aws:iam::${aws_organizations_account.logging.id}:role/OrganizationAccountAccessRole --role-session-name LoggingAccess"
    prod_apps        = "aws sts assume-role --role-arn arn:aws:iam::${aws_organizations_account.prod_apps.id}:role/OrganizationAccountAccessRole --role-session-name ProdAppsAccess"
    prod_data        = "aws sts assume-role --role-arn arn:aws:iam::${aws_organizations_account.prod_data.id}:role/OrganizationAccountAccessRole --role-session-name ProdDataAccess"
    nonprod_apps     = "aws sts assume-role --role-arn arn:aws:iam::${aws_organizations_account.nonprod_apps.id}:role/OrganizationAccountAccessRole --role-session-name NonProdAppsAccess"
    nonprod_data     = "aws sts assume-role --role-arn arn:aws:iam::${aws_organizations_account.nonprod_data.id}:role/OrganizationAccountAccessRole --role-session-name NonProdDataAccess"
  }
}

# ============================================================================
# Summary
# ============================================================================

output "deployment_summary" {
  description = "Summary of deployed resources"
  value = {
    organization_created = true
    accounts_created     = 7
    organizational_units = 4
    scps_created         = 5
    cloudtrail_enabled   = true
    config_enabled       = true
    budgets_created      = 4
    region               = var.aws_region
  }
}
