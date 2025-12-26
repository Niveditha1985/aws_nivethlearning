# ============================================================================
# AWS Organizations
# ============================================================================

# Create the organization
resource "aws_organizations_organization" "main" {
  feature_set = "ALL" # Enables all features including SCPs

  aws_service_access_principals = [
    "cloudtrail.amazonaws.com",
    "config.amazonaws.com",
    "ram.amazonaws.com",
    "ssm.amazonaws.com",
    "sso.amazonaws.com",
    "tagpolicies.tag.amazonaws.com",
  ]

  enabled_policy_types = [
    "SERVICE_CONTROL_POLICY",
    "TAG_POLICY",
  ]
}

# ============================================================================
# Organizational Units (OUs)
# ============================================================================

# Security OU - for security and audit account
resource "aws_organizations_organizational_unit" "security" {
  name      = "Security"
  parent_id = aws_organizations_organization.main.roots[0].id
}

# Infrastructure OU - for shared services and logging
resource "aws_organizations_organizational_unit" "infrastructure" {
  name      = "Infrastructure"
  parent_id = aws_organizations_organization.main.roots[0].id
}

# Workloads-Production OU - for production workloads
resource "aws_organizations_organizational_unit" "workloads_production" {
  name      = "Workloads-Production"
  parent_id = aws_organizations_organization.main.roots[0].id
}

# Workloads-NonProduction OU - for non-production workloads
resource "aws_organizations_organizational_unit" "workloads_nonproduction" {
  name      = "Workloads-NonProduction"
  parent_id = aws_organizations_organization.main.roots[0].id
}

# ============================================================================
# Member Accounts
# ============================================================================

# Security & Audit Account
resource "aws_organizations_account" "security" {
  name                       = "Security-Audit"
  email                      = var.security_account_email
  parent_id                  = aws_organizations_organizational_unit.security.id
  iam_user_access_to_billing = "ALLOW"
  role_name                  = "OrganizationAccountAccessRole"

  tags = {
    Name        = "Security-Audit"
    Environment = "security"
    AccountType = "security"
  }

  lifecycle {
    prevent_destroy = true
  }
}

# Shared Services Account
resource "aws_organizations_account" "shared_services" {
  name                       = "Shared-Services"
  email                      = var.shared_services_account_email
  parent_id                  = aws_organizations_organizational_unit.infrastructure.id
  iam_user_access_to_billing = "ALLOW"
  role_name                  = "OrganizationAccountAccessRole"

  tags = {
    Name        = "Shared-Services"
    Environment = "shared"
    AccountType = "infrastructure"
  }

  lifecycle {
    prevent_destroy = true
  }
}

# Logging Account
resource "aws_organizations_account" "logging" {
  name                       = "Logging"
  email                      = var.logging_account_email
  parent_id                  = aws_organizations_organizational_unit.infrastructure.id
  iam_user_access_to_billing = "ALLOW"
  role_name                  = "OrganizationAccountAccessRole"

  tags = {
    Name        = "Logging"
    Environment = "logging"
    AccountType = "infrastructure"
  }

  lifecycle {
    prevent_destroy = true
  }
}

# Production Apps Account
resource "aws_organizations_account" "prod_apps" {
  name                       = "Production-Apps"
  email                      = var.prod_apps_account_email
  parent_id                  = aws_organizations_organizational_unit.workloads_production.id
  iam_user_access_to_billing = "ALLOW"
  role_name                  = "OrganizationAccountAccessRole"

  tags = {
    Name        = "Production-Apps"
    Environment = "production"
    AccountType = "workload"
  }

  lifecycle {
    prevent_destroy = true
  }
}

# Production Data Account
resource "aws_organizations_account" "prod_data" {
  name                       = "Production-Data"
  email                      = var.prod_data_account_email
  parent_id                  = aws_organizations_organizational_unit.workloads_production.id
  iam_user_access_to_billing = "ALLOW"
  role_name                  = "OrganizationAccountAccessRole"

  tags = {
    Name        = "Production-Data"
    Environment = "production"
    AccountType = "data"
  }

  lifecycle {
    prevent_destroy = true
  }
}

# NonProd Apps Account
resource "aws_organizations_account" "nonprod_apps" {
  name                       = "NonProd-Apps"
  email                      = var.nonprod_apps_account_email
  parent_id                  = aws_organizations_organizational_unit.workloads_nonproduction.id
  iam_user_access_to_billing = "ALLOW"
  role_name                  = "OrganizationAccountAccessRole"

  tags = {
    Name        = "NonProd-Apps"
    Environment = "nonprod"
    AccountType = "workload"
  }

  lifecycle {
    prevent_destroy = true
  }
}

# NonProd Data Account
resource "aws_organizations_account" "nonprod_data" {
  name                       = "NonProd-Data"
  email                      = var.nonprod_data_account_email
  parent_id                  = aws_organizations_organizational_unit.workloads_nonproduction.id
  iam_user_access_to_billing = "ALLOW"
  role_name                  = "OrganizationAccountAccessRole"

  tags = {
    Name        = "NonProd-Data"
    Environment = "nonprod"
    AccountType = "data"
  }

  lifecycle {
    prevent_destroy = true
  }
}
