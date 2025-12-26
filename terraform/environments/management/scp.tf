# ============================================================================
# Service Control Policies (SCPs)
# ============================================================================

# SCP: Deny actions outside allowed regions
resource "aws_organizations_policy" "deny_regions" {
  name        = "DenyRegionsOutsideAllowed"
  description = "Deny all actions outside allowed AWS regions"
  type        = "SERVICE_CONTROL_POLICY"

  content = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "DenyAllOutsideAllowedRegions"
        Effect = "Deny"
        NotAction = [
          "iam:*",
          "organizations:*",
          "route53:*",
          "budgets:*",
          "waf:*",
          "cloudfront:*",
          "support:*",
          "sts:*",
          "globalaccelerator:*",
          "health:*",
        ]
        Resource = "*"
        Condition = {
          StringNotEquals = {
            "aws:RequestedRegion" = [
              var.aws_region,
              "us-east-1" # Always allow us-east-1 for global services
            ]
          }
        }
      }
    ]
  })
}

# SCP: Prevent CloudTrail deletion
resource "aws_organizations_policy" "protect_cloudtrail" {
  name        = "ProtectCloudTrail"
  description = "Prevent deletion or modification of CloudTrail"
  type        = "SERVICE_CONTROL_POLICY"

  content = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "ProtectCloudTrailLogs"
        Effect = "Deny"
        Action = [
          "cloudtrail:DeleteTrail",
          "cloudtrail:StopLogging",
          "cloudtrail:UpdateTrail",
        ]
        Resource = "*"
        Condition = {
          StringNotLike = {
            "aws:PrincipalArn" = [
              "arn:aws:iam::*:role/OrganizationAccountAccessRole",
              "arn:aws:iam::*:role/Admin*"
            ]
          }
        }
      }
    ]
  })
}

# SCP: Prevent leaving organization
resource "aws_organizations_policy" "prevent_leave_organization" {
  name        = "PreventLeaveOrganization"
  description = "Prevent accounts from leaving the organization"
  type        = "SERVICE_CONTROL_POLICY"

  content = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "PreventLeaveOrg"
        Effect   = "Deny"
        Action   = "organizations:LeaveOrganization"
        Resource = "*"
      }
    ]
  })
}

# SCP: Require MFA for sensitive actions
resource "aws_organizations_policy" "require_mfa" {
  name        = "RequireMFAForSensitiveActions"
  description = "Require MFA for sensitive actions"
  type        = "SERVICE_CONTROL_POLICY"

  content = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "DenyWithoutMFA"
        Effect = "Deny"
        Action = [
          "ec2:StopInstances",
          "ec2:TerminateInstances",
          "rds:DeleteDBInstance",
          "rds:DeleteDBCluster",
          "s3:DeleteBucket",
        ]
        Resource = "*"
        Condition = {
          BoolIfExists = {
            "aws:MultiFactorAuthPresent" = "false"
          }
        }
      }
    ]
  })
}

# SCP: Production account restrictions
resource "aws_organizations_policy" "production_restrictions" {
  name        = "ProductionAccountRestrictions"
  description = "Additional restrictions for production accounts"
  type        = "SERVICE_CONTROL_POLICY"

  content = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "DenyNonApprovedInstanceTypes"
        Effect = "Deny"
        Action = "ec2:RunInstances"
        Resource = [
          "arn:aws:ec2:*:*:instance/*"
        ]
        Condition = {
          StringNotEquals = {
            "ec2:InstanceType" = [
              "t3.medium",
              "t3.large",
              "m5.large",
              "m5.xlarge",
              "m5.2xlarge",
              "m6g.large",
              "m6g.xlarge",
              "r6g.large",
              "r6g.xlarge",
            ]
          }
        }
      },
      {
        Sid    = "DenyDBDeletionExceptAdmin"
        Effect = "Deny"
        Action = [
          "rds:DeleteDBInstance",
          "rds:DeleteDBCluster",
        ]
        Resource = "*"
        Condition = {
          StringNotLike = {
            "aws:PrincipalArn" = [
              "arn:aws:iam::*:role/Admin*",
              "arn:aws:iam::*:role/DBAdmin*",
            ]
          }
        }
      }
    ]
  })
}

# ============================================================================
# Attach SCPs to OUs
# ============================================================================

# Attach region restriction to all OUs
resource "aws_organizations_policy_attachment" "deny_regions_security" {
  policy_id = aws_organizations_policy.deny_regions.id
  target_id = aws_organizations_organizational_unit.security.id
}

resource "aws_organizations_policy_attachment" "deny_regions_infrastructure" {
  policy_id = aws_organizations_policy.deny_regions.id
  target_id = aws_organizations_organizational_unit.infrastructure.id
}

resource "aws_organizations_policy_attachment" "deny_regions_prod" {
  policy_id = aws_organizations_policy.deny_regions.id
  target_id = aws_organizations_organizational_unit.workloads_production.id
}

resource "aws_organizations_policy_attachment" "deny_regions_nonprod" {
  policy_id = aws_organizations_policy.deny_regions.id
  target_id = aws_organizations_organizational_unit.workloads_nonproduction.id
}

# Attach CloudTrail protection to all OUs
resource "aws_organizations_policy_attachment" "protect_cloudtrail_security" {
  policy_id = aws_organizations_policy.protect_cloudtrail.id
  target_id = aws_organizations_organizational_unit.security.id
}

resource "aws_organizations_policy_attachment" "protect_cloudtrail_infrastructure" {
  policy_id = aws_organizations_policy.protect_cloudtrail.id
  target_id = aws_organizations_organizational_unit.infrastructure.id
}

resource "aws_organizations_policy_attachment" "protect_cloudtrail_prod" {
  policy_id = aws_organizations_policy.protect_cloudtrail.id
  target_id = aws_organizations_organizational_unit.workloads_production.id
}

resource "aws_organizations_policy_attachment" "protect_cloudtrail_nonprod" {
  policy_id = aws_organizations_policy.protect_cloudtrail.id
  target_id = aws_organizations_organizational_unit.workloads_nonproduction.id
}

# Attach prevent leave to all OUs
resource "aws_organizations_policy_attachment" "prevent_leave_security" {
  policy_id = aws_organizations_policy.prevent_leave_organization.id
  target_id = aws_organizations_organizational_unit.security.id
}

resource "aws_organizations_policy_attachment" "prevent_leave_infrastructure" {
  policy_id = aws_organizations_policy.prevent_leave_organization.id
  target_id = aws_organizations_organizational_unit.infrastructure.id
}

resource "aws_organizations_policy_attachment" "prevent_leave_prod" {
  policy_id = aws_organizations_policy.prevent_leave_organization.id
  target_id = aws_organizations_organizational_unit.workloads_production.id
}

resource "aws_organizations_policy_attachment" "prevent_leave_nonprod" {
  policy_id = aws_organizations_policy.prevent_leave_organization.id
  target_id = aws_organizations_organizational_unit.workloads_nonproduction.id
}

# Attach MFA requirement to production accounts
resource "aws_organizations_policy_attachment" "require_mfa_prod" {
  policy_id = aws_organizations_policy.require_mfa.id
  target_id = aws_organizations_organizational_unit.workloads_production.id
}

# Attach production restrictions to production OU
resource "aws_organizations_policy_attachment" "production_restrictions" {
  policy_id = aws_organizations_policy.production_restrictions.id
  target_id = aws_organizations_organizational_unit.workloads_production.id
}
