# ============================================================================
# IAM Roles for Security Account
# ============================================================================

# ============================================================================
# AWS Config IAM Role
# ============================================================================

resource "aws_iam_role" "config" {
  name = "AWSConfigRole"
  
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "config.amazonaws.com"
        }
      }
    ]
  })
  
  tags = {
    Name = "AWS Config Service Role"
  }
}

resource "aws_iam_role_policy_attachment" "config_policy" {
  role       = aws_iam_role.config.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/ConfigRole"
}

# Custom policy for Config to write to S3
resource "aws_iam_role_policy" "config_s3" {
  name = "ConfigS3Policy"
  role = aws_iam_role.config.id
  
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "s3:GetBucketVersioning",
          "s3:PutObject",
          "s3:GetObject"
        ]
        Resource = [
          aws_s3_bucket.config_logs.arn,
          "${aws_s3_bucket.config_logs.arn}/*"
        ]
      }
    ]
  })
}

# ============================================================================
# AWS Config Aggregator IAM Role
# ============================================================================

resource "aws_iam_role" "config_aggregator" {
  name = "AWSConfigAggregatorRole"
  
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "config.amazonaws.com"
        }
      }
    ]
  })
  
  tags = {
    Name = "AWS Config Aggregator Role"
  }
}

resource "aws_iam_role_policy_attachment" "config_aggregator" {
  role       = aws_iam_role.config_aggregator.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSConfigRoleForOrganizations"
}

# ============================================================================
# Cross-Account CloudWatch Logs Access Role
# ============================================================================
# This role allows member accounts to send logs to centralized logging

resource "aws_iam_role" "cloudwatch_cross_account" {
  name = "CloudWatchCrossAccountRole"
  
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          AWS = [
            for account_id in var.member_account_ids :
            "arn:aws:iam::${account_id}:root"
          ]
        }
        Action = "sts:AssumeRole"
        Condition = {
          StringEquals = {
            "sts:ExternalId" = var.cloudwatch_external_id
          }
        }
      }
    ]
  })
  
  tags = {
    Name = "Cross-Account CloudWatch Access"
  }
}

resource "aws_iam_role_policy" "cloudwatch_cross_account" {
  name = "CloudWatchCrossAccountPolicy"
  role = aws_iam_role.cloudwatch_cross_account.id
  
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents",
          "logs:DescribeLogGroups",
          "logs:DescribeLogStreams"
        ]
        Resource = "arn:aws:logs:${var.aws_region}:${var.security_account_id}:log-group:/aws/security/*"
      }
    ]
  })
}

# ============================================================================
# Security Operations Team IAM Roles
# ============================================================================

# Security Read-Only Role (for security analysts)
resource "aws_iam_role" "security_readonly" {
  name = "SecurityReadOnlyRole"
  
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${var.management_account_id}:root"
        }
        Action = "sts:AssumeRole"
        Condition = {
          StringEquals = {
            "sts:ExternalId" = var.security_readonly_external_id
          }
        }
      }
    ]
  })
  
  tags = {
    Name = "Security Read-Only Access"
  }
}

resource "aws_iam_role_policy_attachment" "security_readonly_securityhub" {
  role       = aws_iam_role.security_readonly.name
  policy_arn = "arn:aws:iam::aws:policy/AWSSecurityHubReadOnlyAccess"
}

resource "aws_iam_role_policy_attachment" "security_readonly_guardduty" {
  role       = aws_iam_role.security_readonly.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonGuardDutyReadOnlyAccess"
}

resource "aws_iam_role_policy_attachment" "security_readonly_config" {
  role       = aws_iam_role.security_readonly.name
  policy_arn = "arn:aws:iam::aws:policy/ConfigUserAccess"
}

# Security Admin Role (for security operations)
resource "aws_iam_role" "security_admin" {
  name = "SecurityAdminRole"
  
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${var.management_account_id}:root"
        }
        Action = "sts:AssumeRole"
        Condition = {
          StringEquals = {
            "sts:ExternalId" = var.security_admin_external_id
          }
          Bool = {
            "aws:MultiFactorAuthPresent" = "true"
          }
        }
      }
    ]
  })
  
  tags = {
    Name = "Security Admin Access"
  }
}

resource "aws_iam_role_policy_attachment" "security_admin_securityhub" {
  role       = aws_iam_role.security_admin.name
  policy_arn = "arn:aws:iam::aws:policy/AWSSecurityHubFullAccess"
}

resource "aws_iam_role_policy_attachment" "security_admin_guardduty" {
  role       = aws_iam_role.security_admin.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonGuardDutyFullAccess"
}

resource "aws_iam_role_policy_attachment" "security_admin_config" {
  role       = aws_iam_role.security_admin.name
  policy_arn = "arn:aws:iam::aws:policy/ConfigUserAccess"
}
