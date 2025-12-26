# ============================================================================
# Security & Audit Account - Main Configuration
# ============================================================================
# This account serves as the central security hub for the organization
# - AWS Security Hub (delegated admin)
# - AWS GuardDuty (delegated admin)  
# - AWS Config Aggregator
# - IAM Access Analyzer
# - Centralized CloudTrail logs
# ============================================================================

terraform {
  required_version = ">= 1.5.0"
  
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

# ============================================================================
# Provider Configuration
# ============================================================================

provider "aws" {
  region = var.aws_region
  
  assume_role {
    role_arn     = "arn:aws:iam::${var.security_account_id}:role/OrganizationAccountAccessRole"
    session_name = "terraform-security-account"
  }
  
  default_tags {
    tags = {
      Environment       = "security"
      ManagedBy        = "terraform"
      Account          = "security"
      CostCenter       = "security-operations"
      ComplianceScope  = "organization-wide"
    }
  }
}

# Provider for Management account (for delegated admin setup)
provider "aws" {
  alias  = "management"
  region = var.aws_region
  
  assume_role {
    role_arn     = "arn:aws:iam::${var.management_account_id}:role/OrganizationAccountAccessRole"
    session_name = "terraform-management-delegation"
  }
}

# ============================================================================
# Data Sources
# ============================================================================

data "aws_caller_identity" "current" {}

data "aws_organizations_organization" "org" {
  provider = aws.management
}

# Get all organizational units and accounts
data "aws_organizations_organizational_units" "root" {
  provider  = aws.management
  parent_id = data.aws_organizations_organization.org.roots[0].id
}

# ============================================================================
# S3 Buckets for Security Logs
# ============================================================================
# Note: CloudTrail logs bucket is now in cloudtrail.tf

# GuardDuty Findings Bucket
resource "aws_s3_bucket" "guardduty_findings" {
  bucket = "${var.bucket_prefix}-guardduty-findings"
  
  tags = {
    Name    = "GuardDuty Findings"
    Purpose = "Store GuardDuty security findings"
  }
}

resource "aws_s3_bucket_versioning" "guardduty_findings" {
  bucket = aws_s3_bucket.guardduty_findings.id
  
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "guardduty_findings" {
  bucket = aws_s3_bucket.guardduty_findings.id
  
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_public_access_block" "guardduty_findings" {
  bucket = aws_s3_bucket.guardduty_findings.id
  
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# ============================================================================
# KMS Keys for Encryption
# ============================================================================
# Note: CloudTrail KMS key is now in cloudtrail.tf

# ============================================================================
# AWS Security Hub
# ============================================================================

# Enable Security Hub
resource "aws_securityhub_account" "main" {}

# Enable CIS AWS Foundations Benchmark
resource "aws_securityhub_standards_subscription" "cis" {
  depends_on    = [aws_securityhub_account.main]
  standards_arn = "arn:aws:securityhub:${var.aws_region}::standards/cis-aws-foundations-benchmark/v/1.4.0"
}

# Enable AWS Foundational Security Best Practices
resource "aws_securityhub_standards_subscription" "aws_foundational" {
  depends_on    = [aws_securityhub_account.main]
  standards_arn = "arn:aws:securityhub:${var.aws_region}::standards/aws-foundational-security-best-practices/v/1.0.0"
}

# Note: Delegated admin setup for Security Hub needs to be done from Management account
# This will be handled in a separate configuration or manually

# ============================================================================
# AWS GuardDuty
# ============================================================================

# Enable GuardDuty
resource "aws_guardduty_detector" "main" {
  enable                       = true
  finding_publishing_frequency = "FIFTEEN_MINUTES"
  
  datasources {
    s3_logs {
      enable = true
    }
    kubernetes {
      audit_logs {
        enable = true
      }
    }
    malware_protection {
      scan_ec2_instance_with_findings {
        ebs_volumes {
          enable = true
        }
      }
    }
  }
  
  tags = {
    Name = "Organization GuardDuty Detector"
  }
}

# Configure GuardDuty to export findings to S3
resource "aws_guardduty_publishing_destination" "s3" {
  detector_id     = aws_guardduty_detector.main.id
  destination_arn = aws_s3_bucket.guardduty_findings.arn
  kms_key_arn     = aws_kms_key.guardduty.arn
  
  depends_on = [
    aws_s3_bucket_policy.guardduty_findings
  ]
}

# KMS key for GuardDuty
resource "aws_kms_key" "guardduty" {
  description             = "KMS key for GuardDuty findings encryption"
  deletion_window_in_days = 30
  enable_key_rotation     = true
  
  tags = {
    Name = "GuardDuty Encryption Key"
  }
}

resource "aws_kms_alias" "guardduty" {
  name          = "alias/guardduty"
  target_key_id = aws_kms_key.guardduty.key_id
}

# GuardDuty bucket policy for findings
resource "aws_s3_bucket_policy" "guardduty_findings" {
  bucket = aws_s3_bucket.guardduty_findings.id
  
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "Allow GuardDuty to use the bucket"
        Effect = "Allow"
        Principal = {
          Service = "guardduty.amazonaws.com"
        }
        Action = [
          "s3:PutObject",
          "s3:GetBucketLocation"
        ]
        Resource = [
          aws_s3_bucket.guardduty_findings.arn,
          "${aws_s3_bucket.guardduty_findings.arn}/*"
        ]
      }
    ]
  })
}

# ============================================================================
# IAM Access Analyzer
# ============================================================================

resource "aws_accessanalyzer_analyzer" "organization" {
  analyzer_name = "organization-analyzer"
  type          = "ORGANIZATION"
  
  tags = {
    Name = "Organization-wide Access Analyzer"
  }
}

# ============================================================================
# SNS Topics for Security Alerts
# ============================================================================

# Critical security findings
resource "aws_sns_topic" "critical_findings" {
  name              = "security-critical-findings"
  display_name      = "Critical Security Findings"
  kms_master_key_id = aws_kms_key.sns.id
  
  tags = {
    Name     = "Critical Security Alerts"
    Severity = "critical"
  }
}

# High severity findings
resource "aws_sns_topic" "high_findings" {
  name              = "security-high-findings"
  display_name      = "High Severity Security Findings"
  kms_master_key_id = aws_kms_key.sns.id
  
  tags = {
    Name     = "High Severity Security Alerts"
    Severity = "high"
  }
}

# KMS key for SNS encryption
resource "aws_kms_key" "sns" {
  description             = "KMS key for SNS topic encryption"
  deletion_window_in_days = 30
  enable_key_rotation     = true
  
  tags = {
    Name = "SNS Encryption Key"
  }
}

resource "aws_kms_alias" "sns" {
  name          = "alias/sns-security"
  target_key_id = aws_kms_key.sns.key_id
}

# SNS topic policy
resource "aws_sns_topic_policy" "critical_findings" {
  arn = aws_sns_topic.critical_findings.arn
  
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowSecurityServicesToPublish"
        Effect = "Allow"
        Principal = {
          Service = [
            "guardduty.amazonaws.com",
            "securityhub.amazonaws.com",
            "config.amazonaws.com"
          ]
        }
        Action   = "SNS:Publish"
        Resource = aws_sns_topic.critical_findings.arn
      }
    ]
  })
}

# Email subscriptions (add actual email addresses)
resource "aws_sns_topic_subscription" "critical_email" {
  count     = length(var.security_alert_emails)
  topic_arn = aws_sns_topic.critical_findings.arn
  protocol  = "email"
  endpoint  = var.security_alert_emails[count.index]
}

# ============================================================================
# EventBridge Rules for Security Findings
# ============================================================================

# GuardDuty High/Critical Findings
resource "aws_cloudwatch_event_rule" "guardduty_findings" {
  name        = "guardduty-high-critical-findings"
  description = "Capture GuardDuty HIGH and CRITICAL severity findings"
  
  event_pattern = jsonencode({
    source      = ["aws.guardduty"]
    detail-type = ["GuardDuty Finding"]
    detail = {
      severity = [
        { numeric = [">=", 7] }  # HIGH and CRITICAL
      ]
    }
  })
}

resource "aws_cloudwatch_event_target" "guardduty_to_sns" {
  rule      = aws_cloudwatch_event_rule.guardduty_findings.name
  target_id = "SendToSNS"
  arn       = aws_sns_topic.critical_findings.arn
}

# Security Hub Findings
resource "aws_cloudwatch_event_rule" "securityhub_findings" {
  name        = "securityhub-critical-findings"
  description = "Capture Security Hub CRITICAL findings"
  
  event_pattern = jsonencode({
    source      = ["aws.securityhub"]
    detail-type = ["Security Hub Findings - Imported"]
    detail = {
      findings = {
        Severity = {
          Label = ["CRITICAL"]
        }
      }
    }
  })
}

resource "aws_cloudwatch_event_target" "securityhub_to_sns" {
  rule      = aws_cloudwatch_event_rule.securityhub_findings.name
  target_id = "SendToSNS"
  arn       = aws_sns_topic.critical_findings.arn
}
