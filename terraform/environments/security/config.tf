# ============================================================================
# AWS Config - Centralized Compliance Monitoring
# ============================================================================
# This file configures AWS Config in the Security account with organization-wide
# aggregation to collect compliance data from all accounts and regions.
#
# Toggle: Set enable_aws_config = false to disable Config during dev/test to save costs
# ============================================================================

# ============================================================================
# IAM Roles for AWS Config
# ============================================================================

# AWS Config Service Role
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

# AWS Config Aggregator IAM Role
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
# S3 Bucket for AWS Config Logs
# ============================================================================

# S3 bucket for Config logs (always created to preserve historical logs)
resource "aws_s3_bucket" "config_logs" {
  bucket = "${var.bucket_prefix}-config-logs"

  tags = {
    Name    = "AWS Config Logs"
    Purpose = "Store AWS Config snapshots and history"
  }
}

resource "aws_s3_bucket_versioning" "config_logs" {
  bucket = aws_s3_bucket.config_logs.id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "config_logs" {
  bucket = aws_s3_bucket.config_logs.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_public_access_block" "config_logs" {
  bucket = aws_s3_bucket.config_logs.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# S3 bucket policy for AWS Config service
resource "aws_s3_bucket_policy" "config_logs" {
  bucket = aws_s3_bucket.config_logs.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AWSConfigBucketPermissionsCheck"
        Effect = "Allow"
        Principal = {
          Service = "config.amazonaws.com"
        }
        Action   = "s3:GetBucketAcl"
        Resource = aws_s3_bucket.config_logs.arn
      },
      {
        Sid    = "AWSConfigBucketExistenceCheck"
        Effect = "Allow"
        Principal = {
          Service = "config.amazonaws.com"
        }
        Action   = "s3:ListBucket"
        Resource = aws_s3_bucket.config_logs.arn
      },
      {
        Sid    = "AWSConfigBucketPutObject"
        Effect = "Allow"
        Principal = {
          Service = "config.amazonaws.com"
        }
        Action   = "s3:PutObject"
        Resource = "${aws_s3_bucket.config_logs.arn}/*"
        Condition = {
          StringEquals = {
            "s3:x-amz-acl" = "bucket-owner-full-control"
          }
        }
      }
    ]
  })
}

# ============================================================================
# AWS Config Recorder & Delivery
# ============================================================================

# Config Recorder
resource "aws_config_configuration_recorder" "main" {
  count = var.enable_aws_config ? 1 : 0

  name     = "organization-config-recorder"
  role_arn = aws_iam_role.config.arn

  recording_group {
    all_supported                 = true
    include_global_resource_types = true
  }
}

resource "aws_config_configuration_recorder_status" "main" {
  count = var.enable_aws_config ? 1 : 0

  name       = aws_config_configuration_recorder.main[0].name
  is_enabled = true

  depends_on = [aws_config_delivery_channel.main]
}

# Config Delivery Channel
resource "aws_config_delivery_channel" "main" {
  count = var.enable_aws_config ? 1 : 0

  name           = "organization-config-delivery"
  s3_bucket_name = aws_s3_bucket.config_logs.bucket

  snapshot_delivery_properties {
    delivery_frequency = var.config_snapshot_frequency
  }

  depends_on = [aws_config_configuration_recorder.main]
}

# Config Aggregator (organization-wide)
resource "aws_config_configuration_aggregator" "organization" {
  count = var.enable_aws_config ? 1 : 0

  name = "organization-aggregator"

  organization_aggregation_source {
    all_regions = true
    role_arn    = aws_iam_role.config_aggregator.arn
  }

  depends_on = [aws_iam_role_policy_attachment.config_aggregator]
}

# ============================================================================
# AWS Config Rules
# ============================================================================
# Individual toggles allow fine-grained control over which rules to enable
# during development/testing to further optimize costs
# ============================================================================

# Rule: Ensure EBS volumes are encrypted
resource "aws_config_config_rule" "encrypted_volumes" {
  count = var.enable_aws_config && var.enable_config_rule_encrypted_volumes ? 1 : 0

  name = "encrypted-volumes"

  source {
    owner             = "AWS"
    source_identifier = "ENCRYPTED_VOLUMES"
  }

  depends_on = [aws_config_configuration_recorder.main]
}

# Rule: Ensure RDS instances are encrypted
resource "aws_config_config_rule" "rds_encryption_enabled" {
  count = var.enable_aws_config && var.enable_config_rule_rds_encryption ? 1 : 0

  name = "rds-encryption-enabled"

  source {
    owner             = "AWS"
    source_identifier = "RDS_STORAGE_ENCRYPTED"
  }

  depends_on = [aws_config_configuration_recorder.main]
}

# Rule: S3 bucket public read prohibited
resource "aws_config_config_rule" "s3_bucket_public_read_prohibited" {
  count = var.enable_aws_config && var.enable_config_rule_s3_public_read ? 1 : 0

  name = "s3-bucket-public-read-prohibited"

  source {
    owner             = "AWS"
    source_identifier = "S3_BUCKET_PUBLIC_READ_PROHIBITED"
  }

  scope {
    compliance_resource_types = ["AWS::S3::Bucket"]
  }

  depends_on = [aws_config_configuration_recorder.main]
}

# Rule: S3 bucket public write prohibited
resource "aws_config_config_rule" "s3_bucket_public_write_prohibited" {
  count = var.enable_aws_config && var.enable_config_rule_s3_public_write ? 1 : 0

  name = "s3-bucket-public-write-prohibited"

  source {
    owner             = "AWS"
    source_identifier = "S3_BUCKET_PUBLIC_WRITE_PROHIBITED"
  }

  scope {
    compliance_resource_types = ["AWS::S3::Bucket"]
  }

  depends_on = [aws_config_configuration_recorder.main]
}

# Rule: Required tags
resource "aws_config_config_rule" "required_tags" {
  count = var.enable_aws_config && var.enable_config_rule_required_tags ? 1 : 0

  name = "required-tags"

  source {
    owner             = "AWS"
    source_identifier = "REQUIRED_TAGS"
  }

  input_parameters = jsonencode({
    tag1Key = "Environment"
    tag2Key = "ManagedBy"
    tag3Key = "CostCenter"
  })

  depends_on = [aws_config_configuration_recorder.main]
}

# Rule: IAM password policy
resource "aws_config_config_rule" "iam_password_policy" {
  count = var.enable_aws_config && var.enable_config_rule_iam_password_policy ? 1 : 0

  name = "iam-password-policy"

  source {
    owner             = "AWS"
    source_identifier = "IAM_PASSWORD_POLICY"
  }

  input_parameters = jsonencode({
    RequireUppercaseCharacters = true
    RequireLowercaseCharacters = true
    RequireSymbols            = true
    RequireNumbers            = true
    MinimumPasswordLength     = 14
    PasswordReusePrevention   = 24
    MaxPasswordAge            = 90
  })

  depends_on = [aws_config_configuration_recorder.main]
}
