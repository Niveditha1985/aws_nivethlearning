# ============================================================================
# IAM Roles for Logging Account
# ============================================================================

# ============================================================================
# Cross-Account CloudWatch Logs Access Role
# ============================================================================
# Allows member accounts to send logs to this logging account

resource "aws_iam_role" "allow_member_accounts_write_logs" {
  name = "AllowMemberAccountsToWriteLogs"
  
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
            "sts:ExternalId" = var.cross_account_external_id
          }
        }
      }
    ]
  })
  
  tags = {
    Name = "Cross-Account CloudWatch Logs Write Access"
  }
}

resource "aws_iam_role_policy" "allow_member_accounts_write_logs" {
  name = "CloudWatchLogsWritePolicy"
  role = aws_iam_role.allow_member_accounts_write_logs.id
  
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
        Resource = [
          "arn:aws:logs:${var.aws_region}:${var.logging_account_id}:log-group:/aws/*",
          "arn:aws:logs:${var.aws_region}:${var.logging_account_id}:log-group:/aws/*:*"
        ]
      }
    ]
  })
}

# ============================================================================
# VPC Flow Logs IAM Role
# ============================================================================

resource "aws_iam_role" "vpc_flow_logs" {
  name = "VPCFlowLogsRole"
  
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "vpc-flow-logs.amazonaws.com"
        }
        Action = "sts:AssumeRole"
      }
    ]
  })
  
  tags = {
    Name = "VPC Flow Logs Role"
  }
}

resource "aws_iam_role_policy" "vpc_flow_logs" {
  name = "VPCFlowLogsPolicy"
  role = aws_iam_role.vpc_flow_logs.id
  
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
        Resource = "arn:aws:logs:${var.aws_region}:${var.logging_account_id}:log-group:/aws/vpc/*"
      }
    ]
  })
}

# ============================================================================
# CloudWatch Logs to Kinesis Firehose IAM Role
# ============================================================================

resource "aws_iam_role" "cloudwatch_to_firehose" {
  name = "CloudWatchLogsToKinesisFirehoseRole"
  
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "logs.amazonaws.com"
        }
        Action = "sts:AssumeRole"
      }
    ]
  })
  
  tags = {
    Name = "CloudWatch Logs to Kinesis Firehose Role"
  }
}

resource "aws_iam_role_policy" "cloudwatch_to_firehose" {
  name = "CloudWatchToFirehosePolicy"
  role = aws_iam_role.cloudwatch_to_firehose.id
  
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "firehose:PutRecord",
          "firehose:PutRecordBatch"
        ]
        Resource = aws_kinesis_firehose_delivery_stream.cloudwatch_to_s3.arn
      }
    ]
  })
}

# ============================================================================
# Kinesis Firehose to S3 IAM Role
# ============================================================================

resource "aws_iam_role" "firehose_to_s3" {
  name = "KinesisFirehoseToS3Role"
  
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "firehose.amazonaws.com"
        }
        Action = "sts:AssumeRole"
      }
    ]
  })
  
  tags = {
    Name = "Kinesis Firehose to S3 Role"
  }
}

resource "aws_iam_role_policy" "firehose_to_s3" {
  name = "FirehoseToS3Policy"
  role = aws_iam_role.firehose_to_s3.id
  
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "s3:AbortMultipartUpload",
          "s3:GetBucketLocation",
          "s3:GetObject",
          "s3:ListBucket",
          "s3:ListBucketMultipartUploads",
          "s3:PutObject"
        ]
        Resource = [
          aws_s3_bucket.cloudwatch_archive.arn,
          "${aws_s3_bucket.cloudwatch_archive.arn}/*"
        ]
      },
      {
        Effect = "Allow"
        Action = [
          "logs:PutLogEvents",
          "logs:CreateLogStream"
        ]
        Resource = "${aws_cloudwatch_log_group.firehose_logs.arn}:*"
      },
      {
        Effect = "Allow"
        Action = [
          "kms:Decrypt",
          "kms:GenerateDataKey"
        ]
        Resource = aws_kms_key.cloudwatch_logs.arn
        Condition = {
          StringEquals = {
            "kms:ViaService" = "s3.${var.aws_region}.amazonaws.com"
          }
          StringLike = {
            "kms:EncryptionContext:aws:s3:arn" = "${aws_s3_bucket.cloudwatch_archive.arn}/*"
          }
        }
      }
    ]
  })
}

# ============================================================================
# Log Analytics IAM Role (for users/teams to query logs)
# ============================================================================

resource "aws_iam_role" "log_analytics_readonly" {
  name = "LogAnalyticsReadOnlyRole"
  
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
            "sts:ExternalId" = var.analytics_external_id
          }
        }
      }
    ]
  })
  
  tags = {
    Name = "Log Analytics Read-Only Access"
  }
}

resource "aws_iam_role_policy" "log_analytics_readonly" {
  name = "LogAnalyticsReadOnlyPolicy"
  role = aws_iam_role.log_analytics_readonly.id
  
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "logs:DescribeLogGroups",
          "logs:DescribeLogStreams",
          "logs:GetLogEvents",
          "logs:FilterLogEvents",
          "logs:StartQuery",
          "logs:StopQuery",
          "logs:DescribeQueries",
          "logs:GetQueryResults"
        ]
        Resource = "arn:aws:logs:${var.aws_region}:${var.logging_account_id}:log-group:*"
      },
      {
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:ListBucket"
        ]
        Resource = [
          aws_s3_bucket.cloudwatch_archive.arn,
          "${aws_s3_bucket.cloudwatch_archive.arn}/*",
          aws_s3_bucket.vpc_flowlogs.arn,
          "${aws_s3_bucket.vpc_flowlogs.arn}/*"
        ]
      }
    ]
  })
}
