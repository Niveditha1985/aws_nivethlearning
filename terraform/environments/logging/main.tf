# ============================================================================
# Logging Account - Main Configuration
# ============================================================================
# This account serves as the central logging repository for the organization
# - CloudWatch Log Groups (centralized)
# - S3 buckets for log archival
# - VPC Flow Logs
# - Application logs
# - Infrastructure logs
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
    role_arn     = "arn:aws:iam::${var.logging_account_id}:role/OrganizationAccountAccessRole"
    session_name = "terraform-logging-account"
  }
  
  default_tags {
    tags = {
      Environment = "logging"
      ManagedBy   = "terraform"
      Account     = "logging"
      CostCenter  = "logging-operations"
      Purpose     = "centralized-logging"
    }
  }
}

# ============================================================================
# Data Sources
# ============================================================================

data "aws_caller_identity" "current" {}

# ============================================================================
# CloudWatch Log Groups
# ============================================================================

# EKS Production Cluster Logs
resource "aws_cloudwatch_log_group" "eks_prod_application" {
  name              = "/aws/eks/prod-eks-cluster/application"
  retention_in_days = var.production_log_retention_days
  kms_key_id        = aws_kms_key.cloudwatch_logs.arn
  
  tags = {
    Name        = "EKS Production Application Logs"
    Environment = "production"
    Service     = "eks"
  }
}

resource "aws_cloudwatch_log_group" "eks_prod_dataplane" {
  name              = "/aws/eks/prod-eks-cluster/dataplane"
  retention_in_days = var.production_log_retention_days
  kms_key_id        = aws_kms_key.cloudwatch_logs.arn
  
  tags = {
    Name        = "EKS Production Dataplane Logs"
    Environment = "production"
    Service     = "eks"
  }
}

resource "aws_cloudwatch_log_group" "eks_prod_host" {
  name              = "/aws/eks/prod-eks-cluster/host"
  retention_in_days = var.production_log_retention_days
  kms_key_id        = aws_kms_key.cloudwatch_logs.arn
  
  tags = {
    Name        = "EKS Production Host Logs"
    Environment = "production"
    Service     = "eks"
  }
}

# EKS Non-Production Cluster Logs
resource "aws_cloudwatch_log_group" "eks_nonprod_application" {
  name              = "/aws/eks/nonprod-eks-cluster/application"
  retention_in_days = var.nonproduction_log_retention_days
  kms_key_id        = aws_kms_key.cloudwatch_logs.arn
  
  tags = {
    Name        = "EKS Non-Prod Application Logs"
    Environment = "nonprod"
    Service     = "eks"
  }
}

resource "aws_cloudwatch_log_group" "eks_nonprod_dataplane" {
  name              = "/aws/eks/nonprod-eks-cluster/dataplane"
  retention_in_days = var.nonproduction_log_retention_days
  kms_key_id        = aws_kms_key.cloudwatch_logs.arn
  
  tags = {
    Name        = "EKS Non-Prod Dataplane Logs"
    Environment = "nonprod"
    Service     = "eks"
  }
}

# RDS Production Logs
resource "aws_cloudwatch_log_group" "rds_prod_postgres" {
  name              = "/aws/rds/prod-postgres"
  retention_in_days = var.production_log_retention_days
  kms_key_id        = aws_kms_key.cloudwatch_logs.arn
  
  tags = {
    Name        = "RDS Production PostgreSQL Logs"
    Environment = "production"
    Service     = "rds"
  }
}

# RDS Non-Production Logs
resource "aws_cloudwatch_log_group" "rds_nonprod_postgres" {
  name              = "/aws/rds/nonprod-postgres"
  retention_in_days = var.nonproduction_log_retention_days
  kms_key_id        = aws_kms_key.cloudwatch_logs.arn
  
  tags = {
    Name        = "RDS Non-Prod PostgreSQL Logs"
    Environment = "nonprod"
    Service     = "rds"
  }
}

# VPC Flow Logs - Production Apps
resource "aws_cloudwatch_log_group" "vpc_flowlogs_prod_apps" {
  name              = "/aws/vpc/flowlogs-prod-apps"
  retention_in_days = var.production_log_retention_days
  kms_key_id        = aws_kms_key.cloudwatch_logs.arn
  
  tags = {
    Name        = "VPC Flow Logs - Production Apps"
    Environment = "production"
    Service     = "vpc"
  }
}

# VPC Flow Logs - Production Data
resource "aws_cloudwatch_log_group" "vpc_flowlogs_prod_data" {
  name              = "/aws/vpc/flowlogs-prod-data"
  retention_in_days = var.production_log_retention_days
  kms_key_id        = aws_kms_key.cloudwatch_logs.arn
  
  tags = {
    Name        = "VPC Flow Logs - Production Data"
    Environment = "production"
    Service     = "vpc"
  }
}

# VPC Flow Logs - Non-Production Apps
resource "aws_cloudwatch_log_group" "vpc_flowlogs_nonprod_apps" {
  name              = "/aws/vpc/flowlogs-nonprod-apps"
  retention_in_days = var.nonproduction_log_retention_days
  kms_key_id        = aws_kms_key.cloudwatch_logs.arn
  
  tags = {
    Name        = "VPC Flow Logs - Non-Prod Apps"
    Environment = "nonprod"
    Service     = "vpc"
  }
}

# VPC Flow Logs - Non-Production Data
resource "aws_cloudwatch_log_group" "vpc_flowlogs_nonprod_data" {
  name              = "/aws/vpc/flowlogs-nonprod-data"
  retention_in_days = var.nonproduction_log_retention_days
  kms_key_id        = aws_kms_key.cloudwatch_logs.arn
  
  tags = {
    Name        = "VPC Flow Logs - Non-Prod Data"
    Environment = "nonprod"
    Service     = "vpc"
  }
}

# Lambda Function Logs
resource "aws_cloudwatch_log_group" "lambda_logs" {
  name              = "/aws/lambda"
  retention_in_days = var.production_log_retention_days
  kms_key_id        = aws_kms_key.cloudwatch_logs.arn
  
  tags = {
    Name    = "Lambda Function Logs"
    Service = "lambda"
  }
}

# API Gateway Logs
resource "aws_cloudwatch_log_group" "api_gateway_logs" {
  name              = "/aws/apigateway"
  retention_in_days = var.production_log_retention_days
  kms_key_id        = aws_kms_key.cloudwatch_logs.arn
  
  tags = {
    Name    = "API Gateway Logs"
    Service = "apigateway"
  }
}

# ============================================================================
# S3 Buckets for Log Archive
# ============================================================================

# CloudWatch Logs Archive
resource "aws_s3_bucket" "cloudwatch_archive" {
  bucket = "${var.bucket_prefix}-cloudwatch-archive"
  
  tags = {
    Name    = "CloudWatch Logs Archive"
    Purpose = "Long-term storage of CloudWatch logs"
  }
}

resource "aws_s3_bucket_versioning" "cloudwatch_archive" {
  bucket = aws_s3_bucket.cloudwatch_archive.id
  
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "cloudwatch_archive" {
  bucket = aws_s3_bucket.cloudwatch_archive.id
  
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_public_access_block" "cloudwatch_archive" {
  bucket = aws_s3_bucket.cloudwatch_archive.id
  
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_lifecycle_configuration" "cloudwatch_archive" {
  bucket = aws_s3_bucket.cloudwatch_archive.id
  
  rule {
    id     = "archive-to-glacier"
    status = "Enabled"
    
    transition {
      days          = 90
      storage_class = "GLACIER"
    }
    
    transition {
      days          = 365
      storage_class = "DEEP_ARCHIVE"
    }
    
    expiration {
      days = 2555  # 7 years
    }
  }
}

# VPC Flow Logs Archive
resource "aws_s3_bucket" "vpc_flowlogs" {
  bucket = "${var.bucket_prefix}-vpc-flowlogs"
  
  tags = {
    Name    = "VPC Flow Logs Archive"
    Purpose = "Long-term storage of VPC flow logs"
  }
}

resource "aws_s3_bucket_versioning" "vpc_flowlogs" {
  bucket = aws_s3_bucket.vpc_flowlogs.id
  
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "vpc_flowlogs" {
  bucket = aws_s3_bucket.vpc_flowlogs.id
  
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_public_access_block" "vpc_flowlogs" {
  bucket = aws_s3_bucket.vpc_flowlogs.id
  
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_lifecycle_configuration" "vpc_flowlogs" {
  bucket = aws_s3_bucket.vpc_flowlogs.id
  
  rule {
    id     = "archive-to-glacier"
    status = "Enabled"
    
    transition {
      days          = 90
      storage_class = "GLACIER"
    }
    
    expiration {
      days = 730  # 2 years
    }
  }
}

# ALB Access Logs
resource "aws_s3_bucket" "alb_accesslogs" {
  bucket = "${var.bucket_prefix}-alb-accesslogs"
  
  tags = {
    Name    = "ALB Access Logs"
    Purpose = "Store ALB access logs"
  }
}

resource "aws_s3_bucket_versioning" "alb_accesslogs" {
  bucket = aws_s3_bucket.alb_accesslogs.id
  
  versioning_configuration {
    status = "Disabled"  # ALB logs don't need versioning
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "alb_accesslogs" {
  bucket = aws_s3_bucket.alb_accesslogs.id
  
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_public_access_block" "alb_accesslogs" {
  bucket = aws_s3_bucket.alb_accesslogs.id
  
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_lifecycle_configuration" "alb_accesslogs" {
  bucket = aws_s3_bucket.alb_accesslogs.id
  
  rule {
    id     = "delete-old-logs"
    status = "Enabled"
    
    expiration {
      days = 90
    }
  }
}

# ALB bucket policy for ELB service
resource "aws_s3_bucket_policy" "alb_accesslogs" {
  bucket = aws_s3_bucket.alb_accesslogs.id
  
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AWSLogDeliveryWrite"
        Effect = "Allow"
        Principal = {
          Service = "elasticloadbalancing.amazonaws.com"
        }
        Action   = "s3:PutObject"
        Resource = "${aws_s3_bucket.alb_accesslogs.arn}/*"
      },
      {
        Sid    = "AWSLogDeliveryAclCheck"
        Effect = "Allow"
        Principal = {
          Service = "elasticloadbalancing.amazonaws.com"
        }
        Action   = "s3:GetBucketAcl"
        Resource = aws_s3_bucket.alb_accesslogs.arn
      }
    ]
  })
}

# ============================================================================
# KMS Keys for Encryption
# ============================================================================

# KMS key for CloudWatch Logs
resource "aws_kms_key" "cloudwatch_logs" {
  description             = "KMS key for CloudWatch Logs encryption"
  deletion_window_in_days = 30
  enable_key_rotation     = true
  
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "Enable IAM User Permissions"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${var.logging_account_id}:root"
        }
        Action   = "kms:*"
        Resource = "*"
      },
      {
        Sid    = "Allow CloudWatch Logs"
        Effect = "Allow"
        Principal = {
          Service = "logs.${var.aws_region}.amazonaws.com"
        }
        Action = [
          "kms:Encrypt",
          "kms:Decrypt",
          "kms:ReEncrypt*",
          "kms:GenerateDataKey*",
          "kms:CreateGrant",
          "kms:DescribeKey"
        ]
        Resource = "*"
        Condition = {
          ArnLike = {
            "kms:EncryptionContext:aws:logs:arn" = "arn:aws:logs:${var.aws_region}:${var.logging_account_id}:log-group:*"
          }
        }
      }
    ]
  })
  
  tags = {
    Name = "CloudWatch Logs Encryption Key"
  }
}

resource "aws_kms_alias" "cloudwatch_logs" {
  name          = "alias/cloudwatch-logs"
  target_key_id = aws_kms_key.cloudwatch_logs.key_id
}

# ============================================================================
# CloudWatch Logs Subscription Filters
# ============================================================================
# These filters export logs to S3 for long-term archival

# Production EKS logs to S3
resource "aws_cloudwatch_log_subscription_filter" "eks_prod_to_s3" {
  name            = "eks-prod-to-s3"
  log_group_name  = aws_cloudwatch_log_group.eks_prod_application.name
  filter_pattern  = ""  # Send all logs
  destination_arn = aws_kinesis_firehose_delivery_stream.cloudwatch_to_s3.arn
  role_arn        = aws_iam_role.cloudwatch_to_firehose.arn
}

# ============================================================================
# Kinesis Firehose for CloudWatch Logs to S3
# ============================================================================

resource "aws_kinesis_firehose_delivery_stream" "cloudwatch_to_s3" {
  name        = "cloudwatch-logs-to-s3"
  destination = "extended_s3"
  
  extended_s3_configuration {
    role_arn   = aws_iam_role.firehose_to_s3.arn
    bucket_arn = aws_s3_bucket.cloudwatch_archive.arn
    
    prefix              = "logs/year=!{timestamp:yyyy}/month=!{timestamp:MM}/day=!{timestamp:dd}/"
    error_output_prefix = "errors/year=!{timestamp:yyyy}/month=!{timestamp:MM}/day=!{timestamp:dd}/!{firehose:error-output-type}/"
    
    buffering_size     = 5   # MB
    buffering_interval = 300 # seconds
    
    compression_format = "GZIP"
    
    cloudwatch_logging_options {
      enabled         = true
      log_group_name  = aws_cloudwatch_log_group.firehose_logs.name
      log_stream_name = "S3Delivery"
    }
  }
  
  tags = {
    Name = "CloudWatch Logs to S3 Delivery Stream"
  }
}

# Firehose logs
resource "aws_cloudwatch_log_group" "firehose_logs" {
  name              = "/aws/kinesisfirehose/cloudwatch-to-s3"
  retention_in_days = 7
  
  tags = {
    Name = "Kinesis Firehose Logs"
  }
}
