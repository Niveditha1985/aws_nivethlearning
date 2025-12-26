# Security & Logging Accounts - Terraform Configuration

This directory contains Terraform configurations for setting up the **Security & Audit** and **Logging** accounts in your AWS multi-account organization.

## Table of Contents

- [Overview](#overview)
- [Directory Structure](#directory-structure)
- [Security Account](#security-account)
- [Logging Account](#logging-account)
- [Prerequisites](#prerequisites)
- [Deployment Instructions](#deployment-instructions)
- [Post-Deployment Configuration](#post-deployment-configuration)
- [Troubleshooting](#troubleshooting)

---

## Overview

### Security Account
The Security & Audit account serves as the central security hub for the entire organization:
- **AWS Security Hub** - Central security findings aggregation
- **AWS GuardDuty** - Threat detection across all accounts
- **AWS Config** - Configuration compliance and tracking
- **IAM Access Analyzer** - Identify unintended resource access
- **CloudTrail** - Centralized audit logging from all accounts
- **SNS Topics** - Security alert notifications

### Logging Account
The Logging account provides centralized log aggregation and long-term storage:
- **CloudWatch Log Groups** - Centralized logs from all accounts
- **S3 Buckets** - Long-term log archival with lifecycle policies
- **Kinesis Firehose** - Automated log export to S3
- **KMS Encryption** - Encrypted log storage
- **Cross-Account Access** - IAM roles for log collection

---

## Directory Structure

```
terraform/environments/
├── security/
│   ├── main.tf                    # Core Security Hub, GuardDuty, Config
│   ├── iam.tf                     # IAM roles for security services
│   ├── variables.tf               # Input variables
│   ├── outputs.tf                 # Output values
│   ├── backend.tf                 # S3 backend configuration
│   ├── terraform.tfvars.example   # Example variable values
│   └── README.md                  # This file
│
└── logging/
    ├── main.tf                    # CloudWatch Log Groups, S3 buckets
    ├── iam.tf                     # IAM roles for logging services
    ├── variables.tf               # Input variables
    ├── outputs.tf                 # Output values
    ├── backend.tf                 # S3 backend configuration
    ├── terraform.tfvars.example   # Example variable values
    └── README.md                  # This file
```

---

## Security Account

### Resources Created

#### S3 Buckets
- `{prefix}-cloudtrail-logs` - CloudTrail logs from all accounts
- `{prefix}-config-logs` - AWS Config snapshots and history
- `{prefix}-guardduty-findings` - GuardDuty security findings

#### Security Services
- **Security Hub**
  - CIS AWS Foundations Benchmark v1.4.0
  - AWS Foundational Security Best Practices
- **GuardDuty**
  - S3 Protection enabled
  - Kubernetes Protection enabled
  - Malware Protection enabled
  - Findings export to S3
- **AWS Config**
  - Organization-wide aggregator
  - Managed config rules (encryption, public access, tagging, IAM)
- **IAM Access Analyzer**
  - Organization-level analyzer

#### SNS Topics
- `security-critical-findings` - Critical security alerts
- `security-high-findings` - High severity alerts

#### EventBridge Rules
- GuardDuty HIGH/CRITICAL findings → SNS
- Security Hub CRITICAL findings → SNS

#### IAM Roles
- `AWSConfigRole` - Config service role
- `AWSConfigAggregatorRole` - Cross-account aggregation
- `CloudWatchCrossAccountRole` - Member account log access
- `SecurityReadOnlyRole` - Security analysts read access
- `SecurityAdminRole` - Security operations admin access

### Configuration Variables

Key variables to configure in `terraform.tfvars`:

```hcl
security_account_id  = "111111111111"
management_account_id = "222222222222"
member_account_ids = ["333333333333", "444444444444", ...]
bucket_prefix = "myapp-security-12345"
security_alert_emails = ["security@example.com"]
```

---

## Logging Account

### Resources Created

#### CloudWatch Log Groups

**Production Logs (365-day retention):**
- `/aws/eks/prod-eks-cluster/application`
- `/aws/eks/prod-eks-cluster/dataplane`
- `/aws/eks/prod-eks-cluster/host`
- `/aws/rds/prod-postgres`
- `/aws/vpc/flowlogs-prod-apps`
- `/aws/vpc/flowlogs-prod-data`

**Non-Production Logs (90-day retention):**
- `/aws/eks/nonprod-eks-cluster/application`
- `/aws/eks/nonprod-eks-cluster/dataplane`
- `/aws/rds/nonprod-postgres`
- `/aws/vpc/flowlogs-nonprod-apps`
- `/aws/vpc/flowlogs-nonprod-data`

**Shared Logs:**
- `/aws/lambda`
- `/aws/apigateway`

#### S3 Buckets

**CloudWatch Archive** (`{prefix}-cloudwatch-archive`):
- Lifecycle: 90 days → Glacier, 365 days → Deep Archive
- Retention: 7 years (2555 days)
- Versioning: Enabled
- Encryption: AES256

**VPC Flow Logs** (`{prefix}-vpc-flowlogs`):
- Lifecycle: 90 days → Glacier
- Retention: 2 years
- Encryption: AES256

**ALB Access Logs** (`{prefix}-alb-accesslogs`):
- Retention: 90 days
- Encryption: AES256

#### Kinesis Firehose
- `cloudwatch-logs-to-s3` - Automated log export stream
- Buffering: 5MB or 300 seconds
- Compression: GZIP
- Output: Partitioned by date in S3

#### IAM Roles
- `AllowMemberAccountsToWriteLogs` - Cross-account log write access
- `VPCFlowLogsRole` - VPC Flow Logs service role
- `CloudWatchLogsToKinesisFirehoseRole` - Log export role
- `KinesisFirehoseToS3Role` - Firehose delivery role
- `LogAnalyticsReadOnlyRole` - Read-only access for analysts

### Configuration Variables

Key variables to configure in `terraform.tfvars`:

```hcl
logging_account_id = "888888888888"
management_account_id = "222222222222"
member_account_ids = ["111111111111", "333333333333", ...]
bucket_prefix = "myapp-logging-12345"
production_log_retention_days = 365
nonproduction_log_retention_days = 90
```

---

## Prerequisites

### 1. AWS Organization Setup
- Management account with AWS Organizations enabled
- Member accounts created (Security, Logging, Prod-Apps, etc.)
- OrganizationAccountAccessRole exists in each member account

### 2. Terraform State Backend
Create in Management account (one-time setup):

```hcl
# In Management account
resource "aws_s3_bucket" "terraform_state" {
  bucket = "myapp-terraform-state"
  
  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_s3_bucket_versioning" "terraform_state" {
  bucket = aws_s3_bucket.terraform_state.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_dynamodb_table" "terraform_locks" {
  name         = "terraform-state-lock"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "LockID"
  
  attribute {
    name = "LockID"
    type = "S"
  }
}
```

### 3. AWS CLI Configuration
Ensure you have AWS credentials configured with access to assume roles:

```bash
# Configure AWS CLI
aws configure --profile management

# Test access
aws sts get-caller-identity --profile management
```

### 4. Terraform Installed
- Terraform >= 1.5.0
- AWS Provider >= 5.0

---

## Deployment Instructions

### Step 1: Deploy Security Account

```bash
# Navigate to security account directory
cd terraform/environments/security

# Copy example variables
cp terraform.tfvars.example terraform.tfvars

# Edit terraform.tfvars with your actual values
vim terraform.tfvars

# Update backend.tf with your Security account ID
sed -i 's/SECURITY_ACCOUNT_ID/111111111111/g' backend.tf

# Initialize Terraform
terraform init

# Review the plan
terraform plan -out=tfplan

# Apply the configuration
terraform apply tfplan

# Save outputs
terraform output > security-outputs.txt
```

### Step 2: Deploy Logging Account

```bash
# Navigate to logging account directory
cd terraform/environments/logging

# Copy example variables
cp terraform.tfvars.example terraform.tfvars

# Edit terraform.tfvars with your actual values
vim terraform.tfvars

# Update backend.tf with your Logging account ID
sed -i 's/LOGGING_ACCOUNT_ID/888888888888/g' backend.tf

# Initialize Terraform
terraform init

# Review the plan
terraform plan -out=tfplan

# Apply the configuration
terraform apply tfplan

# Save outputs
terraform output > logging-outputs.txt
```

### Step 3: Verify Deployment

**Security Account Verification:**
```bash
# Check Security Hub is enabled
aws securityhub describe-hub --region us-east-1 \
  --profile security

# Check GuardDuty detector
aws guardduty list-detectors --region us-east-1 \
  --profile security

# Check Config recorder
aws configservice describe-configuration-recorders \
  --region us-east-1 --profile security

# Verify S3 buckets created
aws s3 ls --profile security | grep security
```

**Logging Account Verification:**
```bash
# List CloudWatch Log Groups
aws logs describe-log-groups --region us-east-1 \
  --profile logging

# List S3 buckets
aws s3 ls --profile logging | grep logging

# Check Kinesis Firehose stream
aws firehose list-delivery-streams --region us-east-1 \
  --profile logging
```

---

## Post-Deployment Configuration

### 1. Enable Security Hub Delegated Administrator

This must be done from the Management account:

```bash
# Enable Security Hub in Management account first
aws securityhub enable-security-hub --region us-east-1 \
  --profile management

# Delegate administration to Security account
aws organizations enable-aws-service-access \
  --service-principal securityhub.amazonaws.com \
  --profile management

aws securityhub enable-organization-admin-account \
  --admin-account-id 111111111111 \
  --region us-east-1 --profile management
```

### 2. Enable GuardDuty Delegated Administrator

```bash
# Enable GuardDuty in Management account
aws guardduty create-detector --enable --region us-east-1 \
  --profile management

# Delegate to Security account
aws organizations enable-aws-service-access \
  --service-principal guardduty.amazonaws.com \
  --profile management

aws guardduty enable-organization-admin-account \
  --admin-account-id 111111111111 \
  --region us-east-1 --profile management
```

### 3. Add Member Accounts to Security Hub

From Security account:

```bash
# Invite and add member accounts
aws securityhub create-members \
  --account-details '[
    {"AccountId": "333333333333", "Email": "prod-apps@example.com"},
    {"AccountId": "444444444444", "Email": "prod-data@example.com"}
  ]' \
  --region us-east-1 --profile security
```

### 4. Configure SNS Email Subscriptions

The SNS email subscriptions need to confirm:

1. Check your email inbox for AWS SNS subscription confirmations
2. Click "Confirm subscription" in each email
3. Verify subscriptions:

```bash
aws sns list-subscriptions-by-topic \
  --topic-arn arn:aws:sns:us-east-1:111111111111:security-critical-findings \
  --profile security
```

### 5. Configure Cross-Account CloudWatch Logs

In each member account, configure CloudWatch to send logs to Logging account:

```hcl
# Example for Production-Apps account
resource "aws_cloudwatch_log_group" "app_logs" {
  name = "/aws/apps/my-application"
  
  # This will be sent to Logging account
}

# Configure log destination in member account
resource "aws_cloudwatch_log_subscription_filter" "to_logging_account" {
  name            = "send-to-logging-account"
  log_group_name  = aws_cloudwatch_log_group.app_logs.name
  filter_pattern  = ""
  destination_arn = "arn:aws:logs:us-east-1:888888888888:destination:central-logging"
  
  depends_on = [aws_iam_role_policy.logs_to_firehose]
}
```

---

## Troubleshooting

### Issue: Terraform can't assume role

**Error:**
```
Error: error configuring Terraform AWS Provider: error validating provider credentials: 
error calling sts:GetCallerIdentity: operation error STS: GetCallerIdentity
```

**Solution:**
1. Verify OrganizationAccountAccessRole exists in target account
2. Check trust policy allows your Management account
3. Ensure your AWS credentials have sts:AssumeRole permission

### Issue: S3 bucket already exists

**Error:**
```
Error: error creating S3 Bucket: BucketAlreadyExists: The requested bucket name is not available
```

**Solution:**
Change `bucket_prefix` in `terraform.tfvars` to include a unique suffix:
```hcl
bucket_prefix = "myapp-security-a1b2c3"
```

### Issue: GuardDuty detector already exists

**Error:**
```
Error: error creating GuardDuty Detector: BadRequestException: 
The request is rejected because a detector already exists
```

**Solution:**
Import existing detector:
```bash
terraform import aws_guardduty_detector.main <detector-id>
```

### Issue: Config recorder already enabled

**Error:**
```
Error: error creating AWS Config Configuration Recorder: 
MaxNumberOfConfigurationRecordersExceededException
```

**Solution:**
1. Check if Config is already enabled
2. Import existing recorder or disable it first
3. Consider using `terraform import`

### Issue: SNS subscription not confirming

**Solution:**
1. Check spam folder for confirmation emails
2. Verify email addresses in `terraform.tfvars`
3. Manually confirm via AWS Console if needed

---

## Cost Estimates

### Security Account (Monthly)
- **GuardDuty**: ~$5-10 (varies by AWS API calls and events)
- **Security Hub**: ~$5-10 (based on security checks)
- **AWS Config**: ~$10-20 (based on config items and rules)
- **S3 Storage**: ~$1-5 (depends on log volume)
- **KMS**: ~$1/month per key
- **Total**: ~$25-50/month

### Logging Account (Monthly)
- **CloudWatch Logs Ingestion**: ~$0.50 per GB
- **CloudWatch Logs Storage**: ~$0.03 per GB/month
- **S3 Storage (Standard)**: ~$0.023 per GB
- **S3 Storage (Glacier)**: ~$0.004 per GB
- **Kinesis Firehose**: ~$0.029 per GB
- **Total**: Varies significantly based on log volume (estimate $50-200/month)

**Cost Optimization Tips:**
1. Adjust log retention periods based on compliance needs
2. Enable S3 Intelligent Tiering for log archives
3. Use lifecycle policies to move old logs to Glacier
4. Review GuardDuty findings frequency settings
5. Disable unused AWS Config rules

---

## Security Best Practices

1. **Least Privilege**: IAM roles use minimal required permissions
2. **Encryption**: All S3 buckets encrypted, CloudWatch Logs use KMS
3. **Versioning**: Enabled on critical S3 buckets
4. **MFA**: Required for Security Admin role assumption
5. **External IDs**: Used for all cross-account role assumptions
6. **Logging**: All service logs captured and retained
7. **Monitoring**: EventBridge rules for critical security findings

---

## Next Steps

After deploying Security and Logging accounts:

1. **Deploy Networking** (Phase 2)
   - Production-Apps VPC
   - Production-Data VPC
   - NonProd-Apps VPC
   - NonProd-Data VPC
   - VPC Peering connections

2. **Deploy Shared Services** (Phase 3)
   - Route 53 hosted zones
   - ACM certificates
   - ECR repositories

3. **Configure Member Accounts**
   - Enable CloudTrail in all accounts pointing to Security account
   - Configure VPC Flow Logs to send to Logging account
   - Set up cross-account IAM roles

---

## Support

For issues or questions:
1. Check [Troubleshooting](#troubleshooting) section
2. Review Terraform documentation: https://www.terraform.io/docs
3. Check AWS documentation for specific services
4. Open an issue in the project repository

---

## License

Copyright © 2024. All rights reserved.
