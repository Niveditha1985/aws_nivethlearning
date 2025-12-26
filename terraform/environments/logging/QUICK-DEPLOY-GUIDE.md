# Quick Deployment Guide - Security & Logging Accounts

## 🚀 Fast Track Deployment (15 minutes)

### Prerequisites Checklist
- [ ] AWS Organizations enabled in Management account
- [ ] Security account created (ID: 111111111111)
- [ ] Logging account created (ID: 888888888888)
- [ ] Terraform >= 1.5.0 installed
- [ ] AWS CLI configured
- [ ] Terraform state bucket created: `myapp-terraform-state`

---

## Step 1: Security Account (10 minutes)

```bash
# 1. Navigate to security directory
cd terraform/environments/security

# 2. Create terraform.tfvars from example
cp terraform.tfvars.example terraform.tfvars

# 3. Edit with your values (use vim, nano, or your editor)
# Update these critical values:
#   - security_account_id
#   - management_account_id
#   - member_account_ids
#   - bucket_prefix (make it unique!)
#   - security_alert_emails

vim terraform.tfvars

# 4. Update backend.tf with actual account ID
sed -i 's/SECURITY_ACCOUNT_ID/111111111111/g' backend.tf

# 5. Initialize Terraform
terraform init

# 6. Plan (review what will be created)
terraform plan -out=security.tfplan

# 7. Apply
terraform apply security.tfplan

# 8. Save outputs for later use
terraform output -json > security-outputs.json
```

**Expected Resources:** 
- 3 S3 buckets (CloudTrail, Config, GuardDuty)
- GuardDuty detector
- Security Hub with 2 standards
- AWS Config with 6 rules
- IAM Access Analyzer
- 2 SNS topics with EventBridge rules
- 5 IAM roles
- 3 KMS keys

---

## Step 2: Logging Account (5 minutes)

```bash
# 1. Navigate to logging directory
cd terraform/environments/logging

# 2. Create terraform.tfvars from example
cp terraform.tfvars.example terraform.tfvars

# 3. Edit with your values
# Update these critical values:
#   - logging_account_id
#   - management_account_id
#   - member_account_ids
#   - bucket_prefix (make it unique!)

vim terraform.tfvars

# 4. Update backend.tf with actual account ID
sed -i 's/LOGGING_ACCOUNT_ID/888888888888/g' backend.tf

# 5. Initialize Terraform
terraform init

# 6. Plan
terraform plan -out=logging.tfplan

# 7. Apply
terraform apply logging.tfplan

# 8. Save outputs
terraform output -json > logging-outputs.json
```

**Expected Resources:**
- 13 CloudWatch Log Groups
- 3 S3 buckets (CloudWatch archive, VPC Flow Logs, ALB logs)
- 1 Kinesis Firehose delivery stream
- 1 KMS key
- 5 IAM roles

---

## Step 3: Post-Deployment Configuration (Manual)

### A. Enable Security Hub Delegated Admin

From **Management account**:

```bash
# Switch to management account profile
export AWS_PROFILE=management

# Enable Security Hub organization integration
aws organizations enable-aws-service-access \
  --service-principal securityhub.amazonaws.com

# Delegate admin to Security account
aws securityhub enable-organization-admin-account \
  --admin-account-id 111111111111 \
  --region us-east-1
```

### B. Enable GuardDuty Delegated Admin

From **Management account**:

```bash
# Enable GuardDuty organization integration
aws organizations enable-aws-service-access \
  --service-principal guardduty.amazonaws.com

# Delegate admin to Security account
aws guardduty enable-organization-admin-account \
  --admin-account-id 111111111111 \
  --region us-east-1
```

### C. Confirm SNS Email Subscriptions

1. Check email inbox for AWS SNS confirmation emails
2. Click "Confirm subscription" for each email
3. Verify:
```bash
export AWS_PROFILE=security
aws sns list-subscriptions --region us-east-1
```

### D. Add Member Accounts to Security Hub

From **Security account**:

```bash
export AWS_PROFILE=security

# Create members (replace with your account IDs)
aws securityhub create-members \
  --account-details '[
    {"AccountId": "333333333333", "Email": "prod-apps@example.com"},
    {"AccountId": "444444444444", "Email": "prod-data@example.com"},
    {"AccountId": "555555555555", "Email": "nonprod-apps@example.com"},
    {"AccountId": "666666666666", "Email": "nonprod-data@example.com"},
    {"AccountId": "777777777777", "Email": "shared-services@example.com"}
  ]' \
  --region us-east-1

# Invite members
aws securityhub invite-members \
  --account-ids 333333333333 444444444444 555555555555 666666666666 777777777777 \
  --region us-east-1
```

---

## Step 4: Verification

### Security Account Health Check

```bash
export AWS_PROFILE=security

# 1. Verify Security Hub is enabled
aws securityhub describe-hub --region us-east-1

# 2. List Security Hub standards
aws securityhub get-enabled-standards --region us-east-1

# 3. Verify GuardDuty detector
aws guardduty list-detectors --region us-east-1

# 4. Check Config recorder status
aws configservice describe-configuration-recorder-status --region us-east-1

# 5. List Config rules
aws configservice describe-config-rules --region us-east-1

# 6. Verify S3 buckets
aws s3 ls | grep security
```

### Logging Account Health Check

```bash
export AWS_PROFILE=logging

# 1. List all log groups
aws logs describe-log-groups --region us-east-1 | grep logGroupName

# 2. Verify S3 buckets
aws s3 ls | grep logging

# 3. Check Kinesis Firehose stream
aws firehose describe-delivery-stream \
  --delivery-stream-name cloudwatch-logs-to-s3 \
  --region us-east-1

# 4. Verify KMS key exists
aws kms list-keys --region us-east-1
```

---

## Step 5: Test Cross-Account Access

### Test Security Account Access from Management

```bash
# Assume SecurityReadOnlyRole from Management account
aws sts assume-role \
  --role-arn arn:aws:iam::111111111111:role/SecurityReadOnlyRole \
  --role-session-name test-session \
  --external-id "your-external-id"

# If successful, you'll get temporary credentials
```

### Test Logging Account Access

```bash
# Assume log write role from member account
aws sts assume-role \
  --role-arn arn:aws:iam::888888888888:role/AllowMemberAccountsToWriteLogs \
  --role-session-name test-session \
  --external-id "your-external-id"
```

---

## Troubleshooting Quick Fixes

### Issue: "Bucket already exists"
```bash
# Solution: Change bucket_prefix in terraform.tfvars
bucket_prefix = "myapp-security-$(date +%s)"
```

### Issue: "Can't assume role"
```bash
# Verify role exists
aws iam get-role --role-name OrganizationAccountAccessRole

# Check your credentials
aws sts get-caller-identity
```

### Issue: "Config recorder already exists"
```bash
# List existing recorders
aws configservice describe-configuration-recorders

# Delete if needed (careful!)
aws configservice delete-configuration-recorder \
  --configuration-recorder-name default

# Or import into Terraform
terraform import aws_config_configuration_recorder.main default
```

---

## What's Next?

After successful deployment of Security and Logging accounts:

1. ✅ **Phase 1 Complete**: Management, Security, and Logging accounts configured
2. ⏭️ **Phase 2**: Deploy networking (VPCs, subnets, peering)
3. ⏭️ **Phase 3**: Deploy shared services (Route 53, ACM, ECR)

---

## Quick Reference

### Account IDs
| Account | Example ID | Purpose |
|---------|-----------|---------|
| Management | 222222222222 | AWS Organizations root |
| Security | 111111111111 | Security Hub, GuardDuty, Config |
| Logging | 888888888888 | CloudWatch Logs, S3 archives |
| Prod-Apps | 333333333333 | Production workloads |
| Prod-Data | 444444444444 | Production databases |
| NonProd-Apps | 555555555555 | Dev/Staging workloads |
| NonProd-Data | 666666666666 | Dev/Staging databases |
| Shared-Services | 777777777777 | CI/CD, DNS, ECR |

### Important ARNs
```bash
# Security Hub delegated admin role
arn:aws:iam::111111111111:role/aws-service-role/securityhub.amazonaws.com/AWSServiceRoleForSecurityHub

# GuardDuty delegated admin role
arn:aws:iam::111111111111:role/aws-service-role/guardduty.amazonaws.com/AWSServiceRoleForAmazonGuardDuty

# CloudWatch Logs cross-account role
arn:aws:iam::888888888888:role/AllowMemberAccountsToWriteLogs

# VPC Flow Logs role
arn:aws:iam::888888888888:role/VPCFlowLogsRole
```

### Useful Commands

```bash
# List all accounts in organization
aws organizations list-accounts

# Check which account you're using
aws sts get-caller-identity

# Assume a role
aws sts assume-role \
  --role-arn arn:aws:iam::ACCOUNT_ID:role/ROLE_NAME \
  --role-session-name SESSION_NAME

# Switch Terraform workspace
terraform workspace select security

# View Terraform state
terraform state list

# Remove resource from state (without deleting)
terraform state rm aws_resource.name
```

---

## Estimated Costs

**Security Account:** ~$30-50/month
- GuardDuty: $5-10
- Security Hub: $5-10  
- Config: $10-20
- S3/KMS: $5-10

**Logging Account:** ~$50-200/month (varies with log volume)
- CloudWatch Logs: $0.50/GB ingestion
- S3 Storage: $0.023/GB standard, $0.004/GB Glacier
- Kinesis Firehose: $0.029/GB

**Total for both:** ~$80-250/month

---

## Support Contacts

- AWS Support: https://console.aws.amazon.com/support
- Terraform Docs: https://www.terraform.io/docs
- AWS Security Best Practices: https://aws.amazon.com/security/best-practices/

---

**Deployment Time:** ~15-20 minutes  
**Difficulty:** Intermediate  
**Prerequisites Met:** ✅ Phase 1 Complete
