# Bootstrap Execution Guide

Follow these steps **exactly** to bootstrap your AWS multi-account architecture.

## Prerequisites Checklist

Before starting, ensure you have:

- [ ] Created your first AWS account (will become Management account)
- [ ] Enabled MFA on root user of Management account
- [ ] AWS CLI installed and configured
- [ ] Terraform >= 1.6.0 installed
- [ ] 8 email addresses ready (Gmail+ approach is fine)
- [ ] Access to email inbox for verification

## Step 1: Create Management Account (Manual)

If you don't already have an AWS account:

1. Go to https://aws.amazon.com/
2. Click "Create an AWS Account"
3. Use email: `yourname+aws-management@gmail.com`
4. Complete signup process
5. **CRITICAL:** Immediately enable MFA on root user
   - Go to IAM → Dashboard → Add MFA
   - Use authenticator app (Google Authenticator, Authy, etc.)

## Step 2: Create IAM Admin User (Manual)

**IMPORTANT:** Don't use root credentials for Terraform. Create an admin IAM user:

1. Sign in to AWS Console as root
2. Go to IAM → Users → Add users
3. Username: `terraform-admin`
4. Check "Provide user access to the AWS Management Console" (optional)
5. Check "Access key - Programmatic access" (required)
6. Click "Next"
7. Select "Attach policies directly"
8. Search and select: `AdministratorAccess`
9. Click "Next" → "Create user"
10. **SAVE** the Access Key ID and Secret Access Key (you won't see them again!)
11. Enable MFA for this user too

## Step 3: Configure AWS CLI Profile

```bash
# Configure profile for Management account
aws configure --profile myapp-management

# Enter the following:
AWS Access Key ID: <your-terraform-admin-access-key>
AWS Secret Access Key: <your-terraform-admin-secret-key>
Default region name: us-east-1
Default output format: json
```

Verify access:
```bash
aws sts get-caller-identity --profile myapp-management
```

You should see output like:
```json
{
    "UserId": "AIDAXXXXXXXXXXXXXXXXX",
    "Account": "123456789012",
    "Arn": "arn:aws:iam::123456789012:user/terraform-admin"
}
```

## Step 4: Set AWS Profile Environment Variable

```bash
export AWS_PROFILE=myapp-management

# Verify it's set
echo $AWS_PROFILE
```

## Step 5: Clone/Navigate to Your Repository

```bash
cd ~/projects
git clone <your-repo-url> myapp-infrastructure
cd myapp-infrastructure/terraform/bootstrap
```

## Step 6: Update terraform.tfvars

Copy the example file:
```bash
cp terraform.tfvars.example terraform.tfvars
```

Edit `terraform.tfvars` with your values:
```bash
# Use your preferred editor
vim terraform.tfvars
# OR
code terraform.tfvars
```

**IMPORTANT:** Update these values:
- All email addresses (replace `yourname` with your actual Gmail username)
- `monthly_budget_limit` if needed
- Verify `aws_region` is correct

Example:
```hcl
management_account_email      = "john.doe+aws-management@gmail.com"
security_account_email        = "john.doe+aws-security@gmail.com"
# ... etc
```

## Step 7: Initialize Terraform

```bash
terraform init
```

Expected output:
```
Initializing the backend...
Initializing provider plugins...
- Finding hashicorp/aws versions matching "~> 5.0"...
- Installing hashicorp/aws v5.x.x...
Terraform has been successfully initialized!
```

## Step 8: Validate Configuration

```bash
terraform validate
```

Expected output:
```
Success! The configuration is valid.
```

## Step 9: Review the Plan

**CRITICAL:** Review this carefully before applying!

```bash
terraform plan -out=tfplan
```

Review the output. You should see approximately:
- 7 new accounts to be created
- 4 Organizational Units
- 5 Service Control Policies
- CloudTrail configuration
- AWS Config setup
- 4 Budgets
- S3 buckets for logs

**Things to verify:**
- [ ] All email addresses are correct
- [ ] Account names are correct
- [ ] Region is us-east-1 (or your chosen region)
- [ ] No unexpected deletions or modifications

## Step 10: Apply the Configuration

**WARNING:** This will create real AWS resources and accounts!

```bash
terraform apply tfplan
```

Type `yes` when prompted.

**Expected duration:** 5-10 minutes

The process will:
1. Create AWS Organizations ✓
2. Create 4 Organizational Units ✓
3. Create 7 member accounts ✓ (this takes the longest)
4. Apply Service Control Policies ✓
5. Configure CloudTrail ✓
6. Configure AWS Config ✓
7. Create budgets ✓

## Step 11: Save Outputs

```bash
# Create outputs directory if it doesn't exist
mkdir -p ../../outputs

# Save outputs to JSON file
terraform output -json > ../../outputs/bootstrap-outputs.json

# Display account IDs
terraform output
```

Save the account IDs shown - you'll need them!

## Step 12: Subscribe to Budget Alerts

1. Check your email inbox
2. You'll receive an email from AWS SNS: "AWS Notification - Subscription Confirmation"
3. Click the "Confirm subscription" link
4. You should see: "Subscription confirmed!"

## Step 13: Verify Account Creation

Check each account was created:

```bash
aws organizations list-accounts --profile myapp-management
```

You should see 8 accounts total (1 management + 7 member accounts).

## Step 14: Access Member Accounts

To access any member account, use the `OrganizationAccountAccessRole`:

```bash
# Example: Access Security account
aws sts assume-role \
  --role-arn arn:aws:iam::<SECURITY_ACCOUNT_ID>:role/OrganizationAccountAccessRole \
  --role-session-name SecurityAccess \
  --profile myapp-management
```

**TIP:** The outputs include ready-to-use commands for each account.

## Step 15: Set Up AWS CLI Profiles for Each Account

For easier access, configure profiles for each account:

Edit `~/.aws/config`:
```ini
[profile myapp-management]
region = us-east-1
output = json

[profile myapp-security]
region = us-east-1
source_profile = myapp-management
role_arn = arn:aws:iam::<SECURITY_ACCOUNT_ID>:role/OrganizationAccountAccessRole

[profile myapp-shared-services]
region = us-east-1
source_profile = myapp-management
role_arn = arn:aws:iam::<SHARED_SERVICES_ACCOUNT_ID>:role/OrganizationAccountAccessRole

[profile myapp-logging]
region = us-east-1
source_profile = myapp-management
role_arn = arn:aws:iam::<LOGGING_ACCOUNT_ID>:role/OrganizationAccountAccessRole

[profile myapp-prod-apps]
region = us-east-1
source_profile = myapp-management
role_arn = arn:aws:iam::<PROD_APPS_ACCOUNT_ID>:role/OrganizationAccountAccessRole

[profile myapp-prod-data]
region = us-east-1
source_profile = myapp-management
role_arn = arn:aws:iam::<PROD_DATA_ACCOUNT_ID>:role/OrganizationAccountAccessRole

[profile myapp-nonprod-apps]
region = us-east-1
source_profile = myapp-management
role_arn = arn:aws:iam::<NONPROD_APPS_ACCOUNT_ID>:role/OrganizationAccountAccessRole

[profile myapp-nonprod-data]
region = us-east-1
source_profile = myapp-management
role_arn = arn:aws:iam::<NONPROD_DATA_ACCOUNT_ID>:role/OrganizationAccountAccessRole
```

Replace `<ACCOUNT_ID>` with actual account IDs from Step 11.

Test access:
```bash
aws sts get-caller-identity --profile myapp-security
```

## Step 16: Commit to Git

```bash
cd ~/projects/myapp-infrastructure

# Add files (but NOT terraform.tfvars which has sensitive data)
git add terraform/bootstrap/*.tf
git add terraform/bootstrap/README.md
git add terraform/bootstrap/.gitignore
git add outputs/bootstrap-outputs.json

# Commit
git commit -m "feat: bootstrap AWS Organizations and member accounts"

# Push
git push origin main
```

## Important Security Notes

1. **Never commit `terraform.tfvars`** - it contains email addresses
2. **Enable MFA on all root accounts** - AWS will send password reset emails to each account's email
3. **Store account IDs securely** - you'll need them for the next phases
4. **The terraform state contains sensitive data** - keep it secure

## Next Steps

✅ Phase 1 Complete!

You now have:
- AWS Organizations set up
- 7 member accounts created
- Service Control Policies applied
- CloudTrail logging to S3
- AWS Config monitoring compliance
- Budget alerts configured

**Next:** Phase 2 - Configure Security Account and enable security services

Proceed to: `terraform/accounts/security/`

## Troubleshooting

### Error: "Email already exists"

If you see this error, it means the email address is already associated with an AWS account.
- Solution: Use a different email address or use the Gmail+ trick with a different suffix

### Error: "AWS Organizations is already enabled"

This means you already have Organizations enabled.
- Solution: Import the existing organization: `terraform import aws_organizations_organization.main <org-id>`

### Error: "Access Denied"

Make sure:
- You're using the correct AWS profile
- The IAM user has AdministratorAccess
- MFA is properly configured if required

### Accounts are created but showing "SUSPENDED"

This is normal immediately after creation. Wait 5-10 minutes and check again.

### Can't assume role in member account

Wait a few minutes after account creation. The OrganizationAccountAccessRole takes time to propagate.

## Verification Checklist

Before moving to next phase, verify:

- [ ] All 7 member accounts created successfully
- [ ] Can assume role in each account using AWS CLI
- [ ] CloudTrail is logging (check S3 bucket)
- [ ] AWS Config is recording (check S3 bucket)
- [ ] Budget alerts email confirmed
- [ ] All account root users have MFA enabled
- [ ] Outputs saved to `outputs/bootstrap-outputs.json`
- [ ] AWS CLI profiles configured for all accounts
- [ ] Code committed to Git (without sensitive files)

## Success Criteria

You know you're successful when:

1. `terraform output` shows all account IDs
2. You can run `aws sts get-caller-identity --profile myapp-security` (and other accounts)
3. You see CloudTrail logs in S3 bucket
4. You received and confirmed budget alerts email
5. No errors in terraform apply

---

**Time estimate:** 30-45 minutes (including account creation wait time)

**Cost impact:** ~$2-5/month for CloudTrail and Config storage

**Ready for next phase?** Yes! Proceed to Security account setup.
