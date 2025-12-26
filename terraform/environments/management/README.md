# Bootstrap - Management Account Setup

This directory contains Terraform code to bootstrap the Management account and create AWS Organizations.

## Prerequisites

Before running this Terraform:

1. **Create your first AWS account manually** (this becomes the Management account)
   - Go to https://aws.amazon.com/
   - Click "Create an AWS Account"
   - Use email: `yourname+aws-management@gmail.com`
   - Complete signup process
   - **IMPORTANT:** Enable MFA on root user immediately

2. **Configure AWS CLI with Management account credentials**
   ```bash
   aws configure --profile myapp-management
   # Enter your Access Key ID
   # Enter your Secret Access Key
   # Region: us-east-1
   # Output format: json
   ```

3. **Verify access**
   ```bash
   aws sts get-caller-identity --profile myapp-management
   ```

## What This Terraform Creates

- AWS Organizations
- Organizational Units (OUs)
- Service Control Policies (SCPs)
- CloudTrail (organization-wide)
- Config (organization-wide)
- Budget alerts
- Initial IAM roles and policies

## Step-by-Step Execution

### 1. Update Variables

Edit `terraform.tfvars` and update:
- `management_account_email`
- `organization_name`
- `aws_region`
- All other account emails

### 2. Initialize Terraform

```bash
cd terraform/bootstrap
terraform init
```

### 3. Review Plan

```bash
terraform plan
```

**IMPORTANT:** Review carefully. Creating Organizations is a significant change.

### 4. Apply

```bash
terraform apply
```

Type `yes` when prompted.

### 5. Save Outputs

```bash
terraform output -json > ../../outputs/bootstrap-outputs.json
```

## What Happens Next

After bootstrap is complete:
1. AWS Organizations is enabled
2. OUs are created
3. You can create member accounts using terraform in `accounts/management/`

## Cleanup

**WARNING:** Deleting AWS Organizations requires:
1. Removing all member accounts first
2. Deleting all SCPs
3. Then you can run `terraform destroy`

**DO NOT** run destroy unless you're completely tearing down the environment.

## Troubleshooting

### "Organizations already enabled"
If you get this error, it means Organizations is already enabled. You'll need to import existing resources:

```bash
terraform import aws_organizations_organization.main <org-id>
```

### "Access Denied"
Make sure:
- You're using the root account credentials or an admin IAM user
- Your AWS CLI profile is set correctly
- You have MFA enabled if required
