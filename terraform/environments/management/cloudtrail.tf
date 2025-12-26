# ============================================================================
# Organization-wide CloudTrail
# ============================================================================
# This file creates the organization-wide CloudTrail trail that logs all
# AWS API activity across all accounts in the organization.
#
# Architecture:
# - Trail created in Management account (required for organization trails)
# - Logs written to centralized S3 bucket in Security account
# - Uses KMS key from Security account for encryption
#
# Toggle: Set enable_cloudtrail = false to disable CloudTrail during dev/test
# ============================================================================

# Organization-wide CloudTrail Trail
resource "aws_cloudtrail" "organization" {
  count = var.enable_cloudtrail ? 1 : 0

  depends_on = [var.cloudtrail_bucket_name]

  name                          = "${var.project_name}-org-trail"
  s3_bucket_name                = var.cloudtrail_bucket_name
  kms_key_id                    = var.cloudtrail_kms_key_arn
  include_global_service_events = true
  is_multi_region_trail         = true
  is_organization_trail         = true
  enable_log_file_validation    = true

  event_selector {
    read_write_type           = "All"
    include_management_events = true

    data_resource {
      type = "AWS::S3::Object"
      values = [
        "arn:aws:s3:::*/AWSLogs/*"
      ]
    }

    data_resource {
      type = "AWS::Lambda::Function"
      values = [
        "arn:aws:lambda:*:*:function/*"
      ]
    }
  }

  insight_selector {
    insight_type = "ApiCallRateInsight"
  }

  tags = {
    Name       = "Organization CloudTrail"
    Purpose    = "audit-compliance"
    Compliance = "required"
  }
}
