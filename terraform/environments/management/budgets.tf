# ============================================================================
# AWS Budgets - Cost Monitoring and Alerts
# ============================================================================

# SNS topic for budget alerts
resource "aws_sns_topic" "budget_alerts" {
  name = "${var.project_name}-budget-alerts"

  tags = {
    Name    = "Budget Alerts"
    Purpose = "cost-monitoring"
  }
}

# SNS topic policy
resource "aws_sns_topic_policy" "budget_alerts" {
  arn = aws_sns_topic.budget_alerts.arn

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AWSBudgetsSNSPublishingPermissions"
        Effect = "Allow"
        Principal = {
          Service = "budgets.amazonaws.com"
        }
        Action   = "SNS:Publish"
        Resource = aws_sns_topic.budget_alerts.arn
      }
    ]
  })
}

# SNS email subscription (you need to confirm this manually)
# Uncomment and add your email address
# resource "aws_sns_topic_subscription" "budget_email" {
#   topic_arn = aws_sns_topic.budget_alerts.arn
#   protocol  = "email"
#   endpoint  = "your-email@example.com"
# }

# Total monthly budget
resource "aws_budgets_budget" "monthly_total" {
  name         = "${var.project_name}-monthly-total"
  budget_type  = "COST"
  limit_amount = var.monthly_budget_limit
  limit_unit   = "USD"
  time_unit    = "MONTHLY"

  notification {
    comparison_operator        = "GREATER_THAN"
    threshold                  = 80
    threshold_type             = "PERCENTAGE"
    notification_type          = "ACTUAL"
    subscriber_sns_topic_arns  = [aws_sns_topic.budget_alerts.arn]
  }

  notification {
    comparison_operator        = "GREATER_THAN"
    threshold                  = 100
    threshold_type             = "PERCENTAGE"
    notification_type          = "ACTUAL"
    subscriber_sns_topic_arns  = [aws_sns_topic.budget_alerts.arn]
  }

  notification {
    comparison_operator        = "GREATER_THAN"
    threshold                  = 90
    threshold_type             = "PERCENTAGE"
    notification_type          = "FORECASTED"
    subscriber_sns_topic_arns  = [aws_sns_topic.budget_alerts.arn]
  }
}

# EC2 specific budget
resource "aws_budgets_budget" "ec2_monthly" {
  name         = "${var.project_name}-ec2-monthly"
  budget_type  = "COST"
  limit_amount = "1000"
  limit_unit   = "USD"
  time_unit    = "MONTHLY"

  cost_filter {
    name = "Service"
    values = [
      "Amazon Elastic Compute Cloud - Compute"
    ]
  }

  notification {
    comparison_operator        = "GREATER_THAN"
    threshold                  = 80
    threshold_type             = "PERCENTAGE"
    notification_type          = "ACTUAL"
    subscriber_sns_topic_arns  = [aws_sns_topic.budget_alerts.arn]
  }
}

# RDS specific budget
resource "aws_budgets_budget" "rds_monthly" {
  name         = "${var.project_name}-rds-monthly"
  budget_type  = "COST"
  limit_amount = "800"
  limit_unit   = "USD"
  time_unit    = "MONTHLY"

  cost_filter {
    name = "Service"
    values = [
      "Amazon Relational Database Service"
    ]
  }

  notification {
    comparison_operator        = "GREATER_THAN"
    threshold                  = 80
    threshold_type             = "PERCENTAGE"
    notification_type          = "ACTUAL"
    subscriber_sns_topic_arns  = [aws_sns_topic.budget_alerts.arn]
  }
}

# Data Transfer budget (often overlooked cost)
resource "aws_budgets_budget" "data_transfer_monthly" {
  name         = "${var.project_name}-data-transfer-monthly"
  budget_type  = "COST"
  limit_amount = "200"
  limit_unit   = "USD"
  time_unit    = "MONTHLY"

  cost_filter {
    name = "Usage Type Group"
    values = [
      "Data Transfer"
    ]
  }

  notification {
    comparison_operator        = "GREATER_THAN"
    threshold                  = 80
    threshold_type             = "PERCENTAGE"
    notification_type          = "ACTUAL"
    subscriber_sns_topic_arns  = [aws_sns_topic.budget_alerts.arn]
  }
}
