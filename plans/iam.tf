data "aws_iam_policy_document" "trivialscan_subdomains_queue_assume_role_policy" {
  statement {
    sid     = "${var.app_env}TrivialScannerSubdomainsQueueAssumeRole"
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
  }
}
data "aws_iam_policy_document" "trivialscan_subdomains_queue_iam_policy" {
  statement {
    sid = "${var.app_env}TrivialScannerSubdomainsQueueLogging"
    actions = [
      "logs:CreateLogGroup",
      "logs:CreateLogStream",
      "logs:PutLogEvents"
    ]
    resources = [
      "arn:aws:logs:${local.aws_default_region}:${local.aws_master_account_id}:log-group:/aws/lambda/${local.function_name}:*"
    ]
  }
  statement {
    sid = "${var.app_env}TrivialScannerSubdomainsQueueObjList"
    actions = [
      "s3:Head*",
      "s3:List*",
    ]
    resources = [
      "arn:aws:s3:::${data.terraform_remote_state.trivialscan_s3.outputs.trivialscan_store_bucket[0]}",
      "arn:aws:s3:::${data.terraform_remote_state.trivialscan_s3.outputs.trivialscan_store_bucket[0]}/*",
    ]
  }
  statement {
    sid = "${var.app_env}TrivialScannerSubdomainsQueueObjAccess"
    actions = [
      "s3:DeleteObject",
      "s3:GetObject",
      "s3:PutObject",
    ]
    resources = [
      "arn:aws:s3:::${data.terraform_remote_state.trivialscan_s3.outputs.trivialscan_store_bucket[0]}/${var.app_env}/*",
    ]
  }
  statement {
    sid = "${var.app_env}TrivialScannerSubdomainsQueueSecrets"
    actions = [
      "ssm:GetParameter",
    ]
    resources = [
      "arn:aws:ssm:${local.aws_default_region}:${local.aws_master_account_id}:parameter/${var.app_env}/${var.app_name}/*",
    ]
  }
  statement {
    sid = "${var.app_env}TrivialScannerSubdomainsQueueSQS"
    actions = [
      "sqs:ReceiveMessage",
      "sqs:DeleteMessage",
      "sqs:ChangeMessageVisibility",
      "sqs:Get*",
    ]
    resources = [
      aws_sqs_queue.trivialscan_subdomains_queue.arn
    ]
  }
}
resource "aws_iam_role" "trivialscan_subdomains_queue_role" {
  name               = "${lower(var.app_env)}_trivialscan_subdomains_queue_lambda_role"
  assume_role_policy = data.aws_iam_policy_document.trivialscan_subdomains_queue_assume_role_policy.json
  lifecycle {
    create_before_destroy = true
  }
}
resource "aws_iam_policy" "trivialscan_subdomains_queue_policy" {
  name   = "${lower(var.app_env)}_trivialscan_subdomains_queue_lambda_policy"
  path   = "/"
  policy = data.aws_iam_policy_document.trivialscan_subdomains_queue_iam_policy.json
}
resource "aws_iam_role_policy_attachment" "policy_attach" {
  role       = aws_iam_role.trivialscan_subdomains_queue_role.name
  policy_arn = aws_iam_policy.trivialscan_subdomains_queue_policy.arn
}
