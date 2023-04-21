resource "aws_sqs_queue" "trivialscan_subdomains_dlq" {
  name = "${lower(var.app_env)}-subdomains-dlq"
  tags = local.tags
}

resource "aws_sqs_queue" "trivialscan_subdomains_queue" {
  name                       = "${lower(var.app_env)}-subdomains"
  visibility_timeout_seconds = 900
  message_retention_seconds  = 86400
  redrive_policy             = "{\"deadLetterTargetArn\":\"${aws_sqs_queue.trivialscan_subdomains_dlq.arn}\",\"maxReceiveCount\":2}"
  tags                       = local.tags
}
