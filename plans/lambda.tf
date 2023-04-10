resource "aws_lambda_function" "trivialscan_subdomains_queue" {
  filename         = "${abspath(path.module)}/${local.source_file}"
  source_code_hash = filebase64sha256("${abspath(path.module)}/${local.source_file}")
  function_name    = local.function_name
  role             = aws_iam_role.trivialscan_subdomains_queue_role.arn
  handler          = "app.handler"
  runtime          = local.python_version
  timeout          = local.timeout
  memory_size      = local.memory_size
  layers           = local.enable_dynatrace ? ["arn:aws:lambda:ap-southeast-2:725887861453:layer:Dynatrace_OneAgent_1_261_5_20230309-143152_python:1"] : []

  environment {
    variables = local.enable_dynatrace ? {
      APP_ENV                              = var.app_env
      APP_NAME                             = var.app_name
      LOG_LEVEL                            = var.log_level
      STORE_BUCKET                         = data.terraform_remote_state.trivialscan_s3.outputs.trivialscan_store_bucket
      BUILD_ENV                            = var.build_env
      AWS_LAMBDA_EXEC_WRAPPER              = "/opt/dynatrace"
      DT_TENANT                            = "xuf85063"
      DT_CLUSTER_ID                        = "-1273248646"
      DT_CONNECTION_BASE_URL               = "https://xuf85063.live.dynatrace.com"
      DT_CONNECTION_AUTH_TOKEN             = var.dynatrace_token
      DT_OPEN_TELEMETRY_ENABLE_INTEGRATION = "true"
      } : {
      APP_ENV      = var.app_env
      APP_NAME     = var.app_name
      LOG_LEVEL    = var.log_level
      STORE_BUCKET = data.terraform_remote_state.trivialscan_s3.outputs.trivialscan_store_bucket
      BUILD_ENV    = var.build_env
    }
  }
  lifecycle {
    create_before_destroy = true
  }
  depends_on = [
    aws_iam_role_policy_attachment.policy_attach
  ]
  tags = local.tags
}

resource "aws_lambda_permission" "allow_queue" {
  statement_id  = "${var.app_env}AllowExecutionFromSQS"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.trivialscan_subdomains_queue.arn
  principal     = "sqs.amazonaws.com"
  source_arn    = aws_sqs_queue.trivialscan_subdomains_queue.arn
}

resource "aws_lambda_event_source_mapping" "trivialscan_subdomains_queue_source" {
  event_source_arn = aws_sqs_queue.trivialscan_subdomains_queue.arn
  enabled          = true
  function_name    = aws_lambda_function.trivialscan_subdomains_queue.arn
  batch_size       = local.queue_batch_size
}

resource "aws_cloudwatch_log_group" "subdomain_logs" {
  skip_destroy      = var.app_env == "Prod"
  name              = "/aws/lambda/${aws_lambda_function.trivialscan_subdomains_queue.function_name}"
  retention_in_days = local.retention_in_days
}
