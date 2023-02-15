output "trivialscan_subdomains_queue_arn" {
    value = aws_lambda_function.trivialscan_subdomains_queue.arn
}
output "trivialscan_subdomains_queue_role" {
    value = aws_iam_role.trivialscan_subdomains_queue_role.name
}
output "trivialscan_subdomains_queue_role_arn" {
    value = aws_iam_role.trivialscan_subdomains_queue_role.arn
}
output "trivialscan_subdomains_queue_policy_arn" {
    value = aws_iam_policy.trivialscan_subdomains_queue_policy.arn
}
