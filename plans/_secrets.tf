variable "aws_secret_access_key" {
  description = "AWS_SECRET_ACCESS_KEY"
  type        = string
  sensitive   = true
}
variable "dynatrace_token" {
  description = "DYNATRACE_TOKEN"
  type        = string
  sensitive   = true
}
