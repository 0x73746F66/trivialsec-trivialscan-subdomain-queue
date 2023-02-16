data "terraform_remote_state" "trivialscan_s3" {
  backend = "s3"
  config = {
    bucket      = "stateful-trivialsec"
    key         = "terraform/trivialscan-s3"
    region      = "ap-southeast-2"
  }
}
data "terraform_remote_state" "reconnaissance_queue" {
  backend = "s3"
  config = {
    bucket      = "stateful-trivialsec"
    key         = "terraform${var.app_env == "Dev" ? "/${lower(var.app_env)}" : ""}/trivialscan-monitor-queue"
    region      = "ap-southeast-2"
  }
}
