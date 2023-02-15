data "terraform_remote_state" "trivialscan_s3" {
  backend = "s3"
  config = {
    bucket      = "stateful-trivialsec"
    key         = "terraform/trivialscan-s3"
    region      = "ap-southeast-2"
  }
}
