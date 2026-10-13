# Remote state so the GitHub pipeline and the laptop see the same infrastructure.
# Bucket was bootstrapped with the AWS CLI (it must exist before Terraform can use it).
terraform {
  backend "s3" {
    bucket  = "acme-health-intake-tfstate-c34bf5d7"
    key     = "capstone/terraform.tfstate"
    region  = "us-east-1"
    encrypt = true
  }
}
