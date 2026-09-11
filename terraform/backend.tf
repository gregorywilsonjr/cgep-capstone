terraform {
  backend "s3" {
    bucket         = "cgep-capstone-tfstate-gregorywilsonjr"
    key            = "capstone/terraform.tfstate"
    region         = "us-east-1"
    dynamodb_table = "cgep-capstone-tf-lock"
    encrypt        = true
  }
}
