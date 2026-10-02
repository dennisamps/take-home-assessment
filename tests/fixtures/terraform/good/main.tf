# Section 4: corrected RDS, database security group and CloudTrail.
# Defects and ranking: review/terraform.md. Recurrence is prevented by Trivy's built-in checks
# plus the custom checks in policies/terraform/. Traces to threat-model.md T2 and T5.
#
# These resources belong to the workload/production account, not the tooling account that
# holds ECR. In a real layout this file would sit in that account's own root module.
provider "aws" {
  alias  = "workload"
  region = "ap-south-1"
}

variable "vpc_id" {
  description = "VPC that holds the shared EKS cluster and the database."
  type        = string
}

variable "db_subnet_group_name" {
  description = "DB subnet group made only of private subnets."
  type        = string
}

variable "accounts_api_pod_security_group_id" {
  description = "Security group attached to accounts-api pods (security groups for pods), not the shared node group."
  type        = string
}

variable "cloudtrail_bucket_name" {
  description = "S3 bucket for CloudTrail logs, owned by the log-archive account."
  type        = string
}

variable "cloudtrail_kms_key_arn" {
  description = "KMS key in the log-archive account used to encrypt CloudTrail logs."
  type        = string
}

# --- Database network path -------------------------------------------------

resource "aws_security_group" "accounts_db" {
  provider    = aws.workload
  name        = "accounts-db"
  description = "accounts-api PostgreSQL: ingress from accounts-api pods only"
  vpc_id      = var.vpc_id
}

# Was 5432 from 0.0.0.0/0. The only source is now the accounts-api pod security group, so other
# tenants on the same nodes cannot reach the database (T3) and the internet cannot at all.
resource "aws_vpc_security_group_ingress_rule" "accounts_db_from_pods" {
  provider                     = aws.workload
  security_group_id            = aws_security_group.accounts_db.id
  description                  = "PostgreSQL from accounts-api pods"
  ip_protocol                  = "tcp"
  from_port                    = 5432
  to_port                      = 5432
  referenced_security_group_id = var.accounts_api_pod_security_group_id
}

# --- Database --------------------------------------------------------------

resource "aws_kms_key" "accounts_db" {
  provider            = aws.workload
  description         = "accounts-api RDS storage and master credential"
  enable_key_rotation = true
}

resource "aws_db_instance" "accounts" {
  provider          = aws.workload
  identifier        = "accounts-api"
  engine            = "postgres"
  instance_class    = "db.m6g.large"
  allocated_storage = 100
  username          = "accounts"

  manage_master_user_password   = true
  master_user_secret_kms_key_id = aws_kms_key.accounts_db.arn

  db_subnet_group_name   = var.db_subnet_group_name
  vpc_security_group_ids = [aws_security_group.accounts_db.id]

  publicly_accessible = false # was true
  storage_encrypted   = true  # was false
  kms_key_id          = aws_kms_key.accounts_db.arn

  backup_retention_period = 35 # was 0 (backups off); 35 days is the RDS maximum

  skip_final_snapshot       = false # was true
  final_snapshot_identifier = "accounts-api-final"
  deletion_protection       = true
}

# --- Audit trail -----------------------------------------------------------

resource "aws_cloudtrail" "main" {
  provider       = aws.workload
  name           = "main"
  s3_bucket_name = var.cloudtrail_bucket_name
  kms_key_id     = var.cloudtrail_kms_key_arn

  is_multi_region_trail         = true # was false
  enable_log_file_validation    = true # was false
  include_global_service_events = true # was false
}
