# The Terraform as supplied for review, reconstructed from the assessment brief.
# Deliberately insecure: the IaC gate must flag every defect in it.

resource "aws_security_group" "accounts_db" {
  name        = "accounts-db"
  description = "accounts-api PostgreSQL"
  vpc_id      = "vpc-0123456789abcdef0"

  ingress {
    description = "PostgreSQL"
    from_port   = 5432
    to_port     = 5432
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_db_instance" "accounts" {
  identifier                  = "accounts-api"
  engine                      = "postgres"
  instance_class              = "db.m6g.large"
  allocated_storage           = 100
  username                    = "accounts"
  manage_master_user_password = true
  vpc_security_group_ids      = [aws_security_group.accounts_db.id]

  publicly_accessible     = true
  storage_encrypted       = false
  skip_final_snapshot     = true
  backup_retention_period = 0
}

resource "aws_cloudtrail" "main" {
  name           = "main"
  s3_bucket_name = "example-cloudtrail-logs"

  is_multi_region_trail         = false
  enable_log_file_validation    = false
  include_global_service_events = false
}
