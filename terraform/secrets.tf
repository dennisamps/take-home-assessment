# Section 6: the secrets accounts-api holds, their encryption key and rotation schedule.
# Delivery to the pod: kubernetes/accounts-api-secrets.yaml. Procedures: data-protection/rotation.md.
# Traces to threat-model.md T2 and T4. Workload/production account, like review-remediate.tf.
#
# No secret VALUE appears here or in Terraform state: there is no aws_secretsmanager_secret_version.
#
# STATUS: this file configures the secrets, their key and the rotation SCHEDULE. The production
# rotation Lambda implementing the alternating-user strategy is specified (by ARN, as a variable)
# but is not deployed or tested in this assessment.

variable "kms_admin_role_arn" {
  description = "Role that administers the secrets key. It can manage the key but cannot decrypt with it."
  type        = string
}

variable "accounts_api_pod_role_arn" {
  description = "IAM role bound to the accounts-api service account through EKS Pod Identity."
  type        = string
}

variable "db_rotation_lambda_arn" {
  description = "Secrets Manager rotation function for PostgreSQL, alternating-users strategy. Not part of this repository."
  type        = string
}

variable "db_rotation_lambda_role_arn" {
  description = "Execution role of the rotation function."
  type        = string
}

# Key administration is separated from key use: the administrator cannot decrypt, and the
# workload can only decrypt, only through Secrets Manager.
data "aws_iam_policy_document" "accounts_api_secrets_key" {
  statement {
    sid    = "AdministerButNeverDecrypt"
    effect = "Allow"
    principals {
      type        = "AWS"
      identifiers = [var.kms_admin_role_arn]
    }
    actions = [
      "kms:CancelKeyDeletion",
      "kms:DescribeKey",
      "kms:DisableKey",
      "kms:EnableKey",
      "kms:EnableKeyRotation",
      "kms:GetKeyPolicy",
      "kms:GetKeyRotationStatus",
      "kms:ListResourceTags",
      "kms:PutKeyPolicy",
      "kms:ScheduleKeyDeletion",
      "kms:TagResource",
      "kms:UntagResource",
    ]
    resources = ["*"] # in a key policy "*" means this key
  }

  statement {
    sid    = "WorkloadDecryptsThroughSecretsManagerOnly"
    effect = "Allow"
    principals {
      type        = "AWS"
      identifiers = [var.accounts_api_pod_role_arn]
    }
    actions   = ["kms:Decrypt"]
    resources = ["*"]
    condition {
      test     = "StringEquals"
      variable = "kms:ViaService"
      values   = ["secretsmanager.ap-south-1.amazonaws.com"]
    }
  }

  statement {
    sid    = "RotationFunctionReadsAndWritesThroughSecretsManagerOnly"
    effect = "Allow"
    principals {
      type        = "AWS"
      identifiers = [var.db_rotation_lambda_role_arn]
    }
    actions   = ["kms:Decrypt", "kms:GenerateDataKey"]
    resources = ["*"]
    condition {
      test     = "StringEquals"
      variable = "kms:ViaService"
      values   = ["secretsmanager.ap-south-1.amazonaws.com"]
    }
  }
}

resource "aws_kms_key" "accounts_api_secrets" {
  provider            = aws.workload
  description         = "accounts-api secrets in Secrets Manager"
  enable_key_rotation = true
  policy              = data.aws_iam_policy_document.accounts_api_secrets_key.json
}

# Database credential: scheduled to rotate every 30 days. The specified alternating-users
# strategy keeps the previous user valid until the next rotation, so running pods are not cut off.
# The schedule is configured below; the function it invokes is not included (see STATUS above).
resource "aws_secretsmanager_secret" "db_credentials" {
  provider   = aws.workload
  name       = "accounts-api/db-credentials"
  kms_key_id = aws_kms_key.accounts_api_secrets.arn
}

resource "aws_secretsmanager_secret_rotation" "db_credentials" {
  provider            = aws.workload
  secret_id           = aws_secretsmanager_secret.db_credentials.id
  rotation_lambda_arn = var.db_rotation_lambda_arn

  rotation_rules {
    automatically_after_days = 30
  }
}

# KYC provider API key: issued by the provider, so it is rotated by runbook every 90 days
# (data-protection/rotation.md), not by a rotation function.
resource "aws_secretsmanager_secret" "kyc_api_key" {
  provider   = aws.workload
  name       = "accounts-api/kyc-api-key"
  kms_key_id = aws_kms_key.accounts_api_secrets.arn
}
