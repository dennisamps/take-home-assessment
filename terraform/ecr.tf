# Section 2: build and release integrity (threat-model.md T1).
#
# Everything in this file lives in the tooling/build account. Production EKS and RDS are in a
# separate workload account and nothing here grants access to it.

# A tag, once pushed, can never be moved to a different image. Combined with tagging by
# commit SHA, one commit maps to exactly one image for the life of the repository.
#
# Tuning decision, not a waiver: Trivy check AWS-0030 (ECR scan-on-push disabled) is switched off
# for this one resource. Trivy in the pipeline is the single vulnerability scanner; native ECR
# scanning would be a second, overlapping scanner whose findings gate nothing. See decisions.md.
#trivy:ignore:AWS-0030
resource "aws_ecr_repository" "accounts_api" {
  name                 = "accounts-api"
  image_tag_mutability = "IMMUTABLE"
}

# The role GitHub Actions assumes through OIDC. Who may assume it is defined in the
# standalone trust policy file; see iam/README.md for what that scope denies.
resource "aws_iam_role" "github_build" {
  name               = "accounts-api-github-build"
  assume_role_policy = file("${path.module}/../iam/github-oidc-trust-policy.json")
}

# The build role's only permissions. It can push to and read from this one repository:
#   push image, signature, attestation  -> the upload actions and PutImage
#   read image for Syft, verify with Cosign -> BatchGetImage (also covers the OCI referrers
#                                              listing) and GetDownloadUrlForLayer
# It has no EKS, RDS, Secrets Manager or IAM permissions and no sts:AssumeRole, so it cannot
# deploy and cannot hop into the production account.
data "aws_iam_policy_document" "github_build" {
  statement {
    sid       = "EcrLogin"
    actions   = ["ecr:GetAuthorizationToken"]
    resources = ["*"] # this action does not support resource-level scoping
  }

  statement {
    sid = "PushPullAccountsApiOnly"
    actions = [
      "ecr:BatchCheckLayerAvailability",
      "ecr:BatchGetImage",
      "ecr:CompleteLayerUpload",
      "ecr:GetDownloadUrlForLayer",
      "ecr:InitiateLayerUpload",
      "ecr:PutImage",
      "ecr:UploadLayerPart",
    ]
    resources = [aws_ecr_repository.accounts_api.arn]
  }
}

resource "aws_iam_role_policy" "github_build" {
  name   = "ecr-push-accounts-api"
  role   = aws_iam_role.github_build.id
  policy = data.aws_iam_policy_document.github_build.json
}
