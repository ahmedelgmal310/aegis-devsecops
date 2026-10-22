# Keyless CI access: GitHub Actions exchanges its OIDC token for short-lived
# AWS credentials. No access keys are ever stored in GitHub.
resource "aws_iam_openid_connect_provider" "github" {
  url            = "https://token.actions.githubusercontent.com"
  client_id_list = ["sts.amazonaws.com"]
}

data "aws_iam_policy_document" "github_trust" {
  statement {
    actions = ["sts:AssumeRoleWithWebIdentity"]

    principals {
      type        = "Federated"
      identifiers = [aws_iam_openid_connect_provider.github.arn]
    }

    condition {
      test     = "StringEquals"
      variable = "token.actions.githubusercontent.com:aud"
      values   = ["sts.amazonaws.com"]
    }

    # Only this repository's workflows on the protected branch.
    condition {
      test     = "StringEquals"
      variable = "token.actions.githubusercontent.com:sub"
      values   = ["repo:${var.github_repository}:ref:refs/heads/${var.github_branch}"]
    }
  }
}

resource "aws_iam_role" "github_push" {
  name                 = "${var.name}-github-image-push"
  description          = "Assumed by the Aegis pipeline to push images to ECR"
  assume_role_policy   = data.aws_iam_policy_document.github_trust.json
  max_session_duration = 3600
}

data "aws_iam_policy_document" "image_push" {
  # GetAuthorizationToken does not support resource-level permissions.
  #checkov:skip=CKV_AWS_356:ecr:GetAuthorizationToken only accepts "*"
  statement {
    sid       = "RegistryLogin"
    actions   = ["ecr:GetAuthorizationToken"]
    resources = ["*"]
  }

  statement {
    sid = "PushLedgerImages"
    actions = [
      "ecr:BatchCheckLayerAvailability",
      "ecr:BatchGetImage",
      "ecr:CompleteLayerUpload",
      "ecr:InitiateLayerUpload",
      "ecr:PutImage",
      "ecr:UploadLayerPart",
    ]
    resources = [aws_ecr_repository.ledger.arn]
  }

  statement {
    sid       = "EncryptImageLayers"
    actions   = ["kms:Decrypt", "kms:GenerateDataKey"]
    resources = [aws_kms_key.images.arn]
  }
}

resource "aws_iam_role_policy" "image_push" {
  name   = "image-push"
  role   = aws_iam_role.github_push.id
  policy = data.aws_iam_policy_document.image_push.json
}
