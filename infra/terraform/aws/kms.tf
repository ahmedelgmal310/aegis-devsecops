data "aws_caller_identity" "current" {}
data "aws_partition" "current" {}

# Customer-managed key for container images at rest, rotated yearly.
resource "aws_kms_key" "images" {
  description             = "Encrypts ${var.name} container images at rest"
  enable_key_rotation     = true
  deletion_window_in_days = 30
  policy                  = data.aws_iam_policy_document.kms.json
}

resource "aws_kms_alias" "images" {
  name          = "alias/${var.name}-images"
  target_key_id = aws_kms_key.images.key_id
}

data "aws_iam_policy_document" "kms" {
  # In a key policy, "*" refers to this key only, and the account root
  # statement is what lets IAM policies grant access to the key.
  #checkov:skip=CKV_AWS_109:Key policy; the resource is the key itself
  #checkov:skip=CKV_AWS_111:Key policy; the resource is the key itself
  #checkov:skip=CKV_AWS_356:Key policy; the resource is the key itself
  statement {
    sid       = "AccountAdministration"
    actions   = ["kms:*"]
    resources = ["*"]

    principals {
      type        = "AWS"
      identifiers = ["arn:${data.aws_partition.current.partition}:iam::${data.aws_caller_identity.current.account_id}:root"]
    }
  }
}
