output "ecr_repository_url" {
  description = "Push images here."
  value       = aws_ecr_repository.ledger.repository_url
}

output "github_push_role_arn" {
  description = "Role for aws-actions/configure-aws-credentials (role-to-assume)."
  value       = aws_iam_role.github_push.arn
}

output "image_kms_key_arn" {
  description = "KMS key that encrypts the images."
  value       = aws_kms_key.images.arn
}
