variable "name" {
  description = "Prefix for every resource name."
  type        = string
  default     = "aegis"
}

variable "region" {
  description = "AWS region to deploy into."
  type        = string
  default     = "eu-central-1"
}

variable "github_repository" {
  description = "GitHub repository (owner/name) allowed to push images through OIDC."
  type        = string
  default     = "ahmedelgmal310/aegis-devsecops"

  validation {
    condition     = can(regex("^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$", var.github_repository))
    error_message = "github_repository must look like owner/name."
  }
}

variable "github_branch" {
  description = "Only workflows running on this branch may assume the push role."
  type        = string
  default     = "main"
}
