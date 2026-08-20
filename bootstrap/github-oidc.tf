# =============================================================================
# GITHUB OIDC PROVIDER FOR AWS AUTHENTICATION
# =============================================================================
#
# PURPOSE:
# This file configures GitHub Actions to authenticate with AWS using OIDC
# (OpenID Connect) instead of static access keys.
#
# HOW IT WORKS:
# 1. GitHub Actions requests a JWT token from GitHub's OIDC provider
# 2. AWS STS validates the token
# 3. AWS assumes the IAM role
# 4. Terraform uses temporary AWS credentials
#
# =============================================================================

# -----------------------------------------------------------------------------
# GITHUB OIDC PROVIDER
# -----------------------------------------------------------------------------

data "tls_certificate" "github" {
  url = "https://token.actions.githubusercontent.com/.well-known/openid-configuration"
}

resource "aws_iam_openid_connect_provider" "github" {
  url = "https://token.actions.githubusercontent.com"

  client_id_list = [
    "sts.amazonaws.com"
  ]

  thumbprint_list = [
    data.tls_certificate.github.certificates[0].sha1_fingerprint
  ]

  tags = {
    Name = "github-actions-oidc"
  }
}

# =============================================================================
# IAM ROLE FOR GITHUB ACTIONS
# =============================================================================

resource "aws_iam_role" "github_actions_terraform" {
  name = "${var.project_name}-github-terraform"

  # ---------------------------------------------------------------------------
  # TRUST POLICY
  # ---------------------------------------------------------------------------
  # Only GitHub Actions from:
  #
  # Repository:
  # Naresh-github-Actions/techitfactory-infra
  #
  # Branch:
  # main
  #
  # can assume this role.
  # ---------------------------------------------------------------------------

  assume_role_policy = jsonencode({
    Version = "2012-10-17"

    Statement = [
      {
        Effect = "Allow"

        Principal = {
          Federated = aws_iam_openid_connect_provider.github.arn
        }

        Action = "sts:AssumeRoleWithWebIdentity"

        Condition = {
          StringEquals = {
            "token.actions.githubusercontent.com:aud" = "sts.amazonaws.com"

            "token.actions.githubusercontent.com:sub" = "repo:Naresh-githb-Actions/techitfactory-infra:ref:refs/heads/main"

            #"token.actions.githubusercontent.com:sub" = "repo:Naresh-githb-Actions/techitfactory-infra:ref:refs/heads/main"
          }
        }
      }
    ]
  })

  tags = {
    Name = "${var.project_name}-github-terraform"
  }
}

# =============================================================================
# IAM POLICY FOR TERRAFORM OPERATIONS
# =============================================================================

resource "aws_iam_role_policy" "github_actions_terraform" {
  name = "terraform-permissions"

  role = aws_iam_role.github_actions_terraform.id

  policy = jsonencode({
    Version = "2012-10-17"

    Statement = [

      # -----------------------------------------------------------------------
      # TERRAFORM STATE ACCESS
      # -----------------------------------------------------------------------

      {
        Sid    = "TerraformStateAccess"
        Effect = "Allow"

        Action = [
          "s3:GetObject",
          "s3:PutObject",
          "s3:DeleteObject",
          "s3:ListBucket"
        ]

        Resource = [
          aws_s3_bucket.terraform_state.arn,
          "${aws_s3_bucket.terraform_state.arn}/*"
        ]
      },

      # -----------------------------------------------------------------------
      # TERRAFORM STATE LOCKING
      # -----------------------------------------------------------------------

      {
        Sid    = "TerraformLockAccess"
        Effect = "Allow"

        Action = [
          "dynamodb:GetItem",
          "dynamodb:PutItem",
          "dynamodb:DeleteItem"
        ]

        Resource = aws_dynamodb_table.terraform_lock.arn
      },

      # -----------------------------------------------------------------------
      # KMS ACCESS
      # -----------------------------------------------------------------------

      {
        Sid    = "KMSAccess"
        Effect = "Allow"

        Action = [
          "kms:Decrypt",
          "kms:Encrypt",
          "kms:GenerateDataKey"
        ]

        Resource = aws_kms_key.terraform_state.arn
      },

      # -----------------------------------------------------------------------
      # EC2 / VPC PERMISSIONS
      # -----------------------------------------------------------------------

      {
        Sid    = "EC2VPCFullAccess"
        Effect = "Allow"

        Action = [
          "ec2:*",
          "elasticloadbalancing:*"
        ]

        Resource = "*"
      },

      # -----------------------------------------------------------------------
      # EKS PERMISSIONS
      # -----------------------------------------------------------------------

      {
        Sid    = "EKSFullAccess"
        Effect = "Allow"

        Action = [
          "eks:*",
          "iam:CreateServiceLinkedRole"
        ]

        Resource = "*"
      },

      # -----------------------------------------------------------------------
      # IAM PERMISSIONS
      # -----------------------------------------------------------------------

      {
        Sid    = "IAMManagement"
        Effect = "Allow"

        Action = [
          "iam:CreateRole",
          "iam:DeleteRole",
          "iam:AttachRolePolicy",
          "iam:DetachRolePolicy",
          "iam:PutRolePolicy",
          "iam:DeleteRolePolicy",
          "iam:GetRole",
          "iam:GetRolePolicy",
          "iam:ListRolePolicies",
          "iam:ListAttachedRolePolicies",
          "iam:PassRole",
          "iam:CreateOpenIDConnectProvider",
          "iam:DeleteOpenIDConnectProvider",
          "iam:GetOpenIDConnectProvider",
          "iam:TagOpenIDConnectProvider",
          "iam:UntagOpenIDConnectProvider",
          "iam:TagRole",
          "iam:UntagRole",
          "iam:ListInstanceProfilesForRole"
        ]

        Resource = "*"
      },

      # -----------------------------------------------------------------------
      # ECR REPOSITORY MANAGEMENT
      # -----------------------------------------------------------------------

      {
        Sid    = "ECRRepositoryManagement"
        Effect = "Allow"

        Action = [
          "ecr:CreateRepository",
          "ecr:DeleteRepository",
          "ecr:DescribeRepositories",
          "ecr:PutLifecyclePolicy",
          "ecr:GetLifecyclePolicy",
          "ecr:DeleteLifecyclePolicy",
          "ecr:PutImageScanningConfiguration",
          "ecr:PutImageTagMutability",
          "ecr:ListTagsForResource",
          "ecr:TagResource",
          "ecr:UntagResource"
        ]

        Resource = "*"
      },

      # -----------------------------------------------------------------------
      # ECR AUTHENTICATION
      # -----------------------------------------------------------------------

      {
        Sid    = "ECRImagePush"
        Effect = "Allow"

        Action = [
          "ecr:GetAuthorizationToken"
        ]

        Resource = "*"
      },

      # -----------------------------------------------------------------------
      # ECR IMAGE OPERATIONS
      # -----------------------------------------------------------------------

      {
        Sid    = "ECRImageOperations"
        Effect = "Allow"

        Action = [
          "ecr:BatchCheckLayerAvailability",
          "ecr:InitiateLayerUpload",
          "ecr:UploadLayerPart",
          "ecr:CompleteLayerUpload",
          "ecr:PutImage",
          "ecr:BatchGetImage",
          "ecr:GetDownloadUrlForLayer",
          "ecr:DescribeImages",
          "ecr:ListImages"
        ]

        Resource = "arn:aws:ecr:ap-south-1:208384285485:repository/techitfactory-infra/*"
      },

      # -----------------------------------------------------------------------
      # ROUTE53 / ACM
      # -----------------------------------------------------------------------

      {
        Sid    = "Route53Access"
        Effect = "Allow"

        Action = [
          "route53:*",
          "acm:*"
        ]

        Resource = "*"
      }
    ]
  })
}

# =============================================================================
# OUTPUTS
# =============================================================================

output "github_actions_role_arn" {
  description = "IAM role ARN for GitHub Actions. Add this to GitHub Secrets as AWS_ROLE_ARN."

  value = aws_iam_role.github_actions_terraform.arn
}

output "oidc_provider_arn" {
  description = "ARN of the GitHub OIDC provider."

  value = aws_iam_openid_connect_provider.github.arn
}