terraform {
  required_version = ">= 1.5.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.0"
    }
  }
}

provider "aws" {
  region = "ap-northeast-1"
}

# ❌ (脆弱) S3バケットを公開 & 暗号化なし & バージョニングなし
resource "aws_s3_bucket" "vuln_bucket" {
  bucket = "wiz-iac-vuln-demo-please-do-not-apply"
}

# ❌ (脆弱) パブリックアクセスブロックを無効化（公開を許可）
resource "aws_s3_bucket_public_access_block" "vuln_bucket_pab" {
  bucket = aws_s3_bucket.vuln_bucket.id

  block_public_acls       = false
  ignore_public_acls      = false
  block_public_policy     = false
  restrict_public_buckets = false
}

# ❌ (脆弱) バケットポリシーで全世界に GetObject を許可
resource "aws_s3_bucket_policy" "vuln_bucket_policy" {
  bucket = aws_s3_bucket.vuln_bucket.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "PublicReadGetObject"
        Effect    = "Allow"
        Principal = "*"
        Action    = ["s3:GetObject"]
        Resource  = "${aws_s3_bucket.vuln_bucket.arn}/*"
      }
    ]
  })
}

# ❌ (脆弱) 0.0.0.0/0 に 22 と 3389 と 80 を開放（SSH/RDP/HTTP）
resource "aws_security_group" "vuln_sg" {
  name        = "wiz-iac-vuln-sg"
  description = "Intentionally insecure SG for IaC scanning demo"
  vpc_id      = "vpc-REPLACE_ME" # ここは apply しないならこのままでOK。apply するなら置換が必要。

  ingress {
    description = "SSH open to the world (bad)"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "RDP open to the world (bad)"
    from_port   = 3389
    to_port     = 3389
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "HTTP open to the world (ok sometimes, but here it's a demo)"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    description = "All egress allowed"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
