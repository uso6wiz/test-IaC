resource "aws_s3_bucket" "vulnerable_bucket" {
  bucket = "my-public-bucket-example"
}

resource "aws_s3_bucket_public_access_block" "vulnerable_bucket_pab" {
  bucket = aws_s3_bucket.vulnerable_bucket.id

  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}

resource "aws_s3_bucket_policy" "vulnerable_bucket_policy" {
  bucket = aws_s3_bucket.vulnerable_bucket.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "PublicReadGetObject"
        Effect    = "Allow"
        Principal = "*"
        Action    = "s3:GetObject"
        Resource  = "${aws_s3_bucket.vulnerable_bucket.arn}/*"
      }
    ]
  })
}