# terraform/hardening.tf
# Remediates GAP-01, GAP-03, GAP-04 on the starter's real aws_s3_bucket.uploads,
# and closes the public-access-block gap the lab's compliance.ac3_aws policy checks.
# Reuses the customer-managed KMS key from kms.tf (aws_kms_key.s3) rather than
# provisioning a second CMK — fewer keys, simpler IAM, lower cost. Trade-off:
# weaker blast-radius isolation between the uploads bucket and the primary/log
# buckets, since they share one CMK.

# GAP-01: SSE-KMS with a customer-managed key, not the AWS-managed SSE-S3 default.
resource "aws_s3_bucket_server_side_encryption_configuration" "uploads" {
  bucket = aws_s3_bucket.uploads.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.s3.arn
    }
    bucket_key_enabled = true
  }
}

# GAP-04: versioning so PHI overwrites/deletes are recoverable.
resource "aws_s3_bucket_versioning" "uploads" {
  bucket = aws_s3_bucket.uploads.id
  versioning_configuration {
    status = "Enabled"
  }
}

# Bonus: closes compliance.ac3_aws (existing lab policy) for the uploads bucket.
resource "aws_s3_bucket_public_access_block" "uploads" {
  bucket                  = aws_s3_bucket.uploads.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# GAP-03: explicit deny on any request that isn't using TLS.
resource "aws_s3_bucket_policy" "uploads" {
  bucket = aws_s3_bucket.uploads.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "DenyInsecureTransport"
      Effect    = "Deny"
      Principal = "*"
      Action    = "s3:*"
      Resource  = [aws_s3_bucket.uploads.arn, "${aws_s3_bucket.uploads.arn}/*"]
      Condition = {
        Bool = { "aws:SecureTransport" = "false" }
      }
    }]
  })
}

# GAP-08 (partial — access logging only; see main.tf and WRITEUP.md for the
# WAF platform-limitation note): destination log group for API Gateway access logs.
resource "aws_cloudwatch_log_group" "apigw_access" {
  name              = "/aws/apigateway/${local.name_prefix}-${local.suffix}"
  retention_in_days = 90
}
