resource "aws_s3_bucket" "vulnerable_bucket" {
  bucket = "my-company-data-bucket"
  # VULNERABILITY: Public ACL
  acl    = "public-read"
}

# VULNERABILITY: No server-side encryption configured
# VULNERABILITY: No versioning configured
# VULNERABILITY: No public access block

resource "aws_s3_bucket" "logs_bucket" {
  bucket = "my-company-logs"
  # VULNERABILITY: Public read-write
  acl    = "public-read-write"
}
