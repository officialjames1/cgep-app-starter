variable "aws_region" {
  type        = string
  description = "AWS region for the starter."
  default     = "us-east-1"
}

variable "lock_mode" {
  type        = string
  description = "S3 Object Lock mode for the evidence vault: GOVERNANCE or COMPLIANCE."
  default     = "GOVERNANCE"
}

variable "retention_days" {
  type        = number
  description = "Number of days evidence objects are retained under Object Lock."
  default     = 90
}
