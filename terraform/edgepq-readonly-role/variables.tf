variable "trusted_principal_arn" {
  description = "The IAM principal (user or role ARN) that runs edgepq and may assume this role."
  type        = string
}

variable "role_name" {
  description = "Name of the role. The scanner's --role-name must match it in every account."
  type        = string
  default     = "edgepq-readonly"
}

variable "external_id" {
  description = "Optional sts:ExternalId the scanner must present (edgepq --external-id)."
  type        = string
  default     = null
}

variable "cloudtrail_sample" {
  description = "Allow cloudtrail:LookupEvents for the client-readiness sample. Set false to drop CLIENT-KX-001 from this account."
  type        = bool
  default     = true
}

variable "tags" {
  type    = map(string)
  default = {}
}
