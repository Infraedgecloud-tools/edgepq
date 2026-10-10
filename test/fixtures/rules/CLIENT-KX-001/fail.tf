# What the AWS scanner synthesises from CloudTrail; never written by hand in
# real Terraform.
resource "edgepq_cloudtrail_tls_sample" "kms_classical" {
  account               = "123456789012"
  region                = "eu-west-2"
  service               = "kms.amazonaws.com"
  events_sampled        = 200
  classical_count       = 37
  hybrid_count          = 163
  user_agents_classical = ["aws-cli/2.15.30 Python/3.11.8 Linux/6.1", "aws-sdk-java/1.12.700"]
}
