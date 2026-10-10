resource "edgepq_cloudtrail_tls_sample" "kms_all_hybrid" {
  account               = "123456789012"
  region                = "eu-west-2"
  service               = "kms.amazonaws.com"
  events_sampled        = 200
  classical_count       = 0
  hybrid_count          = 200
  user_agents_classical = []
}

# Nothing sampled (no calls in the window): the rule does not apply.
resource "edgepq_cloudtrail_tls_sample" "secretsmanager_empty" {
  account               = "123456789012"
  region                = "eu-west-2"
  service               = "secretsmanager.amazonaws.com"
  events_sampled        = 0
  classical_count       = 0
  hybrid_count          = 0
  user_agents_classical = []
}
