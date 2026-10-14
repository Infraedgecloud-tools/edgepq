# edgepq-readonly-role

The role EdgePQ assumes in each account it scans. Every action is a List,
Describe or Get, named one by one. No wildcard actions.

| Action | Collector |
|---|---|
| `elasticloadbalancing:DescribeLoadBalancers`, `DescribeListeners` | listeners and their security policies |
| `cloudfront:ListDistributions` | viewer protocol policy and minimum TLS version |
| `apigateway:GET` on `/domainnames` and `/restapis` (the collections only) | REST and HTTP API domains, REST API endpoints |
| `kms:ListKeys`, `kms:DescribeKey` | key specs and usage |
| `acm:ListCertificates` | certificate inventory for the CBOM |
| `acm-pca:ListCertificateAuthorities` | private CA key algorithms |
| `ec2:DescribeRegions` | which regions to scan |
| `cloudtrail:LookupEvents` (optional) | the client key-exchange sample: 90 days of management events, which carry identity, source IP and user agent; the report prints user agents |

```hcl
module "edgepq_role" {
  source                = "github.com/infraedgecloud-tools/edgepq//terraform/edgepq-readonly-role?ref=v0.1.0"
  trusted_principal_arn = "arn:aws:iam::111111111111:role/ci-scanner"
  external_id           = "a-long-random-string"
}
```

Then, from the trusted principal:

```bash
edgepq aws --accounts 222222222222,333333333333 --role-name edgepq-readonly --external-id a-long-random-string
```
