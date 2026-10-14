# EdgePQ post-quantum readiness report

Scope: Terraform source files, 13 resources, 16 rules, generated 2026-10-14T15:10:56.764Z. 3 failed, 0 not configurable, 4 could not check, 3 already enabled.

## What this report does and does not say

This report lists what is enabled, what is not enabled, and what could not be checked. It does not look at the items listed under "Not covered", and nothing here describes how a particular client behaves. A line saying a setting is already enabled describes that one setting and is not a certification of anything.

- The key exchange between CloudFront and your origin.
- AWS Transfer Family SFTP endpoints. Post-quantum SSH policies exist for them and are a separate protocol.
- S3 negotiates post-quantum key exchange on the server side with nothing to configure, so there is nothing to report.
- Application code, including the TLS libraries and SDK versions your own software uses.
- Classic Load Balancers (aws_elb). No post-quantum policy exists for them; the only remedy is a move to an Application or Network Load Balancer.
- HTTP and WebSocket API default execute-api endpoints (aws_apigatewayv2_api). API Gateway offers them TLS_1_2 only, and nothing in the configuration changes that.
- KMS replica keys (aws_kms_replica_key) and keys with imported material (aws_kms_external_key). A replica of an RSA key is an RSA key; check the primary.
- Clouds other than AWS.
- The values a module call passes into a module. A module in a scanned directory is checked as written, with its own defaults; a module fetched from a registry or a remote source is not scanned.
- Which version of the Secrets Manager Lambda extension a function runs: the number in a layer ARN is a per-region publish counter, not the extension version, so it cannot be judged from configuration.
- Anything behind an expression the engine could not resolve. Those items are listed as could not check.

## Findings: Failed (3)

### ELB-KX-001 · aws_lb_listener.defaulted

Severity: high. Category: key-exchange.

aws_lb_listener.defaulted terminates TLS with ELBSecurityPolicy-2016-08, which negotiates classical key exchange only. Traffic recorded today could be decrypted later by a cryptographically relevant quantum computer (harvest now, decrypt later). A policy with PQ in its name adds X25519MLKEM768, SecP256r1MLKEM768 and SecP384r1MLKEM1024 for clients that offer them.

| Attribute | Value |
| --- | --- |
| protocol | HTTPS |
| ssl_policy | ELBSecurityPolicy-2016-08 (defaulted) |

Fix:

```hcl
ssl_policy = "ELBSecurityPolicy-TLS13-1-0-PQ-2025-09"
```

Safety: auto. Same protocols and ciphers as the current policy, plus TLS 1.3 and hybrid post-quantum key exchange: no client loses a protocol version or a cipher suite. The hybrid key share makes handshake messages larger, and the AWS KMS post-quantum TLS page warns that legacy proxies or firewalls with deep packet inspection might block them, so watch the connection logs after the change. It keeps the TLS 1.0 and 1.1 the current policy admits; AWS recommends ELBSecurityPolicy-TLS13-1-2-Res-PQ-2025-09 once the connection logs show no TLS 1.0 or 1.1 clients. Clients that cannot negotiate ML-KEM keep working on these policies; only the key exchange changes for clients that can. Check the connection logs' key exchange field after the change.

Sources:

- https://docs.aws.amazon.com/elasticloadbalancing/latest/application/describe-ssl-policies.html (verified 2026-10-10)
- https://docs.aws.amazon.com/elasticloadbalancing/latest/network/describe-ssl-policies.html (verified 2026-10-10)
- https://aws.amazon.com/about-aws/whats-new/2025/11/network-load-balancers-post-quantum-key-exchange-tls (verified 2026-10-10)
- https://raw.githubusercontent.com/hashicorp/terraform-provider-aws/main/website/docs/r/lb_listener.html.markdown (verified 2026-10-10)
- https://docs.aws.amazon.com/kms/latest/developerguide/pqtls.html (verified 2026-10-10)

### ELB-KX-001 · aws_lb_listener.explicit_classical

Severity: high. Category: key-exchange.

aws_lb_listener.explicit_classical terminates TLS with ELBSecurityPolicy-TLS13-1-2-Res-2021-06, which negotiates classical key exchange only. Traffic recorded today could be decrypted later by a cryptographically relevant quantum computer (harvest now, decrypt later). A policy with PQ in its name adds X25519MLKEM768, SecP256r1MLKEM768 and SecP384r1MLKEM1024 for clients that offer them.

| Attribute | Value |
| --- | --- |
| protocol | HTTPS |
| ssl_policy | ELBSecurityPolicy-TLS13-1-2-Res-2021-06 |

Fix:

```hcl
ssl_policy = "ELBSecurityPolicy-TLS13-1-2-Res-PQ-2025-09"
```

Safety: auto. Same protocols and ciphers as the current policy, plus TLS 1.3 and hybrid post-quantum key exchange: no client loses a protocol version or a cipher suite. The hybrid key share makes handshake messages larger, and the AWS KMS post-quantum TLS page warns that legacy proxies or firewalls with deep packet inspection might block them, so watch the connection logs after the change. Clients that cannot negotiate ML-KEM keep working on these policies; only the key exchange changes for clients that can. Check the connection logs' key exchange field after the change.

Sources:

- https://docs.aws.amazon.com/elasticloadbalancing/latest/application/describe-ssl-policies.html (verified 2026-10-10)
- https://docs.aws.amazon.com/elasticloadbalancing/latest/network/describe-ssl-policies.html (verified 2026-10-10)
- https://aws.amazon.com/about-aws/whats-new/2025/11/network-load-balancers-post-quantum-key-exchange-tls (verified 2026-10-10)
- https://raw.githubusercontent.com/hashicorp/terraform-provider-aws/main/website/docs/r/lb_listener.html.markdown (verified 2026-10-10)
- https://docs.aws.amazon.com/kms/latest/developerguide/pqtls.html (verified 2026-10-10)

### ELB-KX-001 · aws_lb_listener.nlb_fips

Severity: high. Category: key-exchange.

aws_lb_listener.nlb_fips terminates TLS with ELBSecurityPolicy-TLS13-1-2-FIPS-2023-04, which negotiates classical key exchange only. Traffic recorded today could be decrypted later by a cryptographically relevant quantum computer (harvest now, decrypt later). A policy with PQ in its name adds X25519MLKEM768, SecP256r1MLKEM768 and SecP384r1MLKEM1024 for clients that offer them.

| Attribute | Value |
| --- | --- |
| protocol | TLS |
| ssl_policy | ELBSecurityPolicy-TLS13-1-2-FIPS-2023-04 |

Fix:

```hcl
ssl_policy = "ELBSecurityPolicy-TLS13-1-2-FIPS-PQ-2025-09"
```

Safety: auto. Same protocols and ciphers as the current policy, plus TLS 1.3 and hybrid post-quantum key exchange: no client loses a protocol version or a cipher suite. The hybrid key share makes handshake messages larger, and the AWS KMS post-quantum TLS page warns that legacy proxies or firewalls with deep packet inspection might block them, so watch the connection logs after the change. Clients that cannot negotiate ML-KEM keep working on these policies; only the key exchange changes for clients that can. Check the connection logs' key exchange field after the change.

Sources:

- https://docs.aws.amazon.com/elasticloadbalancing/latest/application/describe-ssl-policies.html (verified 2026-10-10)
- https://docs.aws.amazon.com/elasticloadbalancing/latest/network/describe-ssl-policies.html (verified 2026-10-10)
- https://aws.amazon.com/about-aws/whats-new/2025/11/network-load-balancers-post-quantum-key-exchange-tls (verified 2026-10-10)
- https://raw.githubusercontent.com/hashicorp/terraform-provider-aws/main/website/docs/r/lb_listener.html.markdown (verified 2026-10-10)
- https://docs.aws.amazon.com/kms/latest/developerguide/pqtls.html (verified 2026-10-10)

## Findings: Not configurable (0)

## Findings: Could not check (4)

### ELB-KX-001 · aws_lb_listener.from_variable

Severity: high. Category: key-exchange.

aws_lb_listener.from_variable: ssl_policy is not a literal value here (an expression, a dynamic block, or a value a plan cannot show before apply), so the rule could not be checked offline. The state or the account can show it.

| Attribute | Value |
| --- | --- |
| protocol | HTTPS |
| ssl_policy | (not known offline) |

Sources:

- https://docs.aws.amazon.com/elasticloadbalancing/latest/application/describe-ssl-policies.html (verified 2026-10-10)
- https://docs.aws.amazon.com/elasticloadbalancing/latest/network/describe-ssl-policies.html (verified 2026-10-10)
- https://aws.amazon.com/about-aws/whats-new/2025/11/network-load-balancers-post-quantum-key-exchange-tls (verified 2026-10-10)
- https://raw.githubusercontent.com/hashicorp/terraform-provider-aws/main/website/docs/r/lb_listener.html.markdown (verified 2026-10-10)
- https://docs.aws.amazon.com/kms/latest/developerguide/pqtls.html (verified 2026-10-10)

### ELB-KX-001 · aws_lb_listener.invented

Severity: high. Category: key-exchange.

aws_lb_listener.invented: ssl_policy is ELBSecurityPolicy-PQ-2030-01. Either it is not a literal value (a plan cannot show it before apply; the state or the account can), or it is not a policy name AWS documented when the rule's sources were read; check the spelling against the AWS page.

| Attribute | Value |
| --- | --- |
| protocol | HTTPS |
| ssl_policy | ELBSecurityPolicy-PQ-2030-01 |

Sources:

- https://docs.aws.amazon.com/elasticloadbalancing/latest/application/describe-ssl-policies.html (verified 2026-10-10)
- https://docs.aws.amazon.com/elasticloadbalancing/latest/network/describe-ssl-policies.html (verified 2026-10-10)
- https://aws.amazon.com/about-aws/whats-new/2025/11/network-load-balancers-post-quantum-key-exchange-tls (verified 2026-10-10)
- https://raw.githubusercontent.com/hashicorp/terraform-provider-aws/main/website/docs/r/lb_listener.html.markdown (verified 2026-10-10)
- https://docs.aws.amazon.com/kms/latest/developerguide/pqtls.html (verified 2026-10-10)

### ELB-KX-001 · aws_lb_listener.lowercase_protocol

Severity: high. Category: key-exchange.

aws_lb_listener.lowercase_protocol: ssl_policy is ELBSecurityPolicy-2016-08. Either it is not a literal value (a plan cannot show it before apply; the state or the account can), or it is not a policy name AWS documented when the rule's sources were read; check the spelling against the AWS page.

| Attribute | Value |
| --- | --- |
| protocol | https |
| ssl_policy | ELBSecurityPolicy-2016-08 |

Sources:

- https://docs.aws.amazon.com/elasticloadbalancing/latest/application/describe-ssl-policies.html (verified 2026-10-10)
- https://docs.aws.amazon.com/elasticloadbalancing/latest/network/describe-ssl-policies.html (verified 2026-10-10)
- https://aws.amazon.com/about-aws/whats-new/2025/11/network-load-balancers-post-quantum-key-exchange-tls (verified 2026-10-10)
- https://raw.githubusercontent.com/hashicorp/terraform-provider-aws/main/website/docs/r/lb_listener.html.markdown (verified 2026-10-10)
- https://docs.aws.amazon.com/kms/latest/developerguide/pqtls.html (verified 2026-10-10)

### ELB-KX-001 · aws_lb_listener.misspelt

Severity: high. Category: key-exchange.

aws_lb_listener.misspelt: ssl_policy is ELBSecurityPolicy-TLS13-1-2-Res-PQ-2025-9. Either it is not a literal value (a plan cannot show it before apply; the state or the account can), or it is not a policy name AWS documented when the rule's sources were read; check the spelling against the AWS page.

| Attribute | Value |
| --- | --- |
| protocol | HTTPS |
| ssl_policy | ELBSecurityPolicy-TLS13-1-2-Res-PQ-2025-9 |

Sources:

- https://docs.aws.amazon.com/elasticloadbalancing/latest/application/describe-ssl-policies.html (verified 2026-10-10)
- https://docs.aws.amazon.com/elasticloadbalancing/latest/network/describe-ssl-policies.html (verified 2026-10-10)
- https://aws.amazon.com/about-aws/whats-new/2025/11/network-load-balancers-post-quantum-key-exchange-tls (verified 2026-10-10)
- https://raw.githubusercontent.com/hashicorp/terraform-provider-aws/main/website/docs/r/lb_listener.html.markdown (verified 2026-10-10)
- https://docs.aws.amazon.com/kms/latest/developerguide/pqtls.html (verified 2026-10-10)

## Findings: Already enabled (3)

### ELB-KX-001 · aws_alb_listener.legacy_alias_fips

Severity: high. Category: key-exchange.

aws_alb_listener.legacy_alias_fips uses ELBSecurityPolicy-TLS13-1-2-FIPS-PQ-2025-09, which offers hybrid post-quantum key exchange to clients that support ML-KEM. Whether a given client gets it depends on that client; the listener's connection logs record the key exchange used.

| Attribute | Value |
| --- | --- |
| protocol | HTTPS |
| ssl_policy | ELBSecurityPolicy-TLS13-1-2-FIPS-PQ-2025-09 |

Sources:

- https://docs.aws.amazon.com/elasticloadbalancing/latest/application/describe-ssl-policies.html (verified 2026-10-10)
- https://docs.aws.amazon.com/elasticloadbalancing/latest/network/describe-ssl-policies.html (verified 2026-10-10)
- https://aws.amazon.com/about-aws/whats-new/2025/11/network-load-balancers-post-quantum-key-exchange-tls (verified 2026-10-10)
- https://raw.githubusercontent.com/hashicorp/terraform-provider-aws/main/website/docs/r/lb_listener.html.markdown (verified 2026-10-10)
- https://docs.aws.amazon.com/kms/latest/developerguide/pqtls.html (verified 2026-10-10)

### ELB-KX-001 · aws_lb_listener.nlb

Severity: high. Category: key-exchange.

aws_lb_listener.nlb uses ELBSecurityPolicy-TLS13-1-3-PQ-2025-09, which offers hybrid post-quantum key exchange to clients that support ML-KEM. Whether a given client gets it depends on that client; the listener's connection logs record the key exchange used.

| Attribute | Value |
| --- | --- |
| protocol | TLS |
| ssl_policy | ELBSecurityPolicy-TLS13-1-3-PQ-2025-09 |

Sources:

- https://docs.aws.amazon.com/elasticloadbalancing/latest/application/describe-ssl-policies.html (verified 2026-10-10)
- https://docs.aws.amazon.com/elasticloadbalancing/latest/network/describe-ssl-policies.html (verified 2026-10-10)
- https://aws.amazon.com/about-aws/whats-new/2025/11/network-load-balancers-post-quantum-key-exchange-tls (verified 2026-10-10)
- https://raw.githubusercontent.com/hashicorp/terraform-provider-aws/main/website/docs/r/lb_listener.html.markdown (verified 2026-10-10)
- https://docs.aws.amazon.com/kms/latest/developerguide/pqtls.html (verified 2026-10-10)

### ELB-KX-001 · aws_lb_listener.recommended

Severity: high. Category: key-exchange.

aws_lb_listener.recommended uses ELBSecurityPolicy-TLS13-1-2-Res-PQ-2025-09, which offers hybrid post-quantum key exchange to clients that support ML-KEM. Whether a given client gets it depends on that client; the listener's connection logs record the key exchange used.

| Attribute | Value |
| --- | --- |
| protocol | HTTPS |
| ssl_policy | ELBSecurityPolicy-TLS13-1-2-Res-PQ-2025-09 |

Sources:

- https://docs.aws.amazon.com/elasticloadbalancing/latest/application/describe-ssl-policies.html (verified 2026-10-10)
- https://docs.aws.amazon.com/elasticloadbalancing/latest/network/describe-ssl-policies.html (verified 2026-10-10)
- https://aws.amazon.com/about-aws/whats-new/2025/11/network-load-balancers-post-quantum-key-exchange-tls (verified 2026-10-10)
- https://raw.githubusercontent.com/hashicorp/terraform-provider-aws/main/website/docs/r/lb_listener.html.markdown (verified 2026-10-10)
- https://docs.aws.amazon.com/kms/latest/developerguide/pqtls.html (verified 2026-10-10)

## Coverage

**Input**

- hcl

**Files scanned**

- fail.tf
- pass.tf
- unknown.tf

**Not covered**

- The key exchange between CloudFront and your origin.
- AWS Transfer Family SFTP endpoints. Post-quantum SSH policies exist for them and are a separate protocol.
- S3 negotiates post-quantum key exchange on the server side with nothing to configure, so there is nothing to report.
- Application code, including the TLS libraries and SDK versions your own software uses.
- Classic Load Balancers (aws_elb). No post-quantum policy exists for them; the only remedy is a move to an Application or Network Load Balancer.
- HTTP and WebSocket API default execute-api endpoints (aws_apigatewayv2_api). API Gateway offers them TLS_1_2 only, and nothing in the configuration changes that.
- KMS replica keys (aws_kms_replica_key) and keys with imported material (aws_kms_external_key). A replica of an RSA key is an RSA key; check the primary.
- Clouds other than AWS.
- The values a module call passes into a module. A module in a scanned directory is checked as written, with its own defaults; a module fetched from a registry or a remote source is not scanned.
- Which version of the Secrets Manager Lambda extension a function runs: the number in a layer ARN is a per-region publish counter, not the extension version, so it cannot be judged from configuration.
- Anything behind an expression the engine could not resolve. Those items are listed as could not check.

## Rules run

| Rule | Title | Category | Severity | Sources |
| --- | --- | --- | --- | --- |
| APIGW-KX-001 | API Gateway custom domain (regional or private) does not use a post-quantum security policy | key-exchange | high | 3 |
| APIGW-KX-002 | Edge-optimized API Gateway custom domain has no post-quantum security policy available | key-exchange | low | 2 |
| APIGW-KX-003 | Regional REST API default endpoint does not use a post-quantum security policy | key-exchange | high | 3 |
| APIGW-KX-004 | Private REST API default endpoint does not use a post-quantum security policy | key-exchange | high | 3 |
| APIGW-KX-005 | Edge-optimized REST API default endpoint has no post-quantum security policy available | key-exchange | low | 2 |
| APIGW-KX-006 | HTTP or WebSocket API custom domain cannot use a post-quantum security policy | key-exchange | low | 2 |
| CF-KX-001 | CloudFront distribution lets viewers connect without TLS | key-exchange | medium | 2 |
| CF-KX-002 | CloudFront security policy still admits TLS 1.0 and 1.1 viewers, which never get post-quantum key exchange | inventory | info | 2 |
| CF-KX-003 | CloudFront distribution on the default certificate cannot raise its minimum TLS version | inventory | low | 2 |
| CLIENT-KX-001 | Clients still negotiate classical key exchange with a service that offers ML-KEM | client | medium | 5 |
| CLIENT-KX-002 | Lambda function pins a Parameters and Secrets extension version that predates ML-KEM | client | low | 2 |
| ELB-KX-001 | Load balancer listener does not offer hybrid post-quantum key exchange | key-exchange | high | 6 |
| KMS-KX-001 | KMS asymmetric encryption key uses RSA or SM2, whose ciphertexts can be decrypted later | key-exchange | medium | 4 |
| KMS-KX-002 | KMS key agreement key derives shared secrets with classical ECDH only | key-exchange | medium | 2 |
| KMS-SIG-001 | KMS signing key uses a classical signature algorithm | signature | low | 3 |
| PCA-SIG-001 | Private CA signs with a classical algorithm | signature | low | 3 |
