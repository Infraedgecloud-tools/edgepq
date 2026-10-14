# Security policy

## Supported versions

Only the latest minor release receives security fixes.

## Reporting a vulnerability

Report privately through GitHub private vulnerability reporting:
<https://github.com/infraedgecloud-tools/edgepq/security/advisories/new>

Please do not open a public issue for a vulnerability. We acknowledge reports within 14 days.

## What counts as a security issue

- edgepq reports an endpoint or key as using a post-quantum key exchange or signature when it does not, or marks a finding as passed on evidence that does not support it.
- `edgepq aws` makes a call that is not a List, Describe or Get, or reads something the role's documentation does not name.
- A patch that is not what the finding describes, or anything that applies a change rather than writing a diff.
- Anything that lets a crafted Terraform file, plan, state or TLS response run code, write outside the requested output path, or exfiltrate data.
- The browser bundle making a network request after the parser has loaded.
- A flaw in the release artefacts or the npm package that lets a third party tamper with what users run.

A rule that fails a ready resource is a bug, not a security issue. Use the wrong-finding issue template for those.

## Redact before you attach

Reports, evidence and CBOMs carry resource names, ARNs and account IDs. Remove them from anything you attach.
