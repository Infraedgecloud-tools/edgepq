#!/usr/bin/env python3
"""Regenerate rules/data/elb-security-policies.json from the two AWS pages.

Usage: scripts/extract-elb-policies.py <alb.md> <nlb.md> <retrieved YYYY-MM-DD>

The inputs are the ALB and NLB "Security policies" pages saved as markdown
(docs.aws.amazon.com renders them from markdown; a fetch tool that returns the
markdown form, or pandoc on the HTML, both work). The script reads the
"Protocols by policy" and "Ciphers by policy" tables, then for every classical
policy finds the post-quantum policy whose protocols and ciphers are a
superset, so no current client loses access.

Safety of a mapping:
  auto   - the PQ policy adds nothing but TLS 1.3 and its three suites
  review - the PQ policy also admits older protocols or more ciphers than the
           current one (a wider surface), the current policy is an RFC 9151
           policy (whose curve and signature restrictions no PQ policy keeps),
           or there is no superset at all
"""
import json, re, sys

TLS13_SUITES = {'TLS_AES_128_GCM_SHA256', 'TLS_AES_256_GCM_SHA384', 'TLS_CHACHA20_POLY1305_SHA256'}

def parse(path):
    protocols, ciphers = {}, {}
    for line in open(path, encoding='utf-8'):
        if not line.startswith('| ELBSecurityPolicy'):
            continue
        cells = [c.strip() for c in line.strip().strip('|').split('|')]
        names = [n.strip() for n in cells[0].split('<br />')]
        if len(cells) == 5:
            flags = ['Yes' in c for c in cells[1:]]
            for n in names:
                protocols[n] = sorted(k for k, v in zip(['TLS1.3', 'TLS1.2', 'TLS1.1', 'TLS1.0'], flags) if v)
        elif len(cells) == 2:
            suites = [re.sub(r'<br />', '', c).replace('\\_', '_').strip() for c in cells[1].split('+') if c.strip()]
            for n in names:
                ciphers[n] = suites
    return protocols, ciphers

def main(alb_path, nlb_path, retrieved):
    alb_p, alb_c = parse(alb_path)
    nlb_p, nlb_c = parse(nlb_path)
    names = sorted(set(alb_p) | set(nlb_p))
    policies = {}
    for n in names:
        p = alb_p.get(n) or nlb_p.get(n)
        c = alb_c.get(n) or nlb_c.get(n)
        if n in alb_p and n in nlb_p and (alb_p[n] != nlb_p[n] or alb_c.get(n) != nlb_c.get(n)):
            raise SystemExit(f'{n}: ALB and NLB pages disagree; look before regenerating')
        policies[n] = {
            'protocols': p, 'ciphers': c,
            'post_quantum': '-PQ-' in n, 'fips': 'FIPS' in n,
            'load_balancers': sorted(x for x, present in (('alb', n in alb_p), ('nlb', n in nlb_p)) if present),
        }
    pq = [n for n in names if policies[n]['post_quantum']]
    mapping = {}
    for n in names:
        if policies[n]['post_quantum']:
            continue
        me = policies[n]
        cands = [q for q in pq if policies[q]['fips'] == me['fips']
                 and set(policies[q]['protocols']) >= set(me['protocols'])
                 and set(policies[q]['ciphers']) >= set(me['ciphers'])]
        cands.sort(key=lambda q: (len(set(policies[q]['protocols']) - set(me['protocols'])),
                                  len(set(policies[q]['ciphers']) - set(me['ciphers']))))
        if not cands:
            mapping[n] = {'value': 'ELBSecurityPolicy-TLS13-1-2-Res-FIPS-PQ-2025-09' if me['fips'] else 'ELBSecurityPolicy-TLS13-1-2-Res-PQ-2025-09',
                          'safety': 'review', 'note': 'No post-quantum policy is a superset of the current one; this is the policy AWS recommends. Check the connection logs for clients that would lose access.'}
            continue
        q = cands[0]
        extra_p = sorted(set(policies[q]['protocols']) - set(me['protocols']))
        extra_c = sorted(set(policies[q]['ciphers']) - set(me['ciphers']))
        keeps_legacy = any(p in ('TLS1.0', 'TLS1.1') for p in policies[q]['protocols'])
        legacy_note = ' It keeps the TLS 1.0 and 1.1 the current policy admits; AWS recommends ELBSecurityPolicy-TLS13-1-2-Res-PQ-2025-09 once the connection logs show no TLS 1.0 or 1.1 clients.' if keeps_legacy else ''
        if 'RFC9151' in n:
            mapping[n] = {'value': q, 'safety': 'review', 'note': 'RFC 9151 policies also restrict key-exchange curves and signature algorithms to CNSA 1.0; no post-quantum policy keeps that restriction, so this is a change of posture, not only an addition.'}
        elif set(extra_p) <= {'TLS1.3'} and set(extra_c) <= TLS13_SUITES:
            mapping[n] = {'value': q, 'safety': 'auto', 'note': 'Same protocols and ciphers as the current policy, plus TLS 1.3 and hybrid post-quantum key exchange: no client loses a protocol version or a cipher suite. The hybrid key share makes handshake messages larger, and the AWS KMS post-quantum TLS page warns that legacy proxies or firewalls with deep packet inspection might block them, so watch the connection logs after the change.' + legacy_note}
        else:
            mapping[n] = {'value': q, 'safety': 'review', 'note': f'Nearest post-quantum superset. It also admits {", ".join(extra_p) if extra_p else "no extra protocols"} and {len(extra_c)} more cipher suites than the current policy.'}
    out = {
        'sources': [
            {'url': 'https://docs.aws.amazon.com/elasticloadbalancing/latest/application/describe-ssl-policies.html', 'retrieved': retrieved},
            {'url': 'https://docs.aws.amazon.com/elasticloadbalancing/latest/network/describe-ssl-policies.html', 'retrieved': retrieved},
        ],
        'hybrid_groups': ['X25519MLKEM768', 'SecP256r1MLKEM768', 'SecP384r1MLKEM1024'],
        'policies': policies,
        'pq_superset': mapping,
    }
    json.dump(out, sys.stdout, indent=1)
    sys.stdout.write('\n')

if __name__ == '__main__':
    main(*sys.argv[1:4])
