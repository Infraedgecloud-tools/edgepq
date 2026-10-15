import { checkedPages } from '../bounds.ts';
import { ACMClient, paginateListCertificates } from '@aws-sdk/client-acm';
import { ACMPCAClient, paginateListCertificateAuthorities } from '@aws-sdk/client-acm-pca';
import type { Collector } from '../types.ts';
import { clientConfig, resource } from './helpers.ts';

/* ACM certificates are inventory for the CBOM: there is no post-quantum
   public certificate to move to, so no rule fires on them. */
export const acm: Collector = {
  service: 'acm',
  async run(ctx) {
    const client = new ACMClient(clientConfig(ctx));
    const resources = [];
    const input = { Includes: { keyTypes: ['RSA_1024', 'RSA_2048', 'RSA_3072', 'RSA_4096', 'EC_prime256v1', 'EC_secp384r1', 'EC_secp521r1'] as const } };
    for await (const page of checkedPages(paginateListCertificates({ client, stopOnSameToken: true }, { Includes: { keyTypes: [...input.Includes.keyTypes] } }, ctx.signal ? { abortSignal: ctx.signal } : {}), ctx.signal)) {
      for (const c of page.CertificateSummaryList ?? []) {
        if (!c.CertificateArn) continue;
        resources.push(resource(ctx, 'aws_acm_certificate', c.CertificateArn, {
          domain_name: c.DomainName ?? null,
          key_algorithm: c.KeyAlgorithm ?? null,
          type: c.Type ?? null,
          status: c.Status ?? null,
          in_use: c.InUse ?? null,
          ...(c.Type === 'IMPORTED' ? { certificate_body: '(imported)' } : {}),
        }));
      }
    }
    return { resources };
  },
};

export const acmpca: Collector = {
  service: 'acm-pca',
  async run(ctx) {
    const client = new ACMPCAClient(clientConfig(ctx));
    const resources = [];
    for await (const page of checkedPages(paginateListCertificateAuthorities({ client, stopOnSameToken: true }, {}, ctx.signal ? { abortSignal: ctx.signal } : {}), ctx.signal)) {
      for (const ca of page.CertificateAuthorities ?? []) {
        if (!ca.Arn || ca.Status === 'DELETED') continue;
        const cfg = ca.CertificateAuthorityConfiguration;
        resources.push(resource(ctx, 'aws_acmpca_certificate_authority', ca.Arn, {
          type: ca.Type ?? null,
          status: ca.Status ?? null,
          certificate_authority_configuration: [{
            key_algorithm: cfg?.KeyAlgorithm ?? null,
            signing_algorithm: cfg?.SigningAlgorithm ?? null,
          }],
        }));
      }
    }
    return { resources };
  },
};
