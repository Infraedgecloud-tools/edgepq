import { checkedPages } from '../bounds.ts';
import { CloudFrontClient, paginateListDistributions } from '@aws-sdk/client-cloudfront';
import type { Collector } from '../types.ts';
import { clientConfig, resource } from './helpers.ts';

/* Global service: runs once per account. ListDistributions already carries
   the viewer certificate and every cache behavior's viewer protocol policy,
   so no per-distribution call is needed. Attributes are shaped like the
   Terraform resource so the same rules apply unchanged. */
export const cloudfront: Collector = {
  service: 'cloudfront',
  global: true,
  async run(ctx) {
    const client = new CloudFrontClient(clientConfig(ctx, 'us-east-1'));
    const resources = [];
    for await (const page of checkedPages(paginateListDistributions({ client, stopOnSameToken: true }, {}, ctx.signal ? { abortSignal: ctx.signal } : {}), ctx.signal)) {
      for (const d of page.DistributionList?.Items ?? []) {
        if (!d.ARN) continue;
        const vc = d.ViewerCertificate ?? {};
        resources.push(resource(ctx, 'aws_cloudfront_distribution', d.ARN, {
          id: d.Id ?? null,
          enabled: d.Enabled ?? null,
          aliases: d.Aliases?.Items ?? [],
          default_cache_behavior: [{ viewer_protocol_policy: d.DefaultCacheBehavior?.ViewerProtocolPolicy ?? null }],
          ordered_cache_behavior: (d.CacheBehaviors?.Items ?? []).map((b) => ({ path_pattern: b.PathPattern ?? null, viewer_protocol_policy: b.ViewerProtocolPolicy ?? null })),
          viewer_certificate: [{
            cloudfront_default_certificate: vc.CloudFrontDefaultCertificate ?? false,
            ...(vc.MinimumProtocolVersion ? { minimum_protocol_version: vc.MinimumProtocolVersion } : {}),
            ...(vc.ACMCertificateArn ? { acm_certificate_arn: vc.ACMCertificateArn } : {}),
          }],
        }));
      }
    }
    return { resources };
  },
};
