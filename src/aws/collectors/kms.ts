import { checkedPages } from '../bounds.ts';
import { KMSClient, DescribeKeyCommand, paginateListKeys } from '@aws-sdk/client-kms';
import type { Collector } from '../types.ts';
import { clientConfig, resource } from './helpers.ts';

/* Customer-managed keys only. AWS-managed keys (aws/s3 and the like) are
   symmetric and not the customer's to change; they are counted in a note so
   the omission is visible. Keys pending deletion are skipped the same way. */
export const kms: Collector = {
  service: 'kms',
  async run(ctx) {
    const client = new KMSClient(clientConfig(ctx));
    const resources = [];
    let awsManaged = 0;
    let pendingDeletion = 0;
    for await (const page of checkedPages(paginateListKeys({ client, stopOnSameToken: true }, {}, ctx.signal ? { abortSignal: ctx.signal } : {}), ctx.signal)) {
      for (const k of page.Keys ?? []) {
        if (!k.KeyId) continue;
        const meta = (await client.send(new DescribeKeyCommand({ KeyId: k.KeyId }), ctx.signal ? { abortSignal: ctx.signal } : {})).KeyMetadata;
        if (!meta?.Arn) continue;
        if (meta.KeyManager === 'AWS') { awsManaged += 1; continue; }
        if (meta.KeyState === 'PendingDeletion' || meta.KeyState === 'PendingReplicaDeletion') { pendingDeletion += 1; continue; }
        resources.push(resource(ctx, 'aws_kms_key', meta.Arn, {
          key_id: meta.KeyId ?? null,
          description: meta.Description ?? null,
          customer_master_key_spec: meta.KeySpec ?? 'SYMMETRIC_DEFAULT',
          key_usage: meta.KeyUsage ?? 'ENCRYPT_DECRYPT',
          key_state: meta.KeyState ?? null,
          multi_region: meta.MultiRegion ?? false,
          ...(meta.CustomKeyStoreId ? { custom_key_store_id: meta.CustomKeyStoreId } : {}),
          ...(meta.XksKeyConfiguration?.Id ? { xks_key_id: meta.XksKeyConfiguration.Id } : {}),
        }));
      }
    }
    const notes: string[] = [];
    if (awsManaged) notes.push(`kms ${ctx.scope.account}/${ctx.scope.region}: ${awsManaged} AWS-managed key(s) not inventoried (symmetric, not customer-configurable)`);
    if (pendingDeletion) notes.push(`kms ${ctx.scope.account}/${ctx.scope.region}: ${pendingDeletion} key(s) pending deletion skipped`);
    return { resources, notes };
  },
};
