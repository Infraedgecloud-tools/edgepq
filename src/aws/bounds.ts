/* Finite SDK retry/request limits shared by discovery, AssumeRole and collectors. */
export const AWS_LIMITS = {
  maxAttempts: 3,
  requestHandler: { connectionTimeout: 2000, requestTimeout: 10000, socketTimeout: 10000, throwOnRequestTimeout: true },
};

/* Never call a repeated-token truncation complete. Every page stream is finite
   even if a service returns fresh continuation tokens indefinitely. */
export async function* checkedPages<T extends object>(pages: AsyncIterable<T>, signal?: AbortSignal): AsyncGenerator<T> {
  const seen = new Set<string>();
  let count = 0;
  for await (const page of pages) {
    signal?.throwIfAborted();
    if (++count > 1000) throw new Error('AWS pagination exceeded 1000 pages');
    const p = page as Record<string, unknown>;
    const distributions = p.DistributionList as Record<string, unknown> | undefined;
    const token = p.NextToken ?? p.NextMarker ?? p.position ?? distributions?.NextMarker;
    if (typeof token === 'string' && token) {
      if (seen.has(token)) throw new Error('AWS pagination repeated a continuation token');
      seen.add(token);
    }
    yield page;
  }
}
