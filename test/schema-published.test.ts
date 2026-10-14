/* The findings schema declares an $id on the website; the website serves a
   copy under that path. The two must be the same bytes, or the published
   schema describes a different document from the one the tool writes. */
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';

const source = fileURLToPath(new URL('../src/render/findings.schema.json', import.meta.url));
const published = fileURLToPath(new URL('../../infraedge-website/schemas/edgepq-findings-1.json', import.meta.url));

test('the website serves the findings schema at its $id', async () => {
  const schema = JSON.parse(await readFile(source, 'utf8')) as { $id: string };
  assert.equal(schema.$id, 'https://infraedge.org/schemas/edgepq-findings-1.json');
  assert.equal(await readFile(published, 'utf8'), await readFile(source, 'utf8'), 'copy edgepq/src/render/findings.schema.json to infraedge-website/schemas/edgepq-findings-1.json');
});
