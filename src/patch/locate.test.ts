import test from 'node:test';
import assert from 'node:assert/strict';
import { locateAttribute, locateResource } from './locate.ts';

const attr = (text: string, type: string, name: string, path: string) => {
  const res = locateResource(text, type, name);
  assert.ok(res, 'resource not found');
  return locateAttribute(text, { ...res.body, duplicate: res.duplicate }, path);
};

test('braces inside strings and nested interpolation do not end a block', () => {
  const t = [
    'resource "aws_lb_listener" "a" {',
    '  name = "a{b}"',
    '  tags = "${join("}", [for x in var.l : "${x}{"])}"',
    '  ssl_policy = "old"',
    '}',
    'resource "aws_lb_listener" "b" {',
    '  ssl_policy = "b"',
    '}',
    '',
  ].join('\n');
  const a = locateResource(t, 'aws_lb_listener', 'a')!;
  assert.ok(t.slice(a.range.start, a.range.end).endsWith('"old"\n}'));
  const loc = attr(t, 'aws_lb_listener', 'a', 'ssl_policy');
  assert.equal(loc.kind, 'literal-string');
  if (loc.kind === 'literal-string') {
    assert.equal(t.slice(loc.valueRange.start, loc.valueRange.end), '"old"');
    assert.equal(loc.line, 4);
  }
  assert.equal(attr(t, 'aws_lb_listener', 'a', 'tags').kind, 'present-not-literal');
});

test('escaped $${ is a literal, not an interpolation', () => {
  const t = 'resource "x" "y" {\n  a = "$${not{ready"\n  b = "v"\n}\n';
  const a = attr(t, 'x', 'y', 'a');
  assert.equal(a.kind, 'literal-string');
  assert.equal(attr(t, 'x', 'y', 'b').kind, 'literal-string');
});

test('a heredoc with a lone } line does not end the block', () => {
  const t = 'resource "x" "y" {\n  policy = <<-EOT\n  {\n}\n  EOT\n  mode = "m"\n}\nresource "x" "z" {\n  mode = "z"\n}\n';
  assert.equal(attr(t, 'x', 'y', 'policy').kind, 'present-not-literal');
  assert.equal(attr(t, 'x', 'y', 'mode').kind, 'literal-string');
  assert.equal(attr(t, 'x', 'z', 'mode').kind, 'literal-string');
});

test('comments containing a resource header or braces are ignored', () => {
  const t = [
    '# resource "x" "y" {',
    '// resource "x" "y" {',
    '/* resource "x" "y" {',
    '} */',
    'resource "x" "y" {',
    '  # } stray',
    '  a = "1" // }',
    '}',
    '',
  ].join('\n');
  const res = locateResource(t, 'x', 'y')!;
  assert.equal(res.duplicate, false);
  assert.equal(attr(t, 'x', 'y', 'a').kind, 'literal-string');
});

test('two resources in one file, and a resource defined twice is ambiguous', () => {
  const t = 'resource "x" "a" {\n  v = "1"\n}\nresource "x" "a" {\n  v = "2"\n}\nresource "x" "b" {\n  v = "3"\n}\n';
  assert.equal(locateResource(t, 'x', 'a')!.duplicate, true);
  assert.equal(attr(t, 'x', 'a', 'v').kind, 'ambiguous');
  assert.equal(attr(t, 'x', 'b', 'v').kind, 'literal-string');
  assert.equal(locateResource(t, 'x', 'nope'), undefined);
});

test('nested block paths, repeated blocks and dynamic blocks', () => {
  const t = [
    'resource "x" "y" {',
    '  vc {',
    '    min = "old"',
    '  }',
    '  rep {',
    '    a = "1"',
    '  }',
    '  rep {',
    '    a = "2"',
    '  }',
    '  dynamic "gen" {',
    '    for_each = var.l',
    '    content {',
    '      k = "v"',
    '    }',
    '  }',
    '}',
    '',
  ].join('\n');
  assert.equal(attr(t, 'x', 'y', 'vc.min').kind, 'literal-string');
  assert.equal(attr(t, 'x', 'y', 'rep.a').kind, 'ambiguous');
  assert.equal(attr(t, 'x', 'y', 'gen.k').kind, 'ambiguous');
  assert.equal(attr(t, 'x', 'y', 'missing.k').kind, 'ambiguous');
});

test('absent attribute: inserted after the last attribute, before nested blocks', () => {
  const t = 'resource "x" "y" {\n  a = 1\n  b = 2\n  inner {\n    c = 3\n  }\n}\n';
  const loc = attr(t, 'x', 'y', 'new');
  assert.equal(loc.kind, 'absent');
  if (loc.kind === 'absent') {
    assert.equal(loc.indent, '  ');
    assert.equal(t.slice(loc.insertAt, loc.insertAt + 7), '  inner');
    assert.equal(loc.align, undefined);
  }
});

test('absent attribute: attributes after a block means the end of the body', () => {
  const t = 'resource "x" "y" {\n  inner {\n    c = 3\n  }\n  a = 1\n}\n';
  const loc = attr(t, 'x', 'y', 'new');
  assert.equal(loc.kind, 'absent');
  if (loc.kind === 'absent') assert.equal(t.slice(loc.insertAt), '}\n');
});

test('absent attribute: aligned equals signs are reported', () => {
  const t = 'resource "x" "y" {\n  name   = "n"\n  region = "r"\n}\n';
  const loc = attr(t, 'x', 'y', 'new');
  assert.equal(loc.kind === 'absent' && loc.align, 9);
});

test('absent attribute: a one-line block is refused', () => {
  assert.equal(attr('resource "x" "y" {\n  b { a = 1 }\n}\n', 'x', 'y', 'b.c').kind, 'ambiguous');
});
