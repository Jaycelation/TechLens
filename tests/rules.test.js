import test from 'node:test';
import assert from 'node:assert/strict';
import { RULES, matchRule } from '../engine.js';

const SOURCES = new Set(['urls', 'markers', 'meta', 'inline', 'css', 'headers', 'banners']);
const input = (rule, value) => (rule.source === 'headers' ? { name: rule.header, value } : value);
const label = (rule) => `${rule.name} (${rule.source}${rule.header ? ':' + rule.header : ''})`;

test('every rule has a valid shape', () => {
  for (const rule of RULES) {
    assert.equal(typeof rule.name, 'string', label(rule));
    assert.ok(Array.isArray(rule.categories) && rule.categories.length, label(rule));
    assert.ok(SOURCES.has(rule.source), label(rule));
    assert.ok(['high', 'medium'].includes(rule.confidence), label(rule));
    assert.doesNotThrow(() => new RegExp(rule.pattern, 'i'), label(rule));
    if (rule.source === 'headers')
      assert.equal(rule.header, rule.header.toLowerCase(), label(rule));
    if (rule.version) assert.ok(Number.isInteger(rule.version), label(rule));
  }
});

test('every rule ships at least one matching example', () => {
  for (const rule of RULES) assert.ok(rule.examples?.match?.length, label(rule));
});

for (const rule of RULES)
  test(`fixture: ${label(rule)}`, () => {
    for (const example of rule.examples.match) {
      const hit = matchRule(rule, input(rule, example.input));
      assert.ok(hit, `should match: ${example.input}`);
      assert.equal(hit.version, example.version, `version for: ${example.input}`);
    }
    for (const value of rule.examples.noMatch)
      assert.equal(matchRule(rule, input(rule, value)), null, `should not match: ${value}`);
  });
