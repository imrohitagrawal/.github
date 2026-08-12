// WP1 self-test fixture: a real, passing test executed by `npm test` (which
// runs `node --test`) so the self-test's Node-only scenario proves the
// reusable workflow's "npm test" step actually ran a real test runner
// against real content, not just that a package.json exists.
const test = require('node:test');
const assert = require('node:assert');

test('fixture sanity: addition works', () => {
  assert.strictEqual(1 + 1, 2);
});
