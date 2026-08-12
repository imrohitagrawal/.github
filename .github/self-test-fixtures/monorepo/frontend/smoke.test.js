const test = require('node:test');
const assert = require('node:assert');

test('fixture sanity: multiplication works', () => {
  assert.strictEqual(2 * 3, 6);
});
