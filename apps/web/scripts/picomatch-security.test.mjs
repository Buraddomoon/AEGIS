import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { readFileSync, realpathSync } from 'node:fs'
import { createRequire } from 'node:module'
import { dirname, join } from 'node:path'
import { spawnSync } from 'node:child_process'
import { fileURLToPath } from 'node:url'
import test from 'node:test'

const require = createRequire(import.meta.url)
const web = dirname(dirname(fileURLToPath(import.meta.url)))
const vendor = join(web, 'vendor/picomatch')
const picomatch = require('picomatch')
const provenance = JSON.parse(readFileSync(join(vendor, 'provenance.json'), 'utf8'))
const hash = (value) => createHash('sha256').update(value).digest('hex')

test('installed build tools resolve the reviewed security fork and exact source hashes', () => {
  const identity = JSON.parse(readFileSync(join(vendor, 'package.json'), 'utf8'))
  assert.equal(identity.name, '@aegis/picomatch')
  assert.equal(identity.version, '4.0.7-aegis.1')
  assert.equal(identity.scripts, undefined)
  assert.equal(identity.dependencies, undefined)
  assert.equal(provenance.patch_commit, '1bf0d04563cb9ce568cf36efc5f6b7187d9911d5')
  assert.equal(
    provenance.patched_files['lib/parse.js'],
    '3c6d5e700359313dc2efc3a8719cbeb6dcac43377539a3db6990147b16dba687',
  )
  for (const [name, upstreamHash] of Object.entries(provenance.upstream_files)) {
    assert.equal(
      hash(readFileSync(join(vendor, name))),
      provenance.patched_files[name] ?? upstreamHash,
      name,
    )
  }
  const expected = realpathSync(join(vendor, 'index.js'))
  assert.equal(realpathSync(require.resolve('picomatch')), expected)
  for (const consumer of ['vite', 'vitest', 'tinyglobby', 'fdir']) {
    const fromConsumer = createRequire(require.resolve(consumer))
    assert.equal(realpathSync(fromConsumer.resolve('picomatch')), expected, consumer)
  }
})

for (const pattern of ['+(*)', '+(*a)', '*(*a)', '+(a*)', '+(a*b)', '*(*.js)']) {
  test(`${pattern} has no nested unbounded extglob quantifier`, () => {
    assert.doesNotMatch(picomatch.makeRe(pattern).source, /\)[+*]/)
  })
}

test('advisory inputs finish in a separate process with a hard deadline', () => {
  const child = spawnSync(
    process.execPath,
    [
      '-e',
      `
    const fs = require('node:fs');
    const {module,patterns} = JSON.parse(fs.readFileSync(0,'utf8'));
    const pm = require(module);
    const input = 'a'.repeat(20000) + '!';
    process.stdout.write(JSON.stringify(patterns.map(pattern => pm.isMatch(input,pattern))));
  `,
    ],
    {
      input: JSON.stringify({
        module: require.resolve('picomatch'),
        patterns: ['+(*a)', '*(*a)', '+(a*)c', '+(a*b)c', '*(*.js)c', '+(*)c'],
      }),
      encoding: 'utf8',
      timeout: 2000,
      maxBuffer: 4096,
    },
  )
  assert.ifError(child.error)
  assert.equal(child.status, 0, child.stderr)
  assert.deepEqual(JSON.parse(child.stdout), [false, false, false, false, false, false])
})

for (const [pattern, matching, excluded] of [
  ['+(*)c', ['abc', 'c', 'ac'], ['ab', 'a/bc']],
  ['+(*a)', ['a', 'aaa', 'a.a', 'baba'], ['ab', 'a/b/a']],
  ['+(a*b)', ['ab', 'axb', 'axbayb'], ['axbay', 'a/b']],
  ['*(*.js)', ['foo.js', 'a.jsb.js'], ['foo.ts', 'path/a.js']],
  ['src/**/*.{ts,tsx}', ['src/App.tsx', 'src/a/b.ts'], ['src/a.js', 'src/.hidden.ts']],
  ['**/*.test.tsx', ['src/a.test.tsx', 'a.test.tsx'], ['src/a.tsx', 'src/.a.test.tsx']],
  ['**/node_modules/**', ['node_modules/a/index.js', 'apps/web/node_modules/a'], ['src/a.ts']],
  ['@(foo|bar).js', ['foo.js', 'bar.js'], ['baz.js', 'path/foo.js']],
  ['!(*.d).ts', ['foo.ts'], ['foo.d.ts']],
  ['+("*a")', ['*a', '*a*a'], ['a', 'aaa']],
  ['*("*a")', ['*a', '*a*a'], ['a', 'aaa']],
  ['+("a"*b)', ['ab', 'axbayb'], ['axbay', 'a/b']],
  ['+([/]*a)', ['/a', '/a/a'], ['/ab', 'a']],
]) {
  test(`${pattern} preserves matching and path boundaries`, () => {
    for (const value of matching) assert(picomatch.isMatch(value, pattern), value)
    for (const value of excluded) assert(!picomatch.isMatch(value, pattern), value)
  })
}
