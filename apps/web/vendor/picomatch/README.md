# Local security fork of picomatch4.0.7

Private package `@aegis/picomatch@4.0.7-aegis.1`, used only by build/test tooling.
It is not an upstream release. The original MIT license is retained in LICENSE.

The official npm4.0.7tarball was checked against the previous lockfile SHA512;
its SHA256 and original file hashes are in provenance.json. Eight runtime/license
files were copied exactly. Only lib/parse.js changes: the reviewed correction
from [upstream PR237](https://github.com/micromatch/picomatch/pull/237), commit
`1bf0d04563cb9ce568cf36efc5f6b7187d9911d5`, applied to the release code.
The local review additionally preserves quoted literal-star repetitions and
excludes all slash-containing branches from that collapse optimization; the
additional regression cases compare those semantics with the original release.
That PR was unmerged when reviewed on17/11/2026. The package metadata explicitly
identifies this local fork and contains no lifecycle scripts or dependencies.

The correction collapses the outer repetition of a single simple branch that
contains a star. Repeating that language does not expand it: `+(P)` becomes
`(?:P)` and `*(P)` becomes `(?:P)?`. This removes nested unbounded quantifiers
for the advisory examples, including `+(*a)` and `+(*)c`, while retaining match
semantics. Existing upstream handling of other extglobs and its explicit
`maxExtglobRecursion: false` option remain unchanged. Build consumers use the
default safety options; no API/YAML input supplies glob options.

`package.json` declares this local directory as the direct picomatch dependency;
the override points all transitive consumers to that exact direct specification.
This is a source replacement, not an audit advisory exception. No dependency
version was downgraded, advisory ID excluded or audit threshold changed.

The registry advisory still applies to the upstream package. npm does not assess
a private local fork against that upstream version, so its zero findings alone
do not establish a fix. `npm run test:glob-security` therefore also checks:

- Exact runtime file hashes and the pinned patched parser hash.
- Actual module resolution from Vite, Vitest, tinyglobby and fdir.
- Missing nested quantifiers for six problematic patterns.
- Hostile matching in a subprocess with a hard2second deadline.
- Matching/path-boundary semantics used by the build tools.

The test runs before every normal frontend test suite and in `make audit`.
Docker copies this directory before npm ci. No Git download, patch application,
registry publication or remote update occurs during installation/startup.

Replace this fork only after an official fix is published and reviewed; remove
the direct file dependency/override/vendor together, rerun the security tests,
full React/build/E2E and audit. Recheck newly reported advisories independently;
this patch addresses GHSA-fc5q-39xc-vjpf, not every possible glob complexity issue.
