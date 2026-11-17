# Picomatch remediation for #13

The final CI of the initial #13delivery reported GHSA-fc5q-39xc-vjpf in the
published picomatch4.0.7build dependency, affecting Vite/Vitest transitively.
The [advisory](https://github.com/advisories/GHSA-fc5q-39xc-vjpf) had no patched
published version on17/11/2026; npm registry metadata still reported4.0.7latest.
A forced downgrade did not provide a suitable fix because the advisory covers
all earlier published versions too.

The remediation is a reviewed local source fork with a real parser correction,
not a suppression. See [provenance and maintenance](../../apps/web/vendor/picomatch/README.md).
The upstream release tarball matches the former lockfile integrity. Only its
parser is patched, based on the public PR237commit pinned there, with local
quoted-literal/path-separator guards added during review; license retained.
All consumer resolutions and exact hashes are tested. The dependency manifest
and Docker copy order make installation reproducible without fetching a Git head.
The original npm audit command and high threshold remain unchanged.

Bounded before/after reproduction in separate processes, `+(*a)` against
40letters `a` followed by `!`: the unmodified release exceeded the1second hard
deadline and was terminated; the patched implementation rejected the input in
1.69ms in the observed local run. Timings are observations, not performance
promises. CI regression tests use20,001characters and a2second hard deadline,
with semantic/path-boundary cases alongside the pathological patterns.

A local private fork is outside the registry advisory mapping. Therefore
npm audit0 is reported separately from the21security regressions and consumer
build/tests; it is not a blanket claim that the dependency has no vulnerabilities.
There are no audit allowlists/exclusions or severity relaxations. New findings
remain blocking. No runtime Lab, network profile, PKI, runner or volume is changed.

Review found that applying PR237unchanged would collapse quoted literal-star
repetitions and a slash inside a character class incorrectly. The local guard
tracks quotes and refuses slash-containing branches; focused regressions cover
both, including an unquoted star after a quoted literal. An additional bounded
local comparison exercised11patterns against1,555short inputs (17,105comparisons)
with no match-result differences from the original release. This comparison is
separate from the hard-deadline regression on long hostile inputs.
