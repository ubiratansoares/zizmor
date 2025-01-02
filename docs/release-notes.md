---
description: Abbreviated change notes about each zizmor release.
---

# Release Notes

This page contains _abbreviated_, user-focused release notes for each version
of `zizmor`.

## Upcoming (UNRELEASED)

## v1.0.0

This is the first stable release of `zizmor`!

Starting with this release, `zizmor` will use [Semantic Versioning] for
its versioning scheme. In short, this means that breaking changes will only
happen with a new major version.

[Semantic Versioning]: https://semver.org/

This stable release comes with a large number of new features as well
as stability commitments for existing features; read more below!

### Added

* Composite actions (i.e. `action.yml` where the action is *not* a Docker
  or JavaScript action) are now supported, and are audited by default
  when running `zizmor` on a directory or remote repository (#331)

    !!! tip

        Composite action discovery and auditing can be disabled by passing
        `--collect=workflows-only`. Conversely, workflow discovery and auditing
        can be disabled by passing `--collect=actions-only`.

    See #350 for the status of each audit's support for analyzing
    composite actions.

* The GitHub host to connect to can now be configured with `--gh-hostname`
  or `GH_HOST` in the environment (#371)

    This can be used to connect to a GitHub Enterprise (GHE) instance
    instead of the default `github.com` instance.

### Improved

* The [cache-poisoning] audit is now aware of common publishing actions
  and uses then to determine whether to produce a finding (#338, #341)
* The [cache-poisoning] audit is now aware of configuration-free caching
  actions, such as @Mozilla-Actions/sccache-action (#345)
* The [cache-poisoning] audit is now aware of even more caching actions
  (#346)
* The [cache-poisoning] audit is now aware of common publishing triggers
  (such as pushing to a release branch) and uses them to determine whether
  to produce a finding (#352)
* The [github-env] audit is now significantly more precise on `bash` and `pwsh`
  inputs (#354)

### Fixed

* The [excessive-permissions] audit is now less noisy on single-job workflows (#337)
* Expressions like `function().foo.bar` are now parsed correctly (#340)
* The [cache-poisoning] defaults for `setup-go` were fixed (#343)
* `uses:` matching is now case-insensitive where appropriate (#353)
* Quoted YAML keys (like `'on': foo`) are now parsed correctly (#368)

## v0.10.0

**Full Changelog**: https://github.com/woodruffw/zizmor/compare/v0.9.2...v0.10.0

### New Features 🌈
* feat: handle powershell in github-env audit by @woodruffw in #227
* feat: template-injection: filter static envs by @woodruffw in #318
* feat: add 'primary' locations by @woodruffw in #328
* feat: initial cache-poisoning audit by @ubiratansoares in #294
* feat: Fix Sarif schema and add rules to Sarif files  by @fcasal in #330

### Bug Fixes 🐛
* fix: template-injection: more safe contexts by @woodruffw in #309
* fix: expands_to_static_values considers expressions inside strings by @woodruffw in #317
* fix: sarif: add result and kind by @woodruffw in #68
* fix: sarif: use ResultKind for kind by @woodruffw in #326

### Performance Improvements 🚄
* refactor: use http-cache for caching, optimize network calls by @woodruffw in #304

### Documentation Improvements 📖
* docs: support commits in trophy case by @woodruffw in #303
* docs: Fix typo in development.md by @JustusFluegel in #305

### New Contributors
* @jsoref made their first contribution in #299
* @JustusFluegel made their first contribution in #305
* @fcasal made their first contribution in #330

## v0.9.2

**Full Changelog**: https://github.com/woodruffw/zizmor/compare/v0.9.1...v0.9.2

### Bug Fixes 🐛
* fix: template-injection: consider runner.tool_cache safe by @woodruffw in #297

### Documentation Improvements 📖
* docs: more trophies by @woodruffw in #296

## v0.9.1

**Full Changelog**: https://github.com/woodruffw/zizmor/compare/v0.9.0...v0.9.1

### Bug Fixes 🐛

* fix: dont crash when an expression does not expand a matrix by @ubiratansoares in #284

## v0.9.0

**Full Changelog**: https://github.com/woodruffw/zizmor/compare/v0.8.0...v0.9.0

### New Features 🌈
* refactor: experiment with tracing by @woodruffw in #232
* feat: remove --no-progress by @woodruffw in #248

### Bug Fixes 🐛
* fix: handle non-static env: in job steps by @woodruffw in #246
* fix: template-injection: ignore another safe context by @woodruffw in #254
* fix: download both .yml and .yaml from repos by @woodruffw in #265
* fix: bump annotate-snippets to fix crash by @woodruffw in #264
* fix: move artipacked pendantic finding to auditor by @woodruffw in #272
* fix: template-injection: ignore runner.temp by @woodruffw in #277

### Performance Improvements 🚄
* feat: evaluates a matrix expansion only once by @ubiratansoares in #274

### Documentation Improvements 📖
* docs: document installing with PyPI by @woodruffw in #242
* docs: add a trophy case by @woodruffw in #243
* docs: update pre-commit docs to point to new repo by @woodruffw in #247
* docs: switch GHA example to uvx by @woodruffw in #255
* docs: add template-injection tips by @woodruffw in #259
* docs: audits: add another env hacking reference by @woodruffw in #266
* docs: Rename "unsecure" to insecure by @szepeviktor in #270
* docs: more trophies by @woodruffw in #276
* docs: make the trophy case prettier by @woodruffw in #279

## New Contributors
* @szepeviktor made their first contribution in #270

## v0.8.0

**Full Changelog**: https://github.com/woodruffw/zizmor/compare/v0.7.0...v0.8.0

### New Features 🌈
* feat: remote auditing by @woodruffw in #230

### Bug Fixes 🐛
* fix: template-injection: ignore issue/PR numbers by @woodruffw in #238

### Documentation Improvements 📖
* docs: restore search plugin by @lazka in #239

## New Contributors
* @lazka made their first contribution in #239

## v0.7.0

**Full Changelog**: https://github.com/woodruffw/zizmor/compare/v0.6.0...v0.7.0

### New Features 🌈
* Split unpinned-uses into two separate checks by @funnelfiasco in #205
* feat: even more precision for bash steps in github-env by @ubiratansoares in #208
* feat: add Step::default_shell by @woodruffw in #213
* feat: handle `shell: sh` in github-env by @woodruffw in #216
* feat: primitive Windows batch handling in github-env by @woodruffw in #217
* feat: unpinned-uses: make unhashed check pedantic for now by @woodruffw in #219
* feat: add personas by @woodruffw in #226

### Bug Fixes 🐛
* fix: bump github-actions-models by @woodruffw in #211

### Documentation Improvements 📖
* docs: tweak installation layout by @woodruffw in #223

## v0.6.0

**Full Changelog**: https://github.com/woodruffw/zizmor/compare/v0.5.0...v0.6.0

This is one of `zizmor`'s bigger recent releases! Key enhancements include:

* A new `github-env` audit that detects dangerous `GITHUB_ENV` writes,
  courtesy of @ubiratansoares
* The `--min-severity` and `--min-confidence` flags for filtering results,
  courtest (in part) of @Ninja3047
* Support for `# zizmor: ignore[rule]` comments, courtesy of @ubiratansoares

### New Features 🌈

* feat: adds support to inlined ignores by @ubiratansoares in #187
* feat: add `--min-severity` by @woodruffw in #193
* feat: add `--min-confidence` by @Ninja3047 in #196
* feat: adds new github-env audit by @ubiratansoares in #192
* feat: improve precision for github-env by @woodruffw in #199
* feat: generalized ignore comments by @woodruffw in #200

### Documentation Improvements 📖

* docs: document ignore comments by @woodruffw in #190
* docs: usage: add note about support for ignore comments by @woodruffw in #191
* docs: add page descriptions by @woodruffw in #194
* docs: add more useful 3p references by @woodruffw in #198

## New Contributors

* @Ninja3047 made their first contribution in #196

## v0.5,0

**Full Changelog**: https://github.com/woodruffw/zizmor/compare/v0.4.0...v0.5.0

### New Features 🌈
* feat: improve workflow registry error by @woodruffw in #172
* feat: unsecure-commands-allowed audit by @ubiratansoares in #176

### Documentation Improvements 📖
* docs: rewrite audit docs by @woodruffw in #167
* docs: enable social card generation by @miketheman in #175
* docs: more badges by @woodruffw in #180
* docs: adds recommentations on how to add or change audits by @ubiratansoares in #182

## New Contributors
* @chenrui333 made their first contribution in #90

## v0.4.0

**Full Changelog**: https://github.com/woodruffw/zizmor/compare/v0.3.2...v0.4.0

### New Features 🌈
* Fix singular and plural for 'findings' by @hugovk in #162
* feat: unpinned-uses audit by @woodruffw in #161

### Bug Fixes 🐛
* Fix typos including `github.repostoryUrl` -> `github.repositoryUrl` by @hugovk in #164

## v0.3,2

**Full Changelog**: https://github.com/woodruffw/zizmor/compare/v0.3.1...v0.3.2

### What's Changed
* fix(cli): remove '0 ignored' from another place by @woodruffw in #157
* perf: speed up impostor-commit's fast path by @woodruffw in #158
* fix(cli): fixup error printing by @woodruffw in #159

## v0.3.1

**Full Changelog**: https://github.com/woodruffw/zizmor/compare/v0.3.0...v0.3.1

### What's Changed
* feat(cli): don't render "0 ignored" by @woodruffw in #148
* feat: --no-exit-codes + sarif tweaks by @woodruffw in #154

### New Contributors
* @baggiponte made their first contribution in #150

## v0.3.0

**Full Changelog**: https://github.com/woodruffw/zizmor/compare/v0.2.1...v0.3.0

### What's Changed

* feat: exit code support by @woodruffw in #133
* fix: github.event.merge_group.base_sha is a safe context by @woodruffw in #137
* fix: exclude information about the repo and owner by @funnelfiasco in #136
* feat: add `--no-config` by @woodruffw in #142

## v0.2.1

**Full Changelog**: https://github.com/woodruffw/zizmor/compare/v0.2.0...v0.2.1

### What's Changed
* refactor: clean up expr APIs slightly by @woodruffw in #126
* feat: Exclude safe values from template injection rule by @funnelfiasco in #128
* fix: bump github-actions-models by @woodruffw in #131
* feat: analyze expressions for safety by @woodruffw in #127

## v0.2.0

**Full Changelog**: https://github.com/woodruffw/zizmor/compare/v0.1.6...v0.2.0

### What's Changed
* chore: add description to `--help` by @woodruffw in #111
* fix: bump github-actions-models by @woodruffw in #112
* feat: improves plain output with audit confidence by @ubiratansoares in #119
* fix: bump github-actions-models by @woodruffw in #120
* docs: improve usage page and options for sarif and code scanning by @tobiastornros in #121
* feat: configuration file support by @woodruffw in #116

### New Contributors
* @dependabot made their first contribution in #118
* @tobiastornros made their first contribution in #121

## v0.1.6

**Full Changelog**: https://github.com/woodruffw/zizmor/compare/v0.1.5...v0.1.6

### What's Changed
* feat: accept multiple arguments as inputs by @miketheman in #104

## v0.1.5

**Full Changelog**: https://github.com/woodruffw/zizmor/compare/v0.1.4...v0.1.5

### What's Changed
* Exclude `github.run_*` from template injection check by @funnelfiasco in #92
* fix(ci): move read permissions to job scope by @miketheman in #95
* fix: links in README.md by @dmwyatt in #96
* test: adds acceptance tests on top of json-formatted output by @ubiratansoares in #97
* docs: add an example GHA workflow by @woodruffw in #98
* docs: update readme by @miketheman in #100
* docs: show example for usage in private repos by @miketheman in #99

### New Contributors
* @funnelfiasco made their first contribution in #92
* @dmwyatt made their first contribution in #96
* @ubiratansoares made their first contribution in #97

## v0.1.4

**Full Changelog**: https://github.com/woodruffw/zizmor/compare/v0.1.3...v0.1.4

### What's Changed
* perf: Enable Link-Time Optimization (LTO) by @zamazan4ik in #81
* feat: begin prepping zizmor's website by @woodruffw in #78
* fix: Always use the plain formatter even when the output is not a terminal by @asmeurer in #83
* feat: show version by @miketheman in #84
* fix: finding url link to audits doc by @amenasria in #87

### New Contributors
* @zamazan4ik made their first contribution in #81
* @asmeurer made their first contribution in #83
* @amenasria made their first contribution in #87

## v0.1.3

**Full Changelog**: https://github.com/woodruffw/zizmor/compare/v0.1.2...v0.1.3

### What's Changed
* fix: use relative workflow paths in SARIF output by @woodruffw in #77

## v0.1.2

**Full Changelog**: https://github.com/woodruffw/zizmor/compare/v0.1.1...v0.1.2

### What's Changed
* feat: github.ref_name is always an injection risk by @woodruffw in #67
* Create workflow that runs zizmor latest by @colindean in #71
* Link to GitHub workflow examples by @ncoghlan in #70
* docs: add homebrew install by @miketheman in #74
* fix: bump github-actions-models by @woodruffw in #75

### New Contributors
* @colindean made their first contribution in #71
* @ncoghlan made their first contribution in #70

## v0.1.1

**Full Changelog**: https://github.com/woodruffw/zizmor/compare/v0.1.0...v0.1.1

### What's Changed
* Fix typo: security -> securely by @hugovk in #61
* fix: bump github-action-models by @woodruffw in #65

### New Contributors
* @hugovk made their first contribution in #61

<!-- useful shortlinks -->

[excessive-permissions]: ./audits.md#excessive-permissions
[cache-poisoning]: ./audits.md#cache-poisoning
[github-env]: ./audits.md#github-env