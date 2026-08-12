# Artifact integrity for Clojars releases: signing, SBOM, and verification

## Problem

The release library in `clj/` has strong authorization (a `clojars` environment with
required reviewers and a branch policy) and provenance by policy (a publish must run
in CI against a commit whose CI is green). It has essentially zero cryptographic
artifact integrity.

A consumer pulling `com.cleancoders.c3kit/bucket` cannot verify the jar came from this
organization's repository. The MD5/SHA-1 sidecars aether uploads are transport
checksums computed by the uploader; they prove nothing about authenticity, and SHA-1 is
collision-broken. Nine gaps follow from that, all addressed here:

| # | Gap | Where it is closed |
|---|---|---|
| 1 | No signing of any kind | §3 signing, §7 attestation |
| 2 | Unsigned lightweight tags | §8 tags |
| 3 | `verify-ci!` gates one workflow only | §6 CI gate |
| 4 | No post-publish verification | §5 publish verification |
| 5 | No SBOM | §4 SBOM |
| 6 | Artifact digest recorded nowhere | §8 tags, §9 job summary |
| 7 | Rebuild-at-release, not build-once-promote | §2 reproducible jar |
| 8 | No cryptographic floor under dependencies | §4 SBOM (dep digests), §10 docs |
| 9 | Break-glass path underspecified, no durable audit trail | §9 audit trail, §10 docs |

## Decisions

Made during design, with the reasoning that produced them:

- **Both GPG detached signatures and SLSA provenance attestations.** They answer
  different questions. A `.asc` proves the key holder produced these bytes and reaches
  a consumer who pulls from Clojars without touching GitHub. A provenance attestation
  proves this repository, workflow, and commit produced them, with no key to manage.
  Neither substitutes for the other.
- **SBOM generated in Clojure from the tools.build basis**, not by an external scanner.
  The basis holds the fully resolved transitive closure with exact versions, including
  `:git/sha` coordinates that no jar scanner can see. It is a pure function, so it is
  unit-testable, and it adds no binary to the most security-sensitive workflow in the
  organization.
- **Reproducible jars rather than build-once-promote.** Promoting the CI-built artifact
  is strictly stronger, but it requires every consumer's CI workflow to upload
  artifacts, makes artifact retention a release dependency, and adds a failure mode
  when a run has expired. Normalizing the jar is self-contained in this library, needs
  no consumer changes, and makes a recorded digest meaningful.
- **`:ci-workflow` accepts a string or a vector.** Backward compatible; the four
  existing consumers keep working and add `security.yml` when ready.
- **Signing is mandatory on the publish path.** `deploy!` and `emergency-deploy!` abort
  before building if no key is configured. An opt-in flag would default to the insecure
  behavior and let "we support signing" be true while artifacts stayed unsigned. The
  break-glass path is included deliberately: an emergency is not a reason to ship
  unverifiable bytes, and the abort message says exactly what is missing.
- **Post-publish verification polls, then aborts before tagging.** Clojars is
  eventually consistent, so a single immediate fetch would flap. An unverified artifact
  never gets a tag.
- **One organization release key** shared across repositories, its public half on
  keyservers and documented. A consumer verifying any c3kit artifact imports one key.

Explicitly out of scope: creating GitHub Releases with attached assets. It adds a
failure point after the artifact is already immutable on Clojars and duplicates
distribution that Clojars already performs.

## Architecture

Five new namespaces under `clj/src/cleancoders/build/`, each with one purpose and a
narrow interface. Process spawning stays confined to `shell/sh`, which is the existing
stub point, so every new decision is a pure function over command output.

| Namespace | Purpose | Public interface |
|---|---|---|
| `digest.clj` | Artifact digests | `(sha256 file)` → lowercase hex; `(hex bytes)` |
| `sbom.clj` | CycloneDX document | `(cyclonedx cfg)` → map; `(write! cfg)` → path |
| `sign.clj` | GPG key handling and signing | `(configured? env)`, `(import-key! env)`, `(sign-file! path)` |
| `publish-verify.clj` | Post-publish digest check | `(verdict fetched local)`, `(verify! cfg)` |
| `summary.clj` | Durable release record | `(render cfg)` → string; `(emit! text)` |

Modified: `jar.clj` (normalization, SBOM, signing hooks, `:artifact-map`),
`release.clj` (new gates, workflow vector, signed tags, audit trail), `api.clj`
(wiring and validation), `deps.edn` (explicit `:mvn/repos`), `README.md`.

### Dependency rules

`digest`, `sbom`, and `summary` depend on nothing in this library. `sign` and
`publish-verify` depend only on `shell`. `jar` depends on `digest`, `sbom`, and `sign`.
`release` depends on `shell`, `publish-verify`, `summary`, and `sign`. `api` wires them.
No cycles; nothing new depends on `release`.

## 1. Deploy sequence

`release/deploy!` runs these steps in order. Steps 2, 6, 8, and 9 are new; step 5 gains
work; step 10 changes behavior.

1. `assert-ci!` — unchanged
2. `assert-signing-key!` — abort if `GPG_PRIVATE_KEY` or `GPG_PASSPHRASE` is absent
3. `verify-ci!` — now every named workflow must be green
4. `assert-untagged!` — unchanged
5. `jar!` — build, normalize, generate SBOM
6. `sign!` — detached `.asc` for jar, pom, and SBOM
7. `publish!` — jar, pom, three `.asc` files, and the SBOM
8. `verify-published!` — poll Clojars, compare SHA-256, abort on mismatch
9. `record!` — digests to the job summary
10. `tag!` — signed annotated tag whose message carries the digests

`emergency-deploy!` runs the same sequence minus `verify-ci!`, plus the audit banner
described in §9. It keeps `assert-clean-tree!` where it is today.

The signing-key check is step 2, before `verify-ci!` spends API calls and before
anything is built, so a misconfigured environment costs one line of output:

```
ABORT: signing key not configured.
  deploy requires GPG_PRIVATE_KEY and GPG_PASSPHRASE in the
  clojars environment. See README "Signing keys".
  Nothing was built; no release occurred.
```

## 2. Reproducible jar (gap 7)

`jar/normalize!` rewrites the jar `b/jar` produced:

- entries sorted by name, with `META-INF/MANIFEST.MF` written first
- every entry timestamp set to the zip epoch, 1980-01-01T00:00:00Z
- no per-entry extra attributes, comments, or preserved file metadata
- directory entries retained but normalized identically

`build!` calls it after `b/jar`. Two consecutive builds of the same source then produce
byte-identical jars, so the digest recorded at release time is comparable to a digest
computed from any other build of that commit.

The determinism spec doubles as the detector for nondeterminism this design has not
anticipated. `tools.build`'s `write-pom` emits `pom.properties`; if that file carries a
`#<date>` comment, the spec fails and `normalize!` must strip comment lines from it.
Any similar source of drift surfaces the same way rather than silently weakening the
guarantee.

## 3. Signing (gap 1)

`sign/import-key!` runs once per release, before signing anything:

1. write a `gpg-agent.conf` with `allow-loopback-pinentry` and
   `default-cache-ttl 7200` (a release can outlast the 600-second default)
2. `gpg --batch --import` the armored key from `GPG_PRIVATE_KEY`
3. prime the agent by signing a scratch file with
   `--pinentry-mode loopback --passphrase-fd 0`
4. `git config user.signingkey` to the imported key id

Step 3 is load-bearing. Once the agent holds the passphrase, both `sign-file!` and
`git tag -s` work without further passphrase plumbing, which is what lets §8 sign tags
with the same key and no second mechanism.

`release/deploy!` calls `import-key!` once, then invokes a `:sign!` thunk the caller
supplies — the same arrangement `:jar!` and `:publish!` already use, so `release` never
learns which files a given consumer ships. `api` supplies a thunk that signs the jar,
the pom, and the SBOM; a two-artifact consumer like `c3kit-wire` supplies one that signs
both jars. `jar.clj` owns the file list and the `:artifact-map` that uploads it.

`sign/sign-file!` produces `<path>.asc` via `gpg --batch --yes --detach-sign --armor`,
checks the exit code, and confirms the `.asc` exists and is non-empty before returning.
A signing step that silently produced nothing would publish an empty signature.

The passphrase never appears in an argument vector — it goes to stdin — so it cannot
leak through a process listing or an error message that echoes the command.

## 4. SBOM (gaps 5, 8)

`sbom/cyclonedx` is a pure function of `{:lib :version :basis :jar-digest}`, returning a
CycloneDX 1.6 document:

- `metadata.component` — the artifact being released, purl
  `pkg:maven/<group>/<name>@<version>`
- `components` — one entry per `(:libs basis)` key, which is the fully resolved
  transitive closure. Maven coordinates map to `pkg:maven/<group>/<name>@<version>`;
  git coordinates map to `pkg:github/<owner>/<repo>@<sha>`.
- `hashes` — SHA-256 of each resolved dependency jar, read from that lib's `:paths`
- `bom-ref` — the purl, so references are stable
- `serialNumber` — a UUID derived deterministically from the jar digest
- no `metadata.timestamp`

The dependency hashes are the point of gap 8. `deps.edn` pins versions, not digests,
and `tools.deps` has no lockfile with hashes; that remains true. What changes is that
every release now records the exact dependency bytes it was built against, so a later
substitution upstream is detectable after the fact.

Omitting the timestamp and deriving the serial number keep the SBOM reproducible: the
same source produces the same SBOM. Release time is recorded by the tag and the
attestation, which are the right places for it.

Published as `<lib>-<version>-cyclonedx.json` — classifier `cyclonedx`, extension
`json`, matching the cyclonedx-maven-plugin convention a consumer's tooling expects.

## 5. Publish verification (gap 4)

`publish-verify/verify!` fetches
`https://repo.clojars.org/<group-path>/<name>/<version>/<name>-<version>.jar` with
`curl -fsSL` through `shell/sh`, hashes what came back, and compares it to the local
jar digest. Six attempts with backoff, roughly two minutes total.

```
publishing bucket-2.14.0.jar ... done
verifying published artifact (attempt 1/6) ... 404, retrying in 5s
verifying published artifact (attempt 2/6) ... sha256 match
tagging 2.14.0
```

`verdict` is a pure function of the fetched bytes' digest and the local digest, so the
mismatch, match, and absent cases are all unit-testable without a network.

Two failure modes, both aborting before any tag exists:

- **Digest mismatch** — registry-side substitution or a wrong artifact published. Abort
  naming both digests. This is the only detection this system has for that class of
  failure, so it must be loud and must not be retried into a pass.
- **Never fetched** — retries exhausted. Abort with the recovery text described in §11.

## 6. CI gate (gap 3)

`verify-ci!` takes `:ci-workflow` as either a string or a vector of strings. A vector
requires every named workflow to be `completed` + `success` at the current commit. Each
workflow is queried separately and `run-verdict` applied to each, so an abort names the
workflow that was not green:

```
ABORT: CI run concluded failure (security.yml @ 9fe1c0a)
```

`api/validate!` accepts both shapes and rejects a vector containing a blank entry, which
would otherwise build a malformed API path and read as a passing gate.

The existing reason `verify-ci!` is scoped to named workflows rather than the commit's
check-runs still holds and is unchanged: the release run registers its own check-run
against the same commit, so an all-check-runs-green query would observe itself as
`in_progress` and deadlock.

## 7. Attestations (gap 1)

The `release.yml` template gains `id-token: write` and `attestations: write`, and two
steps after `deploy` succeeds:

- `actions/attest-build-provenance` on the jar
- `actions/attest-sbom` on the CycloneDX file

Both run after the publish, not before. The attestation binds bytes to builder, not to
a moment in time, so a provenance statement created seconds after the upload is exactly
as strong as one created seconds before it. The alternative — splitting `deploy` so
attestation lands between build and publish — would move the gate sequence into YAML,
where it is neither testable nor reusable by escape-hatch consumers. That trade is not
worth an ordering that buys nothing.

## 8. Tags (gaps 2, 6)

`tag!` uses `git tag -s -a` with a message carrying the version, the commit, and the
SHA-256 of every published artifact:

```
2.14.0

commit: 9fe1c0a...
jar:    sha256:1f3a...
pom:    sha256:8c02...
sbom:   sha256:b71d...
```

The tag object is signed, so it is no longer forgeable by anyone holding `contents:
write`, and the digests survive in any clone — "what bits did we ship" is answerable
post-incident with no GitHub API and no log retention window.

README gains a branch-protection requirement: signed commits on `master`. A signed tag
over unsigned commits is a weaker chain than it appears.

## 9. Job summary and audit trail (gaps 6, 9)

`summary/emit!` appends to `$GITHUB_STEP_SUMMARY` when that variable is set and prints
to stdout otherwise, so a local break-glass release still produces the record.

Every release emits version, commit, and the digest of each published artifact.
`emergency-deploy!` additionally emits a banner naming the actor from
`GITHUB_ACTOR`, the version, the commit, and the fact that CI verification was
skipped.

README pins down the break-glass variable: it must be a variable on the `clojars`
environment, never a repository variable. A repository variable is readable and
settable outside the environment's reviewer gate, which would let the emergency path
skip CI verification without approval — the gate exists precisely to prevent that. The
docs add a `gh api` check confirming the variable is environment-scoped.

## 10. Documentation

README additions:

- **Signing keys** — generating the organization release key, exporting a signing
  subkey while the primary key stays offline, publishing the public half, adding
  `GPG_PRIVATE_KEY` and `GPG_PASSPHRASE` to each `clojars` environment, and rotation.
- **Verifying a release** — consumer-facing recipes:
  ```bash
  gpg --recv-keys <ORG_KEY_ID>
  gpg --verify bucket-2.14.0.jar.asc bucket-2.14.0.jar
  gh attestation verify bucket-2.14.0.jar --repo cleancoders/c3kit-bucket
  ```
- **Explicit `:mvn/repos`** in the deps.edn template, with the residual risk stated:
  versions are pinned, digests are not, and `tools.deps` has no lockfile with hashes.
  Mitigation is clj-watson plus the dependency digests the SBOM now records; the
  remainder is documented accepted risk.
- **Break-glass** — the environment-scoped variable requirement and its check.
- Updated `release.yml` template with the new permissions, the inline `gpg` import
  step, and the attestation steps. No third-party action for key import: this repository
  pins its own supply chain, and an import step is a handful of lines.

## Testing

Speclj, following the existing pattern: stub `shell/sh` for process calls and rebind
`release/abort!` to capture aborts instead of exiting. New spec files mirror the new
namespaces; `jar_spec`, `release_spec`, and `api_spec` gain cases.

| Area | Cases |
|---|---|
| `digest` | known-vector SHA-256; hex encoding is lowercase and zero-padded |
| `sbom` | maven and git coordinates produce correct purls; dependency hashes present; no timestamp; serial number stable across two calls with the same digest and different for a different digest |
| `sign` | `configured?` false when either variable is blank; passphrase passed on stdin, never in the argument vector; non-zero gpg exit aborts; empty or missing `.asc` aborts |
| `publish-verify` | match, mismatch, and absent verdicts; retries stop at the cap; mismatch is never retried into a pass |
| `summary` | renders every digest; writes to the summary file when set, stdout when not; emergency banner names actor, version, and commit |
| `jar` | two builds produce identical SHA-256; `:artifact-map` carries exactly the three `.asc` files and the SBOM |
| `release` | key check precedes `verify-ci!` and the build; vector `:ci-workflow` requires all green and names the red one; failure after publish yields the artifact-is-live message; `tag!` invokes `-s -a` with digests in the message |
| `api` | string and vector `:ci-workflow` both validate; a vector with a blank entry aborts |

`self-test.yml` already runs `clojure -M:test:spec` in `clj/`, so new specs run there
with no workflow change.

## Failure semantics

Everything before `publish!` aborts clean: nothing was uploaded, nothing was tagged,
and the abort names what to fix.

Everything after `publish!` extends the existing message shape, which exists because
the artifact is already live on Clojars and cannot be republished. The message must not
let a maintainer conclude the release failed and retry it. It now names which step
failed — verification or tagging — and gives the exact repair:

```
ABORT: published 2.14.0 but could not verify it on Clojars.
  The artifact is live and cannot be republished. Verify by hand:
    curl -fsSL https://repo.clojars.org/.../bucket-2.14.0.jar | shasum -a 256
    expected: 1f3a...
  If it matches, finish the release with:
    git tag -s -a 2.14.0 9fe1c0a -m "..."
    git push origin refs/tags/2.14.0
```

## Rollout

Consumers pin a full `:git/sha` of `clj/`, so nothing changes for them until they bump
that pin. When they do, the `clojars` environment must already hold `GPG_PRIVATE_KEY`
and `GPG_PASSPHRASE` or the next release stops at step 2 with a message naming exactly
what to add. Order per repository: provision the secrets, update `release.yml` from the
template, then bump the pin.
