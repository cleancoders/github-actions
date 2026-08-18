# The SBOM

[← back to the README](../README.md)

## What an SBOM is

An SBOM — Software Bill of Materials — is a machine-readable list of everything that went
into a build. Think of it as the ingredients label on the jar: not just your code, but
every library your code pulled in, and every library *those* pulled in, with exact
versions.

You already have something like this in `deps.edn`. The difference is scope and
resolution. `deps.edn` lists what you asked for; the SBOM lists what you actually got,
after `tools.deps` resolved the whole transitive tree and picked a winner for every
conflict. Those are frequently not the same set, and the gap is exactly where "which
version of that library are we actually shipping against?" becomes hard to answer.

## Why it is worth publishing

Two concrete uses, both after the fact:

**Answering "are we affected?" quickly.** When a CVE lands against some library, the
question is whether any of your releases were built against an affected version. Without
an SBOM you re-resolve the dependency tree as it exists *today* and hope that tells you
something about a build from four months ago. With one, you read the answer off the
release.

**Detecting a substitution.** This is the sharper one, and it needs explaining. `deps.edn`
pins **versions**, not **content**. There is no lockfile with hashes in the `tools.deps`
world, so nothing cryptographically constrains what `{:mvn/version "1.2.3"}` resolves to
at build time. If someone were able to replace the bytes behind a published coordinate,
your build would pick up the new bytes and nothing would complain.

So our SBOM records the **SHA-256 of every dependency jar** the release was built
against, not just its version. That does not prevent a substitution — nothing here can —
but it makes one *discoverable*: two releases whose SBOMs disagree about the digest of an
unchanged dependency version is a finding. That is the floor, and it is honest to call it
detection rather than prevention. Pair it with `clj-watson` in CI for the
known-vulnerability side.

## Turning it on

The SBOM is **opt-in**, and off unless you ask for it:

```clojure
:exec-args {:group       "com.example"
            :lib-name    "mylib"
            :repo        "example/mylib"
            :ci-workflow ["test.yml"]
            :license-url "https://github.com/example/mylib/blob/master/LICENSE"
            :sbom        true}    ;; <- this
```

It is off by default because generating one hashes every jar in the resolved dependency
closure, and that is real work to do on every `clj -T:build jar` and every
`clj -T:build install` for a consumer who never asked for it.

With `:sbom true`, the SBOM is written to `target/<lib>-<version>-cyclonedx.json` during
the build, published to Clojars alongside the jar under the `cyclonedx` classifier, and
signed if `:sign` is also on.

Consumers fetch it the same way they fetch anything else from Clojars:

```bash
curl -fsSL https://repo.clojars.org/com/example/mylib/2.14.0/mylib-2.14.0-cyclonedx.json | jq .
```

## What is in ours

The format is [CycloneDX](https://cyclonedx.org/) 1.6, which is one of the two formats
tooling generally understands (SPDX is the other).

The document is built from the **tools.build basis** rather than by scanning the finished
jar. That choice matters: the basis holds the fully resolved transitive closure with exact
versions, *including `:git/sha` coordinates* — dependencies pulled straight from git,
which never appear in the pom and which a jar scanner therefore cannot see at all.

Each entry gets a [purl](https://github.com/package-url/purl-spec) — a package URL, the
standard way to name a package unambiguously across ecosystems:

| Dependency kind | purl | Extra |
|---|---|---|
| Maven / Clojars | `pkg:maven/<group>/<name>@<version>` | SHA-256 of each resolved jar |
| Git | `pkg:github/<owner>/<repo>@<sha>` | none needed — the sha *is* the content identity |

Git dependencies carry no hashes because they do not need any: the `:git/sha` already
identifies exact content. A Maven version does not, which is why those entries carry
digests.

## Why there is no timestamp in it

The document is **deterministic**: the same source produces a byte-identical SBOM. There
is no build timestamp, and the `serialNumber` is derived from the jar's own digest rather
than being random.

That is deliberate, and it is in service of something else. The jar itself is built to be
byte-reproducible, so a consumer can rebuild a tagged release and confirm the digest
matches. A timestamp anywhere in the published set would break that property for no gain:
"when was this released" is already recorded by the git tag and the attestation, which are
the right places for it.

One consequence worth knowing: the `serialNumber` is *not* an RFC 4122 version-4 UUID. It
is a function of the artifact, formatted to match the shape CycloneDX validates. Two
builds of the same source get the same serial number; two different releases get
different ones.

## What it is attested as

When `:sbom` is on and you use the workflow template in [releasing](releasing.md), the
`attest-sbom` step binds the SBOM to the jar it describes. A consumer can then check not
just that the SBOM is signed, but that this SBOM belongs to this artifact — see
[verifying a release](verifying-a-release.md).
