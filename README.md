# Static integrity.js integrity

This repository contains the version history of `static/js/integrity.js` of the WebFluid `ocean`
Additive — the script that checks every package download in the browser — together with the tools
to check a downloaded release yourself.

## Contents

| Path                 | Meaning                                                                                         |
|----------------------|-------------------------------------------------------------------------------------------------|
| `integrity/v<N>.js`  | The published source of every version of `static/js/integrity.js`.                              |
| `generate.py`        | Computes the SHA-256 of every version and writes `manifest.json` (and `integrity/hashes/`).     |
| `manifest.json`      | The public reference (format 2): per artifact the versions (`version`, `file`, `sha256`, `size`) and `latest`. |
| `digest.py`          | Computes the `wf-content-v1` digest of a release archive or a checked out directory, and the peering artifact id of a release. |
| `.gitattributes`     | Pins `integrity/*.js` to LF, so a checkout on any platform hashes to the same value.            |

`generate.py` hashes the content as stored in git: CRLF line endings count as LF. The output is
deterministic and carries no timestamps; running it twice produces identical files. `integrity/hashes/`
is a local by-product and not committed, `manifest.json` is.

```bash
python generate.py
```

The `ocean` Additive keeps a clone of this repository, runs `generate.py` exactly once per integrity
run as a subprocess of its own interpreter, recomputes every hash itself and only reports versions
whose hashes it could reproduce. With the `peering` Additive, the record `ocean_integrity` is published
to the host's peers, which fetch `manifest.json` from this repository directly and compare it with the
script the host actually serves.

## What the download check does

Every download from the Ocean opens a dialog that shows four steps:

1. **Integrity script** — `integrity.js` hashes its own source and compares it with the host's record
   and with what the peers observed when they fetched it themselves.
2. **Peers** — the peers the host lists are asked directly; only peers whose signed identity and
   signed statement about this host verify are counted.
3. **Download** — the archive is compared with the host's checksum (a transport check, nothing more).
4. **Content** — the browser computes the `wf-content-v1` digest of the archive and compares it with
   the release record the peers replicated from the host's signed ledger. The record of the longest
   chain counts; peers on that chain must agree.

A mismatch is reported as critical and the archive is only saved after an explicit confirmation.
Missing peers or records make the result *unclear* — never a confirmation.

The check needs WebCrypto and therefore a secure context (HTTPS, or `localhost` in development). On a
page without one, `integrity.js` checks nothing, says so and offers to save the archive unchecked.
For tests with a phone in the LAN, a host in debug mode may be opened on a loopback address while its
peers watch its LAN address: `integrity.js` then takes the address from `/peering/api/v1/status` as the
host's own, but only when that status reports `debug` and the page runs on a loopback host. The alias
is named in the details and keeps the result at *unclear* at best.

## Release digests (`wf-content-v1`)

When a release is published, the Ocean records its content digest in the host's signed ledger
(`peering_artifact`); every later change of the stored archive — a new license file, for instance —
adds a link to the same chain, and a deleted package is recorded as withdrawn.

- **Digest:** SHA-256 over all regular files of the archive, sorted by the UTF-8 bytes of their path,
  each contributing `path ‖ 0x00 ‖ SHA-256(content)`.
- **Excluded:** exactly `EULA.md`, `OMLA.md` and `license.json` at the root. The Ocean writes these
  into licensed downloads for one buyer; they are never part of a release and the Ocean refuses
  releases that contain them. `integrity.js` only ever leaves out these three names, whatever the host
  asks for.
- **Artifact id:** `ocean_release:` + the first 32 hex characters of SHA-256 of
  `<ptype>\n<package>\n<version>` (`ptype` is `additives` or `extensions`).
- **Git releases** additionally record the commit they were built from.

## Manual check

The dialog runs inside the page the host delivered — a compromised host could manipulate it. To check
a downloaded release yourself, from tools the host does not control:

1. Compute the digest and the artifact id:

   ```bash
   python digest.py my-package-1.0.0.tar --artifact additives my-package 1.0.0
   ```

2. Ask the host for its peers and each peer for its record of that artifact:

   ```bash
   curl -s https://<host>/peering/api/v1/peers
   curl -s "https://<peer>/api/v1/hash?id=<artifact id>"
   ```

   Compare `hash` with your digest; `chain_length` tells you how often the stored archive changed.
   Verify a peer's identity with `GET /api/v1/node` (signed `wf-peering-node-v1` statement).

3. For a release published from git you can reproduce the digest from the source: clone the commit
   recorded in the release (`record.extra.commit`) **without line-ending conversion**
   (`git -c core.autocrlf=false clone …`), add the `LICENSE` the Ocean stores for the package if the
   repository has none, and run `python digest.py <directory>`. Releases uploaded with `wf ocean
   publish` are built from the maintainer's working tree and can only be compared archive to archive.

A matching digest proves that the release you received is the one the host recorded publicly and the
peers replicated — nothing more. It does not prove that the release is free of bugs or malicious code.

## License

The code of this repository is a public integrity promise that belongs to the WebFluid "ocean"
Additive. The code is licensed as [ARR (All rights reserved)](LICENSE).
