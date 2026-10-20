# Static integrity.js integrity

This repository contains the version history of `static/js/integrity.js` of the WebFluid `ocean`
Additive — the script that checks every package download in the browser — together with the tools
to check a downloaded release yourself.

## Contents

| Path                | Meaning                                                                                                                        |
|---------------------|--------------------------------------------------------------------------------------------------------------------------------|
| `integrity/v<N>.js` | The published source of every version of `static/js/integrity.js`.                                                             |
| `generate.py`       | Computes the SHA-256 of every version and writes `manifest.json` (and `integrity/hashes/`).                                    |
| `manifest.json`     | The public reference (format 2): per artifact the versions (`version`, `file`, `sha256`, `size`) and `latest`.                 |
| `digest.py`         | Computes the `wf-content-v1` digest of a release archive or a checked out directory, and the peering artifact id of a release. |
| `.gitattributes`    | Pins `integrity/*.js` to LF, so a checkout on any platform hashes to the same value.                                           |

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
   and with what the peers observed when they fetched it themselves. The
   [trust check](#trust-check-of-integrityjs) repeats this step from a page the host does not control.
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

## Trust check of integrity.js

The dialog runs inside the page the host delivered — a compromised host could manipulate it, starting
with `integrity.js` itself. The snippet below repeats the first step of the dialog from a page the host
does not control: it loads `integrity.js` from the host itself, hashes it in your browser and compares
the result with the published `manifest.json` of this repository, with the hash the host claims and
with the hashes the host's peers observed.

**Get the snippet from here, not from the Ocean.** Read it on GitHub
(`https://github.com/growvolutionary/WF_ocean__Integrity`), compare it with the version in the
repository history, and only run code you have read. It is short on purpose.

1. Open a new, empty tab (`about:blank`). Do not run it on the Ocean's own page: that page's scripts
   could have replaced `fetch` or `crypto`.
2. Open the developer tools with `CTRL + SHIFT + I` (`CMD + OPTION + I` on macOS) and switch to
   **Console**.
3. Edit `HOST` (and, if you know peers from an independent source, `EXTRA_PEERS`), paste the block and
   press Enter. Some browsers ask you to type `allow pasting` first.

```js
(async () => {
    const HOST = "https://example.org"
    const EXTRA_PEERS = []
    const OCEAN = "/hub"
    const ARTIFACT = "ocean_integrity"
    const SCRIPT = "/static/js/integrity.js"
    const MANIFEST = "https://raw.githubusercontent.com/growvolutionary/WF_ocean__Integrity/main/manifest.json"

    const ORIGIN = new URL(HOST).origin
    const HOST_API = "/peering/api/v1"
    const PEER_API = "/api/v1"
    const load = url => fetch(url, { credentials: "omit", cache: "no-store", redirect: "error" })
        .then(response => response.ok ? response : Promise.reject(new Error(`HTTP ${response.status}`)))
    const json = url => load(url).then(response => response.json())
    const api = (origin, base, path) => json(`${origin}${base}${path}`)
    const hex = buffer => Array.from(new Uint8Array(buffer), byte => byte.toString(16).padStart(2, "0")).join("")
    const sha256 = url => load(url).then(response => response.arrayBuffer())
        .then(bytes => crypto.subtle.digest("SHA-256", bytes)).then(digest => ({ hash: hex(digest) }))
    const b64 = text => Uint8Array.from(atob(text.replace(/-/g, "+").replace(/_/g, "/")
        + "=".repeat((4 - text.length % 4) % 4)), char => char.charCodeAt(0))
    const canonical = value => value === null ? "null"
        : Array.isArray(value) ? `[${value.map(canonical).join(",")}]`
        : typeof value === "object" ? `{${Object.keys(value).sort()
            .map(key => `${JSON.stringify(key)}:${canonical(value[key])}`).join(",")}}`
        : JSON.stringify(value)
    const verify = async (key, context, payload, signature) => {
        const publicKey = await crypto.subtle.importKey("raw", b64(key), { name: "Ed25519" }, false, ["verify"])
        const message = new TextEncoder().encode(`${context}\n${canonical(payload)}`)
        return crypto.subtle.verify({ name: "Ed25519" }, publicKey, b64(signature), message)
    }
    const safe = promise => promise.then(value => value, error => ({ error: error.message }))

    const [manifest, claim, record, listed, served] = await Promise.all([
        safe(json(MANIFEST)), safe(json(`${ORIGIN}${OCEAN}/api/v1/integrity`)),
        safe(api(ORIGIN, HOST_API, `/hash?id=${ARTIFACT}`)), safe(api(ORIGIN, HOST_API, "/peers")),
        safe(sha256(`${ORIGIN}${OCEAN}${SCRIPT}`))
    ])
    const hash = served.hash
    const entry = (manifest.artifacts || {})[ARTIFACT] || {}
    const version = (entry.versions || []).find(item => item.sha256 === hash)?.version ?? null
    const latest = entry.latest ?? null

    const peers = [...new Set([...(listed.peers || []).map(peer => peer.url), ...EXTRA_PEERS])]
        .filter(url => /^https:\/\//.test(url || ""))
    const rows = await Promise.all(peers.map(async url => {
        const [node, trust, checkpoint, replica] = await Promise.all([
            safe(api(url, PEER_API, "/node")), safe(api(url, PEER_API, "/trust")),
            safe(api(url, PEER_API, "/checkpoints/latest")), safe(api(url, PEER_API, `/hash?id=${ARTIFACT}`))
        ])
        const statement = node.statement || {}
        const identity = !node.error && statement.url === url
            && await verify(statement.key, "wf-peering-node-v1", statement, node.signature || "").catch(() => false)
        const signed = identity && !trust.error && trust.key === statement.key
            && await verify(trust.key, "wf-trust-v1", { node: trust.node, key: trust.key, report: trust.report }, trust.signature)
                .catch(() => false)
        const assessment = signed && trust.report.host?.target === ORIGIN ? trust.report.host : {}
        return {
            peer: url,
            reachable: !node.error,
            signed_identity: identity,
            peers_this_host: statement.host === ORIGIN,
            score: assessment.score ?? null,
            level: assessment.level ?? null,
            basis: assessment.basis ?? null,
            replicated: replica.hash ?? null,
            observed: replica.observation?.observed ?? null,
            status: replica.observation?.status ?? null,
            checkpoint: checkpoint.error ? null : `${checkpoint.day} ${checkpoint.status}`,
            ledger_size: checkpoint.content?.ledger?.size ?? null,
            ledger_root: checkpoint.content?.ledger?.root ?? null
        }
    }))
    const confirmed = rows.filter(row => row.signed_identity && row.peers_this_host)
    const observations = confirmed.filter(row => row.observed)

    console.table({ [ARTIFACT]: {
        served_to_you: hash ?? served.error,
        published_version: version, latest_version: latest,
        host_claims: claim.hash ?? null, host_record: record.hash ?? null,
        peers_agree: `${observations.filter(row => row.observed === hash).length}/${observations.length}`
    } })
    if (rows.length) console.table(rows)

    const findings = []
    if (manifest.error) findings.push(`The published manifest could not be loaded (${manifest.error}): integrity.js is UNCLEAR.`)
    if (claim.error) findings.push(`The host does not answer its integrity claim (${claim.error}).`)
    if (!hash) {
        findings.push(`integrity.js could not be loaded from the host (${served.error}). Hosts before the `
            + "cross-origin release of the ocean Additive block this read: compare `sha256sum integrity.js` "
            + "with manifest.json instead.")
    } else {
        if (!manifest.error && !version) findings.push("integrity.js: the bytes you received match no published version.")
        if (version && latest && version !== latest) findings.push(`integrity.js: the host serves ${version}, the latest is ${latest}.`)
        for (const [source, value] of [["claims", claim.hash], ["records in its ledger", record.hash]]) {
            if (value && value !== hash) findings.push(`The host ${source} ${value}, but served you ${hash}.`)
        }
        if (claim.url && claim.url !== `${OCEAN}${SCRIPT}`) {
            findings.push(`The host claims the script at ${claim.url}; this check read ${OCEAN}${SCRIPT}.`)
        }
        for (const row of confirmed) {
            if (row.observed && row.observed !== hash) findings.push(`${row.peer} observed a different integrity.js than the host served you.`)
            if (row.replicated && row.replicated !== hash) findings.push(`${row.peer} replicated a host record that differs from what you received.`)
            if (["served-mismatch", "reference-mismatch", "outdated"].includes(row.status)) {
                findings.push(`${row.peer} reports for integrity.js: ${row.status}.`)
            }
        }
    }
    for (const row of confirmed) {
        if (row.level === "critical" || row.level === "warning") findings.push(`${row.peer} rates the host: ${row.level}.`)
    }
    const roots = {}
    for (const row of confirmed.filter(row => row.ledger_root)) (roots[row.ledger_size] ??= new Set()).add(row.ledger_root)
    for (const [size, set] of Object.entries(roots)) {
        if (set.size > 1) findings.push(`Peers disagree about the ledger of size ${size}: possible split view.`)
    }
    if (listed.error && !EXTRA_PEERS.length) {
        console.log("The host lists no peers: only your own hash, the host's claim and the published manifest were compared.")
    } else if (!confirmed.length) {
        findings.push("No peer of this host could be verified: the peer side of the result is UNCLEAR, not good.")
    }

    console.log(findings.length ? findings.join("\n") : "No deviation found: the integrity.js you received is a "
        + "published version and agrees with the host's claim and with every verified peer.")
    console.log("Limits: the host can tell this request from your Ocean tab and could serve it different bytes; "
        + "the host chose which peers to list; peers may share an operator; a browser cannot inspect TLS "
        + "certificates or DNS; matching values prove agreement, not correctness.")
})()
```

What the snippet does — and what it does not:

- It only sends `GET` requests without credentials: for `integrity.js` and the host's integrity claim
  (`/hub/api/v1/integrity`) to the host, for `manifest.json` to GitHub, to the host's public peering API
  under `/peering/api/v1` and to every peer's under `/api/v1` (the peering app). It reads no cookies,
  passwords, session data or storage, uses no `eval` and loads no further code — `integrity.js` is
  hashed as bytes, never executed.
- It hashes `integrity.js` exactly as the host served it to your browser and looks the hash up in
  `manifest.json`, read straight from this repository: a hash that matches no version is a *reference
  mismatch*, an older version than `latest` is *outdated*.
- It compares your hash with the hash the host claims, with the record `ocean_integrity` in the host's
  ledger and with what each peer replicated and observed, checks the Ed25519 signatures of every peer's
  identity and trust report, and compares the peers' latest checkpoint roots. Without peering, the
  comparison with the manifest still stands on its own.
- The host answers these reads with `Access-Control-Allow-Origin: *` for exactly `integrity.js` and its
  integrity claim. Older versions of the `ocean` Additive do not; the snippet then says so, and the
  fallback is to download the file and compare `sha256sum integrity.js` with `manifest.json`.
- The browser verifies TLS for every `https` request, but a script cannot inspect certificates, DNS
  records or the operator behind a peer. Peers check those themselves; their results appear as their
  signed claims.
- The host can distinguish this request (no cookie, empty origin) from the one your Ocean tab makes and
  could answer it with other bytes. Peers face the same limit. The dialog inside the Ocean hashes the
  copy the page actually loaded; the two complement each other.
- The list of peers comes from the host. A compromised host can leave peers out. Add peers you know
  from an independent source to `EXTRA_PEERS`.
- Peers that do not answer or block cross-origin requests are listed as unreachable. Missing answers
  make the result unclear — they are neither a confirmation nor proof of manipulation.

A clean result means that the `integrity.js` you received is a published version and that the host's
claims and the peers you reached agree with it. It is not a guarantee that the host is uncompromised,
and it says nothing about a release yet — for that, check the release itself.

## Manual check of a release

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
