/********************************************************************
 *                                                                  *
 *    Copyright © 2026 GrowVolution Media, Inh. Pierre Schkoldow    *
 *                                                                  *
 *       This script verifies every download of the WebFluid        *
 *     "ocean" Additive in your browser: it checks itself, asks     *
 *      the peers of the host and compares the content of the       *
 *      release with their records before it is saved. To keep      *
 *     your application transparent and secure, you should not      *
 *     edit or change its content by yourself. Additionally we      *
 *      highly recommend to add the "peering" Additive to your      *
 *       application and to not remove the "ocean" Additive's       *
 *                        peering features.                         *
 *                                                                  *
 ********************************************************************/

const SOURCE = import.meta.url
const PREFIX = new URL(SOURCE).pathname.replace(/\/static\/js\/integrity\.js$/, "")

const ARTIFACT = "ocean_integrity"
const RELEASE = "ocean_release:"
const CONTENT = "wf-content-v1"
const RESERVED = ["EULA.md", "OMLA.md", "license.json"]
const HOST_API = "/peering/api/v1"
const PEER_API = "/api/v1"
const TIMEOUT = 8000
const MAX_PEERS = 8
const BLOCK = 512
const REGULAR = ["0", "\0", "7"]
const LEVELS = { verified: 0, unclear: 1, warning: 2, critical: 3 }
const SYMBOLS = { verified: "✓", unclear: "?", warning: "!", critical: "✕", running: "…" }
const COLORS = { verified: "hsl(120, 55%, 40%)", unclear: "rgb(120 130 150)", warning: "hsl(40, 85%, 45%)",
                 critical: "hsl(0, 70%, 50%)", running: "rgb(120 130 150)" }

const encoder = new TextEncoder()
const decoder = new TextDecoder("utf-8")

let scriptHash = null


function hex(buffer) {
    return Array.from(new Uint8Array(buffer), byte => byte.toString(16).padStart(2, "0")).join("")
}

async function sha256(bytes) {
    return new Uint8Array(await crypto.subtle.digest("SHA-256", bytes))
}

function b64(text) {
    const binary = atob(text.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat((4 - text.length % 4) % 4))
    return Uint8Array.from(binary, char => char.charCodeAt(0))
}

function concat(parts) {
    const out = new Uint8Array(parts.reduce((size, part) => size + part.length, 0))
    let offset = 0
    for (const part of parts) {
        out.set(part, offset)
        offset += part.length
    }
    return out
}

function compare(a, b) {
    const length = Math.min(a.length, b.length)
    for (let i = 0; i < length; i++) if (a[i] !== b[i]) return a[i] - b[i]
    return a.length - b.length
}

function worst(levels) {
    return levels.reduce((current, level) => LEVELS[level] > LEVELS[current] ? level : current, "verified")
}


export function canonical(value) {
    if (value === null) return "null"
    if (value === true) return "true"
    if (value === false) return "false"
    if (typeof value === "number") {
        if (!Number.isSafeInteger(value)) throw new TypeError("Only safe integers are canonical.")
        return String(value)
    }
    if (typeof value === "string") {
        if (/[\ud800-\udfff]/.test(value.replace(/[\ud800-\udbff][\udc00-\udfff]/g, ""))) {
            throw new TypeError("Lone surrogates are not canonical.")
        }
        return JSON.stringify(value)
    }
    if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`
    if (typeof value === "object") {
        const keys = Object.keys(value).filter(key => value[key] !== undefined).sort()
        for (const key of keys) {
            if (!/^[\x20-\x7e]+$/.test(key)) throw new TypeError("Object keys must be printable ASCII.")
        }
        return `{${keys.map(key => `${JSON.stringify(key)}:${canonical(value[key])}`).join(",")}}`
    }
    throw new TypeError("Value cannot be canonicalized.")
}

async function json(url, sameOrigin = false) {
    const controller = new AbortController()
    const timer = setTimeout(() => controller.abort(), TIMEOUT)
    try {
        const response = await fetch(url, {
            credentials: sameOrigin ? "same-origin" : "omit", cache: "no-store", signal: controller.signal, redirect: "error"
        })
        if (!response.ok) return { __error: `HTTP_${response.status}` }
        return await response.json()
    } catch {
        return { __error: controller.signal.aborted ? "TIMEOUT" : "UNREACHABLE" }
    } finally {
        clearTimeout(timer)
    }
}

async function verified(key, context, payload, signature) {
    try {
        const publicKey = await crypto.subtle.importKey("raw", b64(key), { name: "Ed25519" }, false, ["verify"])
        const message = encoder.encode(`${context}\n${canonical(payload)}`)
        return await crypto.subtle.verify({ name: "Ed25519" }, publicKey, b64(signature), message)
    } catch {
        return false
    }
}

async function fingerprint(key) {
    const digest = (await sha256(b64(key))).slice(0, 16)
    let binary = ""
    for (const byte of digest) binary += String.fromCharCode(byte)
    return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "")
}

function origin(url) {
    try {
        const parsed = new URL(url)
        if (parsed.protocol !== "https:" && !(parsed.protocol === "http:" && location.protocol === "http:")) return null
        return parsed.origin
    } catch {
        return null
    }
}


export function hash() {
    scriptHash ??= fetch(SOURCE, { cache: "force-cache", credentials: "same-origin" })
        .then(response => {
            if (!response.ok) throw new Error(`Loading ${SOURCE} answered HTTP ${response.status}.`)
            return response.arrayBuffer()
        })
        .then(source => crypto.subtle.digest("SHA-256", source))
        .then(hex)
        .catch(error => {
            scriptHash = null
            throw error
        })
    return scriptHash
}

export async function peeringAvailable() {
    const health = await json("/peering/api/health", true)
    return !health.__error && health.status === "ok"
}

async function inspectPeer(url, host, artifacts) {
    const result = { url, reachable: false, identity: false, peersHost: false, independent: null, records: {} }
    const base = `${url}${PEER_API}`
    const [node, trust, ...records] = await Promise.all([
        json(`${base}/node`), json(`${base}/trust`),
        ...artifacts.map(artifact => json(`${base}/hash?id=${encodeURIComponent(artifact)}`))
    ])
    if (node.__error) return result
    result.reachable = true
    const statement = node.statement || {}
    result.identity = typeof statement.key === "string"
        && statement.node === await fingerprint(statement.key)
        && await verified(statement.key, "wf-peering-node-v1", statement, node.signature || "")
        && origin(statement.url || "") === url
    result.peersHost = statement.role === "peer" && origin(statement.host || "") === host
    if (!trust.__error && result.identity && trust.key === statement.key
        && await verified(trust.key, "wf-trust-v1", { node: trust.node, key: trust.key, report: trust.report }, trust.signature || "")) {
        const assessment = trust.report?.host || {}
        if (origin(assessment.target || "") === host) result.independent = assessment.independent_observers ?? null
    }
    artifacts.forEach((artifact, index) => { result.records[artifact] = records[index].__error ? null : records[index] })
    return result
}

export async function network(artifacts) {
    const host = location.origin
    if (!await peeringAvailable()) return { available: false, claims: {}, reported: 0, peers: [] }
    const [listing, ...claims] = await Promise.all([
        json(`${HOST_API}/peers`, true),
        ...artifacts.map(artifact => json(`${HOST_API}/hash?id=${encodeURIComponent(artifact)}`, true))
    ])
    const urls = [...new Set((listing.peers || []).map(peer => origin(peer.url || ""))
        .filter(url => url && url !== host))].slice(0, MAX_PEERS)
    const inspected = await Promise.all(urls.map(url => inspectPeer(url, host, artifacts)))
    const result = { available: true, claims: {}, reported: urls.length, peers: inspected.filter(peer => peer.identity && peer.peersHost) }
    artifacts.forEach((artifact, index) => { result.claims[artifact] = claims[index].__error ? null : claims[index] })
    return result
}


export async function checkScript(peering) {
    const local = await hash().catch(() => null)
    const result = { level: "unclear", local, host: null, served: null, latest: null, confirmed: 0, differs: [], message: "SCRIPT_UNCONFIRMED" }
    if (peering.available) {
        const claim = peering.claims[ARTIFACT]
        result.host = claim?.hash ?? null
        result.served = claim?.served_version ?? null
        result.latest = claim?.latest_version ?? null
        for (const peer of peering.peers) {
            const observation = peer.records[ARTIFACT]?.observation || {}
            if (observation.observed && local && observation.observed !== local) result.differs.push(peer.url)
            else if (["reference-mismatch", "served-mismatch"].includes(observation.status)) result.differs.push(peer.url)
            else if (observation.observed && observation.observed === local) result.confirmed++
        }
    } else {
        const status = await json(`${PREFIX}/api/v1/integrity`, true)
        if (!status.__error) {
            result.host = status.hash ?? null
            result.served = status.reference === "ok" ? status.served_version ?? null : null
            result.latest = status.latest_version ?? null
        }
    }

    if (local && result.host && local !== result.host) {
        result.level = "critical"
        result.message = "SCRIPT_DIFFERS"
    } else if (result.differs.length) {
        result.level = "critical"
        result.message = "SCRIPT_PEER_DIFFERS"
    } else if (local && result.host && result.served) {
        result.level = result.latest && result.latest !== result.served ? "warning" : "verified"
        result.message = "SCRIPT_OK"
    }
    return result
}


function field(header, offset, length) {
    const slice = header.subarray(offset, offset + length)
    const end = slice.indexOf(0)
    return end === -1 ? slice : slice.subarray(0, end)
}

function octal(header, offset, length) {
    const raw = header.subarray(offset, offset + length)
    if (raw[0] & 0x80) {
        let value = 0
        for (let i = 1; i < raw.length; i++) value = value * 256 + raw[i]
        return value
    }
    const text = decoder.decode(field(header, offset, length)).trim()
    if (!/^[0-7]*$/.test(text)) throw new Error("INVALID_ARCHIVE")
    return text ? parseInt(text, 8) : 0
}

function checksums(header) {
    let unsigned = 0, signed = 0
    for (let i = 0; i < BLOCK; i++) {
        const byte = i >= 148 && i < 156 ? 32 : header[i]
        unsigned += byte
        signed += byte > 127 ? byte - 256 : byte
    }
    return [unsigned, signed]
}

function pax(data) {
    const records = {}
    let offset = 0
    while (offset < data.length) {
        const space = data.indexOf(32, offset)
        if (space === -1) break
        const length = parseInt(decoder.decode(data.subarray(offset, space)), 10)
        if (!Number.isFinite(length) || length <= 0) throw new Error("INVALID_ARCHIVE")
        const record = data.subarray(space + 1, offset + length - 1)
        const equals = record.indexOf(61)
        if (equals !== -1) records[decoder.decode(record.subarray(0, equals))] = record.subarray(equals + 1)
        offset += length
    }
    return records
}

export function entries(buffer) {
    const bytes = new Uint8Array(buffer)
    const files = []
    let offset = 0, longName = null, local = {}, global = {}
    while (offset + BLOCK <= bytes.length) {
        const header = bytes.subarray(offset, offset + BLOCK)
        if (header.every(byte => byte === 0)) break
        if (!checksums(header).includes(octal(header, 148, 8))) throw new Error("INVALID_ARCHIVE")
        const type = String.fromCharCode(header[156] || 0)
        let size = octal(header, 124, 12)
        const overrides = { ...global, ...local }
        if (overrides.size) size = parseInt(decoder.decode(overrides.size), 10)
        const start = offset + BLOCK
        const data = bytes.subarray(start, start + size)
        if (data.length !== size) throw new Error("INVALID_ARCHIVE")
        offset = start + Math.ceil(size / BLOCK) * BLOCK

        if (type === "L") { longName = field(data, 0, data.length); continue }
        if (type === "x") { local = pax(data); continue }
        if (type === "g") { global = { ...global, ...pax(data) }; continue }
        if (type === "S") throw new Error("UNSUPPORTED_ARCHIVE")

        let name = field(header, 0, 100)
        const prefix = field(header, 345, 155)
        if (prefix.length && !["L", "K", "S"].includes(type)) name = concat([prefix, Uint8Array.of(47), name])
        if (longName) name = longName
        if (overrides.path) name = overrides.path
        longName = null
        local = {}

        const text = decoder.decode(name)
        if (!REGULAR.includes(type) || (type === "\0" && text.endsWith("/"))) continue
        files.push({ name, text, data })
    }
    return files
}

export async function contentDigest(buffer, exclude) {
    const files = entries(buffer).filter(file => !exclude.includes(file.text))
    files.sort((a, b) => compare(a.name, b.name))
    const parts = []
    for (const file of files) parts.push(file.name, Uint8Array.of(0), await sha256(file.data))
    return { digest: hex(await sha256(concat(parts))), files: files.length }
}

export async function releaseArtifact(ptype, pkg, version) {
    return RELEASE + hex(await sha256(encoder.encode(`${ptype}\n${pkg}\n${version}`))).slice(0, 32)
}


export async function verifyRelease({ ptype, pkg, version, buffer, meta, peering }) {
    const checks = []
    const result = { transfer: "verified", content: "unclear", checks, confirmed: 0, chain: null }
    const add = (level, key, values) => checks.push({ level, key, values: values || {} })

    if (hex(await sha256(new Uint8Array(buffer))) !== meta.hash) {
        result.transfer = "critical"
        add("critical", "TRANSFER_FAILED")
    } else add("verified", "TRANSFER_OK")

    const requested = Array.isArray(meta.exclude) ? meta.exclude : []
    const refused = requested.filter(name => !RESERVED.includes(name))
    if (refused.length) add("critical", "EXCLUDE_REFUSED", { files: refused.join(", ") })
    const exclude = requested.filter(name => RESERVED.includes(name))

    let content
    try { content = await contentDigest(buffer, exclude) }
    catch {
        add("critical", "CONTENT_INVALID")
        result.content = "critical"
        return result
    }
    const artifact = await releaseArtifact(ptype, pkg, version)
    if (meta.artifact && meta.artifact !== artifact) add("critical", "ARTIFACT_MISMATCH")
    const claimed = meta.content?.algorithm === CONTENT ? meta.content.digest : null
    const recorded = peering.available ? peering.claims[artifact]?.hash ?? null : null
    if ((claimed && claimed !== content.digest) || (recorded && recorded !== content.digest)) {
        add("critical", "CONTENT_HOST_MISMATCH")
    }

    if (!peering.available) {
        if (claimed === content.digest) add("unclear", "CONTENT_HOST_ONLY")
        else if (!claimed) add("unclear", "CONTENT_UNRECORDED")
    } else {
        const records = peering.peers
            .map(peer => ({ peer, record: peer.records[artifact] }))
            .filter(item => item.record && item.record.hash)
        if (!records.length) add("unclear", recorded === content.digest ? "CONTENT_HOST_ONLY" : "CONTENT_UNRECORDED")
        else {
            const chain = Math.max(...records.map(item => item.record.chain_length || 0))
            const head = records.filter(item => (item.record.chain_length || 0) === chain)
            const hashes = new Set(head.map(item => item.record.hash))
            result.chain = chain
            const extra = head[0].record.record?.extra || {}
            if (extra.package !== undefined && (extra.package !== pkg || extra.version !== version || extra.ptype !== ptype)) {
                add("critical", "ARTIFACT_MISMATCH")
            }
            if (hashes.size > 1) add("critical", "CONTENT_PEERS_DISAGREE")
            else if (!hashes.has(content.digest)) add("critical", "CONTENT_PEERS_MISMATCH", { chain })
            else {
                const confirmers = head.filter(item => item.record.hash === content.digest)
                result.confirmed = confirmers.length
                const independent = confirmers.length >= 2 || (confirmers[0].peer.independent ?? 0) >= 2
                add(independent ? "verified" : "unclear", independent ? "CONTENT_PEERS_MATCH" : "PEER_SINGLE",
                    { count: confirmers.length, chain })
            }
            if (head.some(item => item.record.missing_since)) add("warning", "CONTENT_RETRACTED")
        }
    }
    if ((meta.uncovered || []).length) add("unclear", "CONTENT_UNCOVERED", { files: meta.uncovered.join(", ") })
    if ((meta.injected || []).length) add("verified", "CONTENT_INJECTED", { files: meta.injected.join(", ") })
    result.content = worst(checks.filter(check => check.key !== "TRANSFER_OK" && check.key !== "TRANSFER_FAILED").map(check => check.level))
    return result
}


function text(key, values) {
    const table = window.ocPublic?.i18n?.integrity || {}
    let out = table[key] ?? key
    for (const [name, value] of Object.entries(values || {})) out = out.replace(`%(${name})s`, String(value))
    return out
}

function element(tag, style, content) {
    const node = document.createElement(tag)
    if (style) node.setAttribute("style", style)
    if (content !== undefined) node.textContent = content
    return node
}

function modal() {
    const root = document.getElementById("ocIntegrity")
    const steps = document.getElementById("ocIntegritySteps")
    const result = document.getElementById("ocIntegrityResult")
    const details = document.getElementById("ocIntegrityDetails")
    const save = document.getElementById("ocIntegritySave")
    const close = document.getElementById("ocIntegrityClose")
    if (!root || !steps || !result || !details || !save || !close) return null

    const rows = {}
    steps.replaceChildren()
    details.replaceChildren()
    result.textContent = ""
    save.hidden = true
    for (const key of ["script", "peers", "transfer", "content"]) {
        const symbol = element("span", "display:inline-block;width:1.25rem;font-weight:700;flex-shrink:0")
        const label = element("strong", "flex-shrink:0", text(`STEP_${key.toUpperCase()}`))
        const message = element("span", "opacity:.85")
        const row = element("li", "display:flex;gap:.5rem;align-items:baseline;flex-wrap:wrap")
        row.append(symbol, label, message)
        steps.append(row)
        rows[key] = { symbol, message }
    }

    const ui = {
        set(key, level, message) {
            rows[key].symbol.textContent = SYMBOLS[level]
            rows[key].symbol.style.color = COLORS[level]
            rows[key].message.textContent = message
        },
        detail(line) {
            details.append(element("li", "word-break:break-all", line))
        },
        finish(level, message) {
            result.textContent = message
            result.style.color = COLORS[level]
        },
        decide(allowSave) {
            save.hidden = !allowSave
            return new Promise(resolve => {
                const done = value => {
                    save.removeEventListener("click", onSave)
                    close.removeEventListener("click", onClose)
                    resolve(value)
                }
                const onSave = () => done(true)
                const onClose = () => done(false)
                save.addEventListener("click", onSave)
                close.addEventListener("click", onClose)
            })
        },
        hide() {
            root.hidden = true
        }
    }
    for (const key of Object.keys(rows)) ui.set(key, "running", text("RUNNING"))
    root.hidden = false
    return ui
}

function store(buffer, filename) {
    const url = URL.createObjectURL(new Blob([buffer], { type: "application/x-tar" }))
    const link = document.createElement("a")
    link.href = url
    link.download = filename
    document.body.appendChild(link)
    link.click()
    link.remove()
    setTimeout(() => URL.revokeObjectURL(url), 1000)
}

export async function download(options) {
    const ui = modal()
    if (!ui) return { saved: false, level: "critical" }
    try {
        return await run(ui, options)
    } catch {
        ui.finish("critical", text("RESULT_FAILED"))
        await ui.decide(false)
        ui.hide()
        return { saved: false, level: "critical" }
    }
}

async function run(ui, { ptype, pkg, version, base, filename }) {
    const artifact = await releaseArtifact(ptype, pkg, version)
    const peering = await network([ARTIFACT, artifact])
    const script = await checkScript(peering)
    ui.set("script", script.level, text(script.message, { version: script.served ?? "?", count: script.confirmed }))
    ui.detail(`integrity.js · ${script.local ?? "?"} / ${script.host ?? "?"}`)
    if (script.confirmed) ui.detail(text("SCRIPT_PEERS_CONFIRM", { count: script.confirmed }))

    if (peering.available) {
        ui.set("peers", peering.peers.length ? "verified" : "unclear", peering.peers.length
            ? text("PEERS_CONFIRMED", { verified: peering.peers.length, reported: peering.reported })
            : text("PEERS_NONE"))
        for (const peer of peering.peers) ui.detail(`${peer.url} · ${peer.records[artifact]?.hash ?? "–"} · ${peer.records[artifact]?.chain_length ?? "–"}`)
    } else ui.set("peers", "unclear", text("PEERING_OFF"))

    let buffer, meta
    try {
        const response = await fetch(base, { credentials: "include" })
        if (!response.ok) throw new Error("download")
        buffer = await response.arrayBuffer()
        meta = await fetch(`${base}/integrity`, { credentials: "include" }).then(r => r.ok ? r.json() : null)
        if (!meta?.hash) throw new Error("integrity")
    } catch {
        ui.set("transfer", "critical", text("DOWNLOAD_FAILED"))
        ui.set("content", "unclear", "–")
        ui.finish("critical", text("RESULT_FAILED"))
        await ui.decide(false)
        ui.hide()
        return { saved: false, level: "critical" }
    }

    const release = await verifyRelease({ ptype, pkg, version, buffer, meta, peering })
    const transfer = release.checks.find(check => check.key.startsWith("TRANSFER_"))
    ui.set("transfer", release.transfer, text(transfer.key))
    const contentChecks = release.checks.filter(check => !check.key.startsWith("TRANSFER_"))
    const headline = contentChecks.find(check => check.level === release.content) || contentChecks[0]
    ui.set("content", release.content, headline ? text(headline.key, headline.values) : "–")
    for (const check of contentChecks) if (check !== headline) ui.detail(text(check.key, check.values))
    ui.detail(`${artifact} · ${meta.content?.digest ?? "?"}`)

    const level = worst([script.level, release.transfer, release.content])
    if (level === "critical") {
        ui.finish("critical", text("RESULT_CRITICAL"))
        const override = await ui.decide(true)
        if (override) store(buffer, filename)
        ui.hide()
        return { saved: override, level }
    }

    store(buffer, filename)
    ui.finish(level, text(`RESULT_${level.toUpperCase()}`))
    await ui.decide(false)
    ui.hide()
    return { saved: true, level }
}


window.wf ??= {}
window.wf.adt ??= {}
window.wf.adt.ocean = {
    ...window.wf.adt.ocean,
    integrity: { hash, canonical, peeringAvailable, network, checkScript, entries, contentDigest, releaseArtifact, verifyRelease, download }
}
window.dispatchEvent(new Event("ocean:integrity"))
