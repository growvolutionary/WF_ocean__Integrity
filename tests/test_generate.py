from pathlib import Path
import base64, hashlib, json, pytest, re, shutil, subprocess, sys

ROOT = Path(__file__).resolve().parents[1]
ADDITIVE = ROOT.parent
SERVED = {'ocean_integrity': 'static/js/integrity.js'}
KNOWN_DRIFT = {}


def manifest(root: Path = ROOT) -> dict:
    return json.loads((root / "manifest.json").read_text(encoding="utf-8"))


def generate(root: Path) -> bytes:
    subprocess.run([sys.executable, "-I", str(root / "generate.py")], check=True, cwd=root, capture_output=True)
    return (root / "manifest.json").read_bytes()


def copy(tmp_path: Path) -> Path:
    target = tmp_path / "repo"
    shutil.copytree(ROOT, target, ignore=shutil.ignore_patterns(".git", "__pycache__", "hashes", "tests"))
    return target


def latest(data: dict, artifact: str) -> dict:
    entry = data["artifacts"][artifact]
    return next(item for item in entry["versions"] if item["version"] == entry["latest"])


def test_generator_reproduces_the_committed_manifest(tmp_path):
    target = copy(tmp_path)
    committed = (ROOT / "manifest.json").read_bytes().replace(b"\r\n", b"\n")
    assert generate(target) == committed
    assert generate(target) == committed


def test_every_version_separates_content_http_and_sri(tmp_path):
    data = manifest()
    assert data["format"] == 2 and data["normalization"] and data["http"]
    for artifact, entry in data["artifacts"].items():
        for item in entry["versions"]:
            raw = (ROOT / item["file"]).read_bytes()
            binary = item["file"].endswith(".wasm")
            served = raw if binary else raw.replace(b"\r\n", b"\n")
            assert item["http"]["sha256"] == hashlib.sha256(served).hexdigest(), artifact
            digest = hashlib.sha384(served).digest()
            assert item["http"]["sri"] == "sha384-" + base64.b64encode(digest).decode("ascii")
            assert item["http"]["size"] == len(served)


def test_a_crlf_copy_keeps_the_content_digest_but_fails_the_byte_digest(tmp_path):
    target = copy(tmp_path)
    data = manifest(target)
    artifact, item = next((name, latest(data, name)) for name in data["artifacts"]
                          if not latest(data, name)["file"].endswith(".wasm"))
    path = target / item["file"]
    lf = path.read_bytes().replace(b"\r\n", b"\n")
    path.write_bytes(lf.replace(b"\n", b"\r\n"))
    regenerated = json.loads(generate(target).decode("utf-8"))
    fresh = latest(regenerated, artifact)
    assert fresh["sha256"] == item["sha256"]
    assert hashlib.sha256(path.read_bytes()).hexdigest() != fresh["http"]["sha256"]


def test_one_changed_byte_changes_every_digest(tmp_path):
    target = copy(tmp_path)
    data = manifest(target)
    artifact = next(iter(data["artifacts"]))
    item = latest(data, artifact)
    path = target / item["file"]
    raw = bytearray(path.read_bytes())
    raw[len(raw) // 2] ^= 0x01
    path.write_bytes(bytes(raw))
    fresh = latest(json.loads(generate(target).decode("utf-8")), artifact)
    assert fresh["sha256"] != item["sha256"] and fresh["http"]["sha256"] != item["http"]["sha256"]
    assert fresh["http"]["sri"] != item["http"]["sri"]


@pytest.mark.parametrize("artifact", sorted(SERVED))
def test_the_additive_serves_the_latest_reference(artifact):
    served = ADDITIVE / SERVED[artifact]
    if not served.is_file(): pytest.skip(f"{SERVED[artifact]} is not next to this repository")
    expected = latest(manifest(), artifact)["http"]["sha256"]
    actual = hashlib.sha256(served.read_bytes()).hexdigest()
    if artifact in KNOWN_DRIFT:
        assert actual != expected, f"{artifact} matches again; remove it from KNOWN_DRIFT"
        pytest.xfail(KNOWN_DRIFT[artifact])
    assert actual == expected


def run_sync(target: Path, additive: Path) -> subprocess.CompletedProcess:
    return subprocess.run([sys.executable, "-I", str(target / "sync.py"), "--additive", str(additive)], cwd=target,
                          capture_output=True, text=True)


def test_sync_writes_the_open_version_and_never_a_frozen_one(tmp_path):
    target = copy(tmp_path)
    artifact, source = next(iter(SERVED.items()))
    before = manifest(target)["artifacts"][artifact]
    kept = {item["file"]: (target / item["file"]).read_bytes() for item in before["versions"][:-1]}
    served = tmp_path / "additive" / source
    served.parent.mkdir(parents=True)
    served.write_bytes(b"changed\r\n")
    assert run_sync(target, tmp_path / "additive").returncode == 0
    item = latest(manifest(target), artifact)
    assert item["version"] == before["latest"] and (target / item["file"]).read_bytes() == b"changed\n"
    assert all((target / file).read_bytes() == data for file, data in kept.items())
    script = (target / "sync.py").read_text(encoding="utf-8")
    frozen = re.sub(r"^FROZEN = .*$", f'FROZEN = {{"{artifact}": {{"{before["latest"]}"}}}}', script, flags=re.M)
    (target / "sync.py").write_bytes(frozen.encode("utf-8"))
    served.write_bytes(b"again\n")
    assert run_sync(target, tmp_path / "additive").returncode == 0
    fresh = latest(manifest(target), artifact)
    assert fresh["version"] == f"v{int(before['latest'][1:]) + 1}"
    assert (target / fresh["file"]).read_bytes() == b"again\n"
    assert (target / item["file"]).read_bytes() == b"changed\n"
