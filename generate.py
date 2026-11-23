from pathlib import Path
import base64, hashlib, json, re

ROOT = Path(__file__).resolve().parent
MANIFEST = ROOT / "manifest.json"
ARTIFACTS = {
    "ocean_integrity": "integrity"
}
CHUNK_SIZE = 1024 * 1024
VERSION = re.compile(r"^v(\d+)$")
NORMALIZATION = "Hashes cover the content as stored in git: CRLF line endings count as LF."
SERVED = ("http covers the exact bytes a host serves and a browser checks with Subresource Integrity: text "
          "artifacts are served with LF line endings, binary artifacts byte for byte. A client compares bytes it "
          "fetched over HTTP only with http, never with the normalized sha256.")


def _http(data: bytes) -> dict:
    sha384 = hashlib.sha384(data).digest()
    return {
        "sha256": hashlib.sha256(data).hexdigest(),
        "sha384": sha384.hex(),
        "sri": "sha384-" + base64.b64encode(sha384).decode("ascii"),
        "size": len(data)
    }


def _sha256_file(path: Path) -> tuple[str, int]:
    hasher = hashlib.sha256()
    size = 0
    pending = b""

    with open(path, "rb") as f:
        while chunk := f.read(CHUNK_SIZE):
            data = pending + chunk
            pending = b"\r" if data.endswith(b"\r") else b""
            data = (data[:-1] if pending else data).replace(b"\r\n", b"\n")
            hasher.update(data)
            size += len(data)

    hasher.update(pending)
    return hasher.hexdigest(), size + len(pending)


def _versions(directory: Path) -> list[Path]:
    files = [file for file in directory.glob("*.js") if VERSION.match(file.stem)]
    return sorted(files, key=lambda file: int(VERSION.match(file.stem).group(1)))


def _artifact(directory: Path) -> dict:
    hashes = directory / "hashes"
    hashes.mkdir(exist_ok=True)

    versions = []
    for file in _versions(directory):
        digest, size = _sha256_file(file)
        with open(hashes / f"{file.stem}.sha256", "w", encoding="ascii", newline="\n") as f:
            f.write(digest)
        versions.append({
            "version": file.stem,
            "file": file.relative_to(ROOT).as_posix(),
            "sha256": digest,
            "size": size,
            "http": _http(file.read_bytes().replace(b"\r\n", b"\n"))
        })

    return {
        "path": directory.relative_to(ROOT).as_posix(),
        "latest": versions[-1]["version"] if versions else None,
        "versions": versions
    }


def main():
    manifest = {
        "format": 2,
        "algorithm": "sha256",
        "normalization": NORMALIZATION,
        "http": SERVED,
        "artifacts": {
            artifact: _artifact(ROOT / directory)
            for artifact, directory in ARTIFACTS.items()
        }
    }
    with open(MANIFEST, "w", encoding="utf-8", newline="\n") as f:
        f.write(json.dumps(manifest, indent=2, sort_keys=True) + "\n")


if __name__ == "__main__": main()
