from pathlib import Path
import argparse, hashlib, tarfile

RESERVED = ("EULA.md", "OMLA.md", "license.json")
PREFIX = "ocean_release:"


def from_archive(path: Path) -> list[tuple[bytes, bytes]]:
    files = []
    with tarfile.open(path) as tar:
        for member in tar.getmembers():
            if not member.isfile() or member.name in RESERVED: continue
            content = tar.extractfile(member).read()
            files.append((member.name.encode("utf-8", "surrogateescape"), hashlib.sha256(content).digest()))
    return files


def from_directory(root: Path) -> list[tuple[bytes, bytes]]:
    files = []
    for path in root.rglob("*"):
        if not path.is_file(): continue
        relative = path.relative_to(root)
        if relative.parts[0] == ".git": continue
        name = relative.as_posix()
        if name in RESERVED: continue
        files.append((name.encode("utf-8"), hashlib.sha256(path.read_bytes()).digest()))
    return files


def digest(files: list[tuple[bytes, bytes]]) -> tuple[str, int]:
    hasher = hashlib.sha256()
    for name, value in sorted(files, key=lambda item: item[0]):
        hasher.update(name + b"\0" + value)
    return hasher.hexdigest(), len(files)


def artifact(ptype: str, package: str, version: str) -> str:
    return PREFIX + hashlib.sha256(f"{ptype}\n{package}\n{version}".encode("utf-8")).hexdigest()[:32]


def main():
    parser = argparse.ArgumentParser(description="wf-content-v1 digest of an Ocean release and its peering artifact id.")
    parser.add_argument("source", nargs="?", help="A downloaded release archive (.tar) or a checked out directory.")
    parser.add_argument("--artifact", nargs=3, metavar=("PTYPE", "PACKAGE", "VERSION"),
                        help="Print the artifact id of a release, e.g. additives users 1.0a4.")
    args = parser.parse_args()

    if args.artifact: print(artifact(*args.artifact))
    if args.source:
        source = Path(args.source)
        value, count = digest(from_directory(source) if source.is_dir() else from_archive(source))
        print(f"{value}  ({count} files)")
    if not args.artifact and not args.source: parser.print_help()


if __name__ == "__main__": main()
