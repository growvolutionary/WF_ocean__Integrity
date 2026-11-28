from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path
import argparse, re, sys

ROOT = Path(__file__).resolve().parent
SOURCES = {"ocean_integrity": "static/js/integrity.js"}
FROZEN = {}
VERSION = re.compile(r"^v(\d+)$")


def _generator():
    sys.dont_write_bytecode = True
    spec = spec_from_file_location("generate", ROOT / "generate.py")
    module = module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _folder(generate, artifact: str) -> Path:
    entry = generate.ARTIFACTS[artifact]
    return ROOT / (entry if isinstance(entry, str) else entry[0])


def _version(path: Path) -> int:
    return int(VERSION.match(path.stem).group(1))


def sync(additive: Path) -> list:
    generate = _generator()
    changes = []
    for artifact, source in SOURCES.items():
        served = additive / source
        if not served.is_file(): sys.exit(f"{source} of {artifact} does not exist")
        data = served.read_bytes().replace(b"\r\n", b"\n")
        folder = _folder(generate, artifact)
        versions = sorted((file for file in folder.glob("v*.js") if VERSION.match(file.stem)), key=_version)
        target = versions[-1] if versions else folder / "v1.js"
        frozen = target.stem in FROZEN.get(artifact, ())
        if versions and frozen and target.read_bytes().replace(b"\r\n", b"\n") != data:
            target = folder / f"v{_version(target) + 1}.js"
        if target.is_file() and target.read_bytes() == data: continue
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
        changes.append(target.relative_to(ROOT).as_posix())
    generate.main()
    return changes


def main():
    parser = argparse.ArgumentParser(description="Copy the served script into its latest open version and "
                                                 "regenerate manifest.json.")
    parser.add_argument("--additive", type=Path, default=ROOT.parent)
    for line in sync(parser.parse_args().additive.resolve()): print(line)
    print("manifest.json regenerated")


if __name__ == "__main__": main()
