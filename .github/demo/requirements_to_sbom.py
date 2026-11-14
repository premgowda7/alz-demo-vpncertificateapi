#!/usr/bin/env python3
"""Make a minimal CycloneDX SBOM from a pip requirements file.

This is a small, dependency-free stand-in for the company CI's real cdxgen/BDBA
SBOM step, so the demo workflow can produce a real SBOM artifact on a GitHub-hosted
runner without needing any private registry or extra packages.

Usage: python requirements_to_sbom.py <requirements.txt> <output.json>
It reads only the declared dependency names and versions; it installs nothing.
"""
import json
import re
import sys
from pathlib import Path


def parse_requirements(text):
    """Return a list of (name, version-or-empty) from a requirements file."""
    components = []
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line or line.startswith("-"):
            continue
        match = re.match(r"^([A-Za-z0-9_.\-]+)\s*==\s*([A-Za-z0-9_.\-]+)", line)
        if match:
            components.append((match.group(1), match.group(2)))
            continue
        name = re.match(r"^([A-Za-z0-9_.\-]+)", line)
        if name:
            components.append((name.group(1), ""))
    return components


def build_sbom(components):
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "components": [
            {
                "type": "library",
                "name": name,
                "version": version,
                "purl": "pkg:pypi/{}@{}".format(name, version) if version else "pkg:pypi/{}".format(name),
            }
            for name, version in components
        ],
    }


def main(argv):
    if len(argv) != 3:
        print("usage: requirements_to_sbom.py <requirements.txt> <output.json>", file=sys.stderr)
        return 2
    req_path, out_path = Path(argv[1]), Path(argv[2])
    if not req_path.is_file():
        print("requirements file not found: {}".format(req_path), file=sys.stderr)
        return 1
    components = parse_requirements(req_path.read_text(encoding="utf-8"))
    sbom = build_sbom(components)
    out_path.write_text(json.dumps(sbom, indent=2), encoding="utf-8")
    print("wrote {} with {} components".format(out_path, len(components)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
