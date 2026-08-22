#!/usr/bin/env python3
"""Enforce the workspace's parser, format, device, and adapter boundaries."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
FORMATS = ROOT / "crates" / "formats"
FORMAT_CONSUMERS = {"fsmnt-drivers", "fsmnt-fuzz"}
FOUNDATION_DEPENDENCIES = {
    "fsmnt-core": set(),
    "fsmnt-parser-core": set(),
    "fsmnt-device": {"fsmnt-core", "fsmnt-parser-core"},
}


def cargo_metadata() -> dict[str, object]:
    """Return locked workspace metadata or terminate with Cargo's error."""
    completed = subprocess.run(
        ("cargo", "metadata", "--no-deps", "--format-version", "1", "--locked"),
        cwd=ROOT,
        check=False,
        text=True,
        capture_output=True,
    )
    if completed.returncode != 0:
        sys.stderr.write(completed.stdout)
        sys.stderr.write(completed.stderr)
        raise SystemExit(completed.returncode)
    return json.loads(completed.stdout)


def is_below(path: str, directory: Path) -> bool:
    """Return whether `path` resolves below `directory`."""
    try:
        Path(path).resolve().relative_to(directory)
    except ValueError:
        return False
    return True


def workspace_dependencies(
    package: dict[str, object], workspace_names: set[str]
) -> set[str]:
    """Return non-development workspace dependencies for one package."""
    return {
        dependency["name"]
        for dependency in package["dependencies"]
        if dependency.get("kind") != "dev" and dependency["name"] in workspace_names
    }


def main() -> None:
    """Reject dependency edges that invert the documented architecture."""
    metadata = cargo_metadata()
    packages = metadata["packages"]
    workspace_names = {package["name"] for package in packages}
    format_names = {
        package["name"]
        for package in packages
        if is_below(package["manifest_path"], FORMATS)
    }
    errors: list[str] = []

    for package in packages:
        name = package["name"]
        dependencies = workspace_dependencies(package, workspace_names)

        allowed_foundation = FOUNDATION_DEPENDENCIES.get(name)
        if allowed_foundation is not None:
            forbidden = dependencies - allowed_foundation
            if forbidden:
                edges = ", ".join(sorted(forbidden))
                errors.append(f"foundation crate {name} has inverted edges: {edges}")

        if name in format_names:
            forbidden = dependencies - format_names - {"fsmnt-parser-core"}
            if forbidden:
                edges = ", ".join(sorted(forbidden))
                errors.append(
                    f"{name} may depend only on parser-core or another format: {edges}"
                )
            continue

        if name not in FORMAT_CONSUMERS:
            leaked_formats = dependencies & format_names
            if leaked_formats:
                edges = ", ".join(sorted(leaked_formats))
                errors.append(f"shared crate {name} depends on format code: {edges}")

    if errors:
        sys.stderr.write("dependency boundary violations:\n")
        for error in errors:
            sys.stderr.write(f"- {error}\n")
        raise SystemExit(1)

    formats = ", ".join(sorted(format_names))
    print(f"dependency boundaries hold across {len(workspace_names)} packages")
    print(f"isolated format packages: {formats}")


if __name__ == "__main__":
    main()
