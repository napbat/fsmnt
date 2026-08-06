#!/usr/bin/env python3
"""Verify that every no-std format parser stays free of std features."""

from __future__ import annotations

import subprocess
import sys
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
FORMAT_CRATES = (
    "fs-common",
    "fs-ntfs",
    "fs-fat",
    "fs-ext",
    "fs-apfs",
    "fs-exfat",
    "nt-compression",
)


def run_cargo(*arguments: str) -> str:
    """Run Cargo from the workspace root and return its standard output."""
    command = ("cargo", *arguments, "--locked")
    completed = subprocess.run(
        command,
        cwd=ROOT,
        check=False,
        text=True,
        capture_output=True,
    )
    if completed.returncode != 0:
        sys.stderr.write(completed.stdout)
        sys.stderr.write(completed.stderr)
        raise SystemExit(completed.returncode)
    return completed.stdout


def reaches_std(
    feature: str,
    feature_table: dict[str, list[str]],
    visiting: frozenset[str] = frozenset(),
) -> bool:
    """Return whether a local feature enables std directly or transitively."""
    if feature == "std":
        return True
    if feature in visiting:
        return False
    for enabled in feature_table.get(feature, []):
        if enabled == "std" or enabled.endswith("/std"):
            return True
        if enabled in feature_table and reaches_std(
            enabled,
            feature_table,
            visiting | {feature},
        ):
            return True
    return False


def check_crate(
    package: str,
    manifest_path: str,
    feature_table: dict[str, list[str]],
) -> None:
    """Check one parser's manifest, default build, and maximal no-std build."""
    for feature in feature_table:
        if feature != "std" and reaches_std(feature, feature_table):
            raise SystemExit(
                f"{manifest_path}: feature {feature!r} enables std; "
                "only the explicit 'std' compatibility feature may do that"
            )

    run_cargo("check", "-p", package)
    default_tree = run_cargo("tree", "-p", package, "-e", "normal,features")
    if 'feature "std"' in default_tree:
        raise SystemExit(f"{package}: its default dependency graph enables std")

    non_std_features = sorted(
        feature for feature in feature_table if feature not in {"default", "std"}
    )
    check_arguments = ["check", "-p", package, "--no-default-features"]
    tree_arguments = [
        "tree",
        "-p",
        package,
        "--no-default-features",
        "-e",
        "normal,features",
    ]
    if non_std_features:
        feature_list = ",".join(non_std_features)
        check_arguments.extend(("--features", feature_list))
        tree_arguments.extend(("--features", feature_list))

    run_cargo(*check_arguments)
    feature_tree = run_cargo(*tree_arguments)
    if 'feature "std"' in feature_tree:
        raise SystemExit(
            f"{package}: enabling all non-std parser features activates std"
        )

    print(f"{package}: default and maximal feature sets are no_std")


def main() -> None:
    """Check all parsers; nt-bitlocker is the documented std-only exception."""
    metadata = json.loads(
        run_cargo("metadata", "--no-deps", "--format-version", "1")
    )
    packages = {package["name"]: package for package in metadata["packages"]}
    for package in FORMAT_CRATES:
        package_metadata = packages[package]
        check_crate(
            package,
            package_metadata["manifest_path"],
            package_metadata["features"],
        )


if __name__ == "__main__":
    main()
