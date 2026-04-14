# -*- coding: utf-8 -*-
# ------------------------------------------------------------------------------
#
#   Copyright 2022-2026 Valory AG
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.
#
# ------------------------------------------------------------------------------

"""Check that third-party package hashes match one or more upstream repositories.

Downstream repos (e.g. open-autonomy) pin third-party packages in their
local ``packages/packages.json`` under ``third_party``. Those entries
must match the hashes published by each upstream repo at the relevant
version tag. This command verifies that alignment.

Upstreams are passed as ``owner/repo@version`` and may be repeated. For
each upstream, the command fetches ``packages/packages.json`` from the
tag ``v<version>`` on ``raw.githubusercontent.com`` and compares the
hashes of any local ``third_party`` entries present in that upstream.
"""

import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Tuple

import requests

RAW_PACKAGES_URL = (
    "https://raw.githubusercontent.com/{repo}/v{version}/packages/packages.json"
)


@dataclass(frozen=True)
class Upstream:
    """An upstream repository reference."""

    repo: str
    version: str

    @classmethod
    def parse(cls, spec: str) -> "Upstream":
        """Parse ``owner/repo@version`` into an ``Upstream``."""
        if "@" not in spec:
            raise ValueError(
                f"Invalid upstream spec {spec!r}: expected 'owner/repo@version'"
            )
        repo, _, version = spec.partition("@")
        if not repo or not version or "/" not in repo:
            raise ValueError(
                f"Invalid upstream spec {spec!r}: expected 'owner/repo@version'"
            )
        return cls(repo=repo, version=version)


def fetch_upstream_packages(upstream: Upstream, timeout: int = 30) -> Dict[str, str]:
    """Fetch ``packages.json`` from an upstream repo at the tagged version.

    :param upstream: the upstream reference.
    :param timeout: request timeout in seconds.
    :return: mapping of package ID to IPFS hash (dev + third_party combined).
    :raises RuntimeError: if the upstream is unreachable or returns a non-200.
    """
    url = RAW_PACKAGES_URL.format(repo=upstream.repo, version=upstream.version)
    response = requests.get(url, timeout=timeout)
    if response.status_code != 200:
        raise RuntimeError(
            f"Failed to fetch packages.json from {url} "
            f"(status {response.status_code})"
        )
    data = response.json()
    if "dev" in data:
        combined: Dict[str, str] = {}
        combined.update(data.get("dev", {}))
        combined.update(data.get("third_party", {}))
        return combined
    return data


def load_local_third_party(root_dir: Path) -> Dict[str, str]:
    """Read the ``third_party`` section of the local ``packages.json``.

    :param root_dir: repository root containing ``packages/packages.json``.
    :return: mapping of package ID to IPFS hash.
    """
    packages_json = root_dir / "packages" / "packages.json"
    with open(packages_json, "r", encoding="utf-8") as f:
        data = json.load(f)
    return data.get("third_party", {})


def check_hashes(
    local_third_party: Dict[str, str], upstreams: List[Upstream]
) -> Tuple[List[Tuple[str, str, str, str]], List[str]]:
    """Compare local third-party hashes against one or more upstream repos.

    A local entry is considered resolved as soon as any upstream contains
    it with a matching hash. It is a mismatch if some upstream contains
    it with a different hash. It is "missing" only if no upstream knows
    about it at all.

    :param local_third_party: local third_party map (package_id -> hash).
    :param upstreams: list of upstream package maps, aligned with ``specs``.
    :return: ``(mismatches, missing)`` where
        * ``mismatches`` is a list of ``(package_id, local_hash,
          remote_hash, upstream_spec)`` tuples,
        * ``missing`` is a list of package IDs not found in any upstream.
    """
    mismatches: List[Tuple[str, str, str, str]] = []
    missing: List[str] = []
    upstream_maps = [
        (f"{u.repo}@v{u.version}", fetch_upstream_packages(u)) for u in upstreams
    ]

    for package_id, local_hash in sorted(local_third_party.items()):
        seen_in_any = False
        matched = False
        pending_mismatches: List[Tuple[str, str, str, str]] = []
        for spec, remote_map in upstream_maps:
            if package_id not in remote_map:
                continue
            seen_in_any = True
            remote_hash = remote_map[package_id]
            if remote_hash == local_hash:
                matched = True
                break
            pending_mismatches.append((package_id, local_hash, remote_hash, spec))

        if not seen_in_any:
            missing.append(package_id)
        elif not matched:
            mismatches.extend(pending_mismatches)

    return mismatches, missing


def run(root_dir: Path, upstream_specs: List[str]) -> int:
    """Run the third-party hash check.

    :param root_dir: repository root (contains ``packages/packages.json``).
    :param upstream_specs: list of ``owner/repo@version`` strings.
    :return: 0 on success, 1 if mismatches or unreachable upstreams.
    """
    try:
        upstreams = [Upstream.parse(s) for s in upstream_specs]
    except ValueError as e:
        print(f"ERROR: {e}")
        return 1

    if not upstreams:
        print("ERROR: at least one --upstream must be provided")
        return 1

    print(f"Checking third-party hashes in {root_dir}")
    for u in upstreams:
        print(f"  upstream: {u.repo}@v{u.version}")

    local_third_party = load_local_third_party(root_dir)
    if not local_third_party:
        print("No third-party packages declared locally; nothing to check.")
        return 0

    try:
        mismatches, missing = check_hashes(local_third_party, upstreams)
    except RuntimeError as e:
        print(f"ERROR: {e}")
        return 1

    if missing:
        print(
            f"\nWARNING: {len(missing)} third-party package(s) not found in any "
            "upstream:"
        )
        for pkg in missing:
            print(f"  - {pkg}")

    if mismatches:
        print(f"\nERROR: {len(mismatches)} hash mismatch(es) found:")
        for pkg, local_h, remote_h, spec in mismatches:
            print(f"  {pkg} (upstream: {spec})")
            print(f"    local:  {local_h}")
            print(f"    remote: {remote_h}")
        return 1

    print(
        f"\nAll {len(local_third_party)} third-party hashes are consistent "
        f"with {len(upstreams)} upstream(s)."
    )
    return 0


def main(root_dir: Path, upstream_specs: List[str]) -> None:
    """CLI entry point."""
    sys.exit(run(root_dir, upstream_specs))
