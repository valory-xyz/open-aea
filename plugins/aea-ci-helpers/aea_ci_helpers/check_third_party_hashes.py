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

Upstreams are passed as ``owner/repo@version`` and may be repeated. The
``version`` segment may optionally include a leading ``v`` — both
``@2.2.0`` and ``@v2.2.0`` resolve to the same tag. For each upstream
the command fetches ``packages/packages.json`` from
``raw.githubusercontent.com`` at tag ``v<version>`` and compares
against any local ``third_party`` entries.

Matching rule: a local entry is considered OK as soon as *any* upstream
contains it with a matching hash. An upstream that cannot be reached
(network error, 404, malformed response) is tolerated as long as at
least one other upstream was reachable. The check fails only when (a)
a reachable upstream reports a different hash, (b) a local entry is
present nowhere in any reachable upstream, or (c) *every* upstream is
unreachable.
"""

import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Tuple

import click

from aea.helpers import http_requests

RAW_PACKAGES_URL = (
    "https://raw.githubusercontent.com/{repo}/v{version}/packages/packages.json"
)


@dataclass(frozen=True)
class Upstream:
    """An upstream repository reference."""

    repo: str
    version: str

    @property
    def tag_version(self) -> str:
        """Return the version segment used to build the tag URL.

        Any leading ``v`` supplied by the caller is stripped so that
        both ``@2.2.0`` and ``@v2.2.0`` build the same URL.

        :return: the version string with any leading ``v`` removed.
        """
        return self.version.lstrip("v")

    @property
    def display(self) -> str:
        """Return a human-readable form, e.g. ``valory-xyz/open-aea@v2.2.0``.

        :return: the canonical display string.
        """
        return f"{self.repo}@v{self.tag_version}"

    @classmethod
    def parse(cls, spec: str) -> "Upstream":
        """Parse ``owner/repo@version`` into an ``Upstream``.

        :param spec: the raw string supplied via ``--upstream``.
        :return: the parsed ``Upstream`` instance.
        :raises ValueError: if ``spec`` is not well-formed.
        """
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

    Returns the union of the ``dev`` and ``third_party`` maps, which
    together describe every package the upstream publishes.

    :param upstream: the upstream reference.
    :param timeout: request timeout in seconds.
    :return: mapping of package ID to IPFS hash.
    :raises RuntimeError: if the upstream is unreachable, returns a
        non-200, yields malformed JSON, or has no ``dev`` section (which
        would indicate a malformed ``packages.json``).
    """
    url = RAW_PACKAGES_URL.format(repo=upstream.repo, version=upstream.tag_version)
    try:
        response = http_requests.get(url, timeout=timeout)
    except http_requests.ConnectionError as e:
        raise RuntimeError(f"Failed to fetch packages.json from {url}: {e}") from e
    if response.status_code != 200:
        raise RuntimeError(
            f"Failed to fetch packages.json from {url} "
            f"(status {response.status_code})"
        )
    try:
        data = response.json()
    except ValueError as e:
        snippet = response.text[:120].replace("\n", " ")
        raise RuntimeError(f"Malformed JSON from {url}: {snippet!r}") from e
    if "dev" not in data:
        raise RuntimeError(
            f"{url} does not contain a 'dev' section; " f"not a valid packages.json"
        )
    # Merge ``dev`` and ``third_party`` into a single lookup: a downstream's
    # third-party entry may originate from either the upstream's own
    # first-party packages (``dev``) or its re-exported third-party set.
    combined: Dict[str, str] = {}
    combined.update(data.get("dev", {}))
    combined.update(data.get("third_party", {}))
    return combined


def load_local_third_party(root_dir: Path) -> Dict[str, str]:
    """Read the ``third_party`` section of the local ``packages.json``.

    :param root_dir: repository root containing ``packages/packages.json``.
    :return: mapping of package ID to IPFS hash (empty if section absent).
    :raises RuntimeError: if ``packages/packages.json`` is missing or
        not valid JSON.
    """
    packages_json = root_dir / "packages" / "packages.json"
    try:
        with open(packages_json, "r", encoding="utf-8") as f:
            data = json.load(f)
    except FileNotFoundError as e:
        raise RuntimeError(f"Local packages file not found: {packages_json}") from e
    except json.JSONDecodeError as e:
        raise RuntimeError(
            f"Local packages file is malformed JSON: {packages_json}: {e}"
        ) from e
    return data.get("third_party", {})


def check_hashes(
    local_third_party: Dict[str, str],
    upstream_maps: List[Tuple[str, Dict[str, str]]],
) -> Tuple[List[Tuple[str, str, str, str]], List[str]]:
    """Compare local third-party hashes against pre-fetched upstream maps.

    A local entry is considered OK as soon as any upstream contains it
    with a matching hash. If some upstream contains it with a different
    hash and no upstream matches, it is reported as a mismatch. If no
    reachable upstream knows about it at all, it is reported as missing.

    :param local_third_party: local ``third_party`` map.
    :param upstream_maps: list of ``(display_spec, package_map)`` pairs
        for every *reachable* upstream. Unreachable upstreams must be
        handled (logged / tolerated) by the caller before invoking
        this function.
    :return: ``(mismatches, missing)`` where
        * ``mismatches`` is a list of ``(package_id, local_hash,
          remote_hash, upstream_spec)`` tuples,
        * ``missing`` is a list of package IDs not found in any
          reachable upstream.
    """
    mismatches: List[Tuple[str, str, str, str]] = []
    missing: List[str] = []

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


def _fetch_all(
    upstreams: List[Upstream],
) -> Tuple[List[Tuple[str, Dict[str, str]]], List[Tuple[str, str]]]:
    """Fetch every upstream, tolerating per-upstream failures.

    :param upstreams: list of upstream references.
    :return: ``(reachable, failed)`` where
        * ``reachable`` is a list of ``(display_spec, package_map)``
          pairs for upstreams that responded successfully,
        * ``failed`` is a list of ``(display_spec, error_message)``
          pairs for upstreams that couldn't be fetched.
    """
    reachable: List[Tuple[str, Dict[str, str]]] = []
    failed: List[Tuple[str, str]] = []
    for u in upstreams:
        try:
            reachable.append((u.display, fetch_upstream_packages(u)))
        except RuntimeError as e:
            failed.append((u.display, str(e)))
    return reachable, failed


def run(root_dir: Path, upstream_specs: List[str]) -> int:
    """Run the third-party hash check.

    :param root_dir: repository root (contains ``packages/packages.json``).
    :param upstream_specs: list of ``owner/repo@version`` strings.
    :return: 0 on success, 1 on any error (bad input, local file
        problems, hash mismatches, missing packages, or all upstreams
        unreachable).
    """
    try:
        upstreams = [Upstream.parse(s) for s in upstream_specs]
    except ValueError as e:
        click.echo(f"ERROR: {e}", err=True)
        return 1

    if not upstreams:
        click.echo("ERROR: at least one --upstream must be provided", err=True)
        return 1

    click.echo(f"Checking third-party hashes in {root_dir}")
    for u in upstreams:
        click.echo(f"  upstream: {u.display}")

    try:
        local_third_party = load_local_third_party(root_dir)
    except RuntimeError as e:
        click.echo(f"ERROR: {e}", err=True)
        return 1

    if not local_third_party:
        click.echo("No third-party packages declared locally; nothing to check.")
        return 0

    reachable, failed = _fetch_all(upstreams)

    if failed:
        click.echo(
            f"\nWARNING: {len(failed)} upstream(s) could not be fetched "
            "(tolerated as long as at least one other upstream responded):",
            err=True,
        )
        for spec, err in failed:
            click.echo(f"  - {spec}: {err}", err=True)

    if not reachable:
        click.echo(
            "\nERROR: all upstreams are unreachable; cannot verify "
            "third-party hashes.",
            err=True,
        )
        return 1

    mismatches, missing = check_hashes(local_third_party, reachable)

    if missing:
        click.echo(
            f"\nWARNING: {len(missing)} third-party package(s) not found "
            "in any reachable upstream:",
            err=True,
        )
        for pkg in missing:
            click.echo(f"  - {pkg}", err=True)

    if mismatches:
        click.echo(f"\nERROR: {len(mismatches)} hash mismatch(es) found:", err=True)
        for pkg, local_h, remote_h, spec in mismatches:
            click.echo(f"  {pkg} (upstream: {spec})", err=True)
            click.echo(f"    local:  {local_h}", err=True)
            click.echo(f"    remote: {remote_h}", err=True)
        return 1

    if missing:
        # "Missing from every reachable upstream" is a harder failure
        # than "mismatch" — we cannot verify the package at all.
        return 1

    click.echo(
        f"\nAll {len(local_third_party)} third-party hashes are consistent "
        f"with {len(reachable)} reachable upstream(s)."
    )
    return 0


def main(root_dir: Path, upstream_specs: List[str]) -> None:
    """CLI entry point."""
    sys.exit(run(root_dir, upstream_specs))
