# -*- coding: utf-8 -*-
# ------------------------------------------------------------------------------
#
#   Copyright 2026 Valory AG
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

"""Tests for ``aea_ci_helpers.check_third_party_hashes``."""

import json
from pathlib import Path
from typing import Dict
from unittest import mock

import pytest
from aea_ci_helpers.check_third_party_hashes import (
    Upstream,
    check_hashes,
    load_local_third_party,
    run,
)


class TestUpstream:
    """Tests for ``Upstream.parse``."""

    def test_parse_valid(self) -> None:
        """A well-formed spec yields the expected fields."""
        u = Upstream.parse("valory-xyz/open-aea@2.2.0")
        assert u.repo == "valory-xyz/open-aea"
        assert u.version == "2.2.0"

    @pytest.mark.parametrize(
        "spec",
        [
            "no-at-sign",
            "@2.2.0",
            "valory-xyz/open-aea@",
            "noslash@2.2.0",
        ],
    )
    def test_parse_invalid(self, spec: str) -> None:
        """Malformed specs raise ``ValueError``."""
        with pytest.raises(ValueError):
            Upstream.parse(spec)


class TestLoadLocalThirdParty:
    """Tests for ``load_local_third_party``."""

    def test_reads_third_party_section(self, tmp_path: Path) -> None:
        """Returns the ``third_party`` map from ``packages/packages.json``."""
        (tmp_path / "packages").mkdir()
        (tmp_path / "packages" / "packages.json").write_text(
            json.dumps(
                {
                    "dev": {"skill/me/a/0.1.0": "bafy1"},
                    "third_party": {"protocol/you/x/0.1.0": "bafy2"},
                }
            )
        )
        result = load_local_third_party(tmp_path)
        assert result == {"protocol/you/x/0.1.0": "bafy2"}

    def test_missing_third_party_returns_empty(self, tmp_path: Path) -> None:
        """Absent ``third_party`` key yields an empty dict."""
        (tmp_path / "packages").mkdir()
        (tmp_path / "packages" / "packages.json").write_text(json.dumps({"dev": {}}))
        assert load_local_third_party(tmp_path) == {}


class TestCheckHashes:
    """Tests for the matching logic in ``check_hashes``."""

    def _patched(
        self,
        local: Dict[str, str],
        upstream_responses: Dict[str, Dict[str, str]],
    ):
        """Patch ``fetch_upstream_packages`` to return canned data per upstream."""

        def _fake_fetch(upstream: Upstream) -> Dict[str, str]:
            key = f"{upstream.repo}@{upstream.version}"
            return upstream_responses[key]

        return mock.patch(
            "aea_ci_helpers.check_third_party_hashes.fetch_upstream_packages",
            side_effect=_fake_fetch,
        )

    def test_all_match_single_upstream(self) -> None:
        """No mismatches or missing when local hashes match upstream."""
        local = {"protocol/valory/abci/0.1.0": "bafyA"}
        upstreams = [Upstream("valory-xyz/open-aea", "2.2.0")]
        responses = {
            "valory-xyz/open-aea@2.2.0": {"protocol/valory/abci/0.1.0": "bafyA"}
        }
        with self._patched(local, responses):
            mismatches, missing = check_hashes(local, upstreams)
        assert mismatches == []
        assert missing == []

    def test_mismatch_detected(self) -> None:
        """A differing hash in the only upstream is reported as mismatch."""
        local = {"protocol/valory/abci/0.1.0": "bafyLOCAL"}
        upstreams = [Upstream("valory-xyz/open-aea", "2.2.0")]
        responses = {
            "valory-xyz/open-aea@2.2.0": {"protocol/valory/abci/0.1.0": "bafyREMOTE"}
        }
        with self._patched(local, responses):
            mismatches, missing = check_hashes(local, upstreams)
        assert mismatches == [
            (
                "protocol/valory/abci/0.1.0",
                "bafyLOCAL",
                "bafyREMOTE",
                "valory-xyz/open-aea@v2.2.0",
            )
        ]
        assert missing == []

    def test_package_missing_from_all_upstreams(self) -> None:
        """A package absent from every upstream is reported as missing."""
        local = {"protocol/valory/orphan/0.1.0": "bafyX"}
        upstreams = [
            Upstream("valory-xyz/open-aea", "2.2.0"),
            Upstream("other/repo", "1.0.0"),
        ]
        responses = {
            "valory-xyz/open-aea@2.2.0": {},
            "other/repo@1.0.0": {},
        }
        with self._patched(local, responses):
            mismatches, missing = check_hashes(local, upstreams)
        assert mismatches == []
        assert missing == ["protocol/valory/orphan/0.1.0"]

    def test_match_in_any_upstream_is_ok(self) -> None:
        """A match in *any* upstream is enough; no mismatch reported."""
        local = {"protocol/valory/abci/0.1.0": "bafyA"}
        upstreams = [
            Upstream("valory-xyz/open-aea", "2.2.0"),
            Upstream("other/repo", "1.0.0"),
        ]
        responses = {
            "valory-xyz/open-aea@2.2.0": {"protocol/valory/abci/0.1.0": "bafyOTHER"},
            "other/repo@1.0.0": {"protocol/valory/abci/0.1.0": "bafyA"},
        }
        with self._patched(local, responses):
            mismatches, missing = check_hashes(local, upstreams)
        assert mismatches == []
        assert missing == []


class TestRun:
    """Tests for the top-level ``run`` entry point."""

    def _write_packages(self, root: Path, third_party: Dict[str, str]) -> None:
        (root / "packages").mkdir()
        (root / "packages" / "packages.json").write_text(
            json.dumps({"dev": {}, "third_party": third_party})
        )

    def test_rejects_invalid_upstream_spec(self, tmp_path: Path) -> None:
        """An unparseable ``--upstream`` arg yields exit code 1."""
        self._write_packages(tmp_path, {"p/v/a/0.1.0": "bafy"})
        assert run(tmp_path, ["not-a-spec"]) == 1

    def test_requires_at_least_one_upstream(self, tmp_path: Path) -> None:
        """No upstreams provided yields exit code 1."""
        self._write_packages(tmp_path, {"p/v/a/0.1.0": "bafy"})
        assert run(tmp_path, []) == 1

    def test_empty_third_party_is_ok(self, tmp_path: Path) -> None:
        """An empty ``third_party`` section succeeds without any requests."""
        self._write_packages(tmp_path, {})
        with mock.patch(
            "aea_ci_helpers.check_third_party_hashes.fetch_upstream_packages",
        ) as fetch:
            assert run(tmp_path, ["valory-xyz/open-aea@2.2.0"]) == 0
            fetch.assert_not_called()

    def test_mismatch_yields_exit_1(self, tmp_path: Path) -> None:
        """A hash mismatch returns exit code 1."""
        self._write_packages(tmp_path, {"p/v/a/0.1.0": "bafyLOCAL"})
        with mock.patch(
            "aea_ci_helpers.check_third_party_hashes.fetch_upstream_packages",
            return_value={"p/v/a/0.1.0": "bafyREMOTE"},
        ):
            assert run(tmp_path, ["valory-xyz/open-aea@2.2.0"]) == 1

    def test_match_yields_exit_0(self, tmp_path: Path) -> None:
        """All hashes matching returns exit code 0."""
        self._write_packages(tmp_path, {"p/v/a/0.1.0": "bafyOK"})
        with mock.patch(
            "aea_ci_helpers.check_third_party_hashes.fetch_upstream_packages",
            return_value={"p/v/a/0.1.0": "bafyOK"},
        ):
            assert run(tmp_path, ["valory-xyz/open-aea@2.2.0"]) == 0

    def test_unreachable_upstream_yields_exit_1(self, tmp_path: Path) -> None:
        """An upstream fetch error returns exit code 1."""
        self._write_packages(tmp_path, {"p/v/a/0.1.0": "bafyOK"})
        with mock.patch(
            "aea_ci_helpers.check_third_party_hashes.fetch_upstream_packages",
            side_effect=RuntimeError("network unreachable"),
        ):
            assert run(tmp_path, ["valory-xyz/open-aea@2.2.0"]) == 1
