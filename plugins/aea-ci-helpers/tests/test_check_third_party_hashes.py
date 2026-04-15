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
from typing import Dict, Tuple
from unittest import mock

import pytest
from aea_ci_helpers.check_third_party_hashes import (
    Upstream,
    check_hashes,
    fetch_upstream_packages,
    load_local_third_party,
    run,
)

from aea.helpers import http_requests


class TestUpstream:
    """Tests for ``Upstream.parse`` and version normalisation."""

    def test_parse_valid(self) -> None:
        """A well-formed spec yields the expected fields."""
        u = Upstream.parse("valory-xyz/open-aea@2.2.0")
        assert u.repo == "valory-xyz/open-aea"
        assert u.version == "2.2.0"

    def test_tag_version_strips_leading_v(self) -> None:
        """``@v2.2.0`` and ``@2.2.0`` build the same tag URL."""
        assert Upstream("o/r", "v2.2.0").tag_version == "2.2.0"
        assert Upstream("o/r", "2.2.0").tag_version == "2.2.0"

    def test_display_always_shows_v(self) -> None:
        """The human-readable form is consistent regardless of input."""
        assert Upstream("o/r", "2.2.0").display == "o/r@v2.2.0"
        assert Upstream("o/r", "v2.2.0").display == "o/r@v2.2.0"

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


class TestFetchUpstreamPackages:
    """Tests for ``fetch_upstream_packages`` itself (not just its callers).

    These cover URL building, non-200 handling, JSON decoding, the
    ``dev``/``third_party`` merge, and network/transport errors —
    everything the rest of the suite mocks out.
    """

    def _mock_response(
        self,
        status_code: int = 200,
        json_data: object = None,
        text: str = "",
        content_type: str = "application/json",
        raise_on_json: bool = False,
    ) -> mock.Mock:
        resp = mock.Mock()
        resp.status_code = status_code
        resp.text = text
        resp.headers = {"Content-Type": content_type}
        if raise_on_json:
            resp.json.side_effect = ValueError("no json")
        else:
            resp.json.return_value = json_data
        return resp

    def test_builds_expected_url(self) -> None:
        """The tag URL uses the stripped version with a leading ``v``."""
        upstream = Upstream("valory-xyz/open-aea", "v2.2.0")
        with mock.patch(
            "aea_ci_helpers.check_third_party_hashes.http_requests.get",
            return_value=self._mock_response(json_data={"dev": {}}),
        ) as get:
            fetch_upstream_packages(upstream)
        called_url = get.call_args.args[0]
        assert called_url == (
            "https://raw.githubusercontent.com/valory-xyz/open-aea/"
            "v2.2.0/packages/packages.json"
        )

    def test_non_200_raises(self) -> None:
        """A non-200 response raises ``RuntimeError`` with the status."""
        upstream = Upstream("o/r", "1.0.0")
        with mock.patch(
            "aea_ci_helpers.check_third_party_hashes.http_requests.get",
            return_value=self._mock_response(status_code=404),
        ):
            with pytest.raises(RuntimeError, match="status 404"):
                fetch_upstream_packages(upstream)

    def test_request_exception_is_wrapped(self) -> None:
        """Transport errors become ``RuntimeError`` (not raw exceptions)."""
        upstream = Upstream("o/r", "1.0.0")
        with mock.patch(
            "aea_ci_helpers.check_third_party_hashes.http_requests.get",
            side_effect=http_requests.ConnectionError("boom"),
        ):
            with pytest.raises(RuntimeError, match="Failed to fetch"):
                fetch_upstream_packages(upstream)

    def test_malformed_json_is_wrapped(self) -> None:
        """A non-JSON 200 body (e.g. GitHub HTML error) raises ``RuntimeError``."""
        upstream = Upstream("o/r", "1.0.0")
        with mock.patch(
            "aea_ci_helpers.check_third_party_hashes.http_requests.get",
            return_value=self._mock_response(
                raise_on_json=True, text="<html>oops</html>", content_type="text/html"
            ),
        ):
            with pytest.raises(RuntimeError, match="Malformed JSON"):
                fetch_upstream_packages(upstream)

    def test_merges_dev_and_third_party(self) -> None:
        """The returned map is the union of ``dev`` and ``third_party``."""
        upstream = Upstream("o/r", "1.0.0")
        payload = {
            "dev": {"skill/a/b/0.1.0": "bafy1"},
            "third_party": {"protocol/x/y/0.1.0": "bafy2"},
        }
        with mock.patch(
            "aea_ci_helpers.check_third_party_hashes.http_requests.get",
            return_value=self._mock_response(json_data=payload),
        ):
            result = fetch_upstream_packages(upstream)
        assert result == {
            "skill/a/b/0.1.0": "bafy1",
            "protocol/x/y/0.1.0": "bafy2",
        }

    def test_missing_dev_key_raises(self) -> None:
        """A response without a ``dev`` section is treated as malformed."""
        upstream = Upstream("o/r", "1.0.0")
        with mock.patch(
            "aea_ci_helpers.check_third_party_hashes.http_requests.get",
            return_value=self._mock_response(json_data={"third_party": {}}),
        ):
            with pytest.raises(RuntimeError, match="does not contain a 'dev' section"):
                fetch_upstream_packages(upstream)


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

    def test_missing_file_raises_runtime_error(self, tmp_path: Path) -> None:
        """A missing ``packages.json`` yields a clean ``RuntimeError``."""
        with pytest.raises(RuntimeError, match="not found"):
            load_local_third_party(tmp_path)

    def test_malformed_json_raises_runtime_error(self, tmp_path: Path) -> None:
        """A malformed ``packages.json`` yields a clean ``RuntimeError``."""
        (tmp_path / "packages").mkdir()
        (tmp_path / "packages" / "packages.json").write_text("{ not json")
        with pytest.raises(RuntimeError, match="malformed JSON"):
            load_local_third_party(tmp_path)


class TestCheckHashes:
    """Tests for the matching logic in ``check_hashes``.

    ``check_hashes`` now operates purely on pre-fetched upstream maps,
    so these tests do not need to patch the network layer.
    """

    @staticmethod
    def _maps(
        *entries: Tuple[str, Dict[str, str]],
    ) -> list:
        return list(entries)

    def test_all_match_single_upstream(self) -> None:
        """No mismatches or missing when local hashes match upstream."""
        local = {"protocol/valory/abci/0.1.0": "bafyA"}
        upstream_maps = self._maps(
            ("valory-xyz/open-aea@v2.2.0", {"protocol/valory/abci/0.1.0": "bafyA"}),
        )
        mismatches, missing = check_hashes(local, upstream_maps)
        assert mismatches == []
        assert missing == []

    def test_mismatch_detected(self) -> None:
        """A differing hash in the only upstream is reported as mismatch."""
        local = {"protocol/valory/abci/0.1.0": "bafyLOCAL"}
        upstream_maps = self._maps(
            (
                "valory-xyz/open-aea@v2.2.0",
                {"protocol/valory/abci/0.1.0": "bafyREMOTE"},
            ),
        )
        mismatches, missing = check_hashes(local, upstream_maps)
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
        upstream_maps = self._maps(
            ("valory-xyz/open-aea@v2.2.0", {}),
            ("other/repo@v1.0.0", {}),
        )
        mismatches, missing = check_hashes(local, upstream_maps)
        assert mismatches == []
        assert missing == ["protocol/valory/orphan/0.1.0"]

    def test_match_in_any_upstream_is_ok(self) -> None:
        """A match in *any* upstream is enough; no mismatch reported."""
        local = {"protocol/valory/abci/0.1.0": "bafyA"}
        upstream_maps = self._maps(
            ("valory-xyz/open-aea@v2.2.0", {"protocol/valory/abci/0.1.0": "bafyOTHER"}),
            ("other/repo@v1.0.0", {"protocol/valory/abci/0.1.0": "bafyA"}),
        )
        mismatches, missing = check_hashes(local, upstream_maps)
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

    def test_missing_local_packages_json_yields_exit_1(self, tmp_path: Path) -> None:
        """A missing local file is reported cleanly."""
        assert run(tmp_path, ["valory-xyz/open-aea@2.2.0"]) == 1

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

    def test_all_upstreams_unreachable_yields_exit_1(self, tmp_path: Path) -> None:
        """If no upstream is reachable, the command cannot verify and fails."""
        self._write_packages(tmp_path, {"p/v/a/0.1.0": "bafyOK"})
        with mock.patch(
            "aea_ci_helpers.check_third_party_hashes.fetch_upstream_packages",
            side_effect=RuntimeError("network unreachable"),
        ):
            assert run(tmp_path, ["valory-xyz/open-aea@2.2.0"]) == 1

    def test_one_unreachable_but_other_matches_is_ok(self, tmp_path: Path) -> None:
        """A flaky upstream is tolerated when another upstream succeeds."""
        self._write_packages(tmp_path, {"p/v/a/0.1.0": "bafyOK"})

        def _fetch(upstream: Upstream) -> Dict[str, str]:
            if "flaky" in upstream.repo:
                raise RuntimeError("boom")
            return {"p/v/a/0.1.0": "bafyOK"}

        with mock.patch(
            "aea_ci_helpers.check_third_party_hashes.fetch_upstream_packages",
            side_effect=_fetch,
        ):
            assert (
                run(
                    tmp_path,
                    [
                        "flaky/mirror@2.2.0",
                        "valory-xyz/open-aea@2.2.0",
                    ],
                )
                == 0
            )

    def test_missing_from_reachable_upstreams_yields_exit_1(
        self, tmp_path: Path
    ) -> None:
        """A package absent from every reachable upstream fails the check."""
        self._write_packages(tmp_path, {"p/v/a/0.1.0": "bafyOK"})
        with mock.patch(
            "aea_ci_helpers.check_third_party_hashes.fetch_upstream_packages",
            return_value={},
        ):
            assert run(tmp_path, ["valory-xyz/open-aea@2.2.0"]) == 1
