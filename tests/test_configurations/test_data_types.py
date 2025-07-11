# -*- coding: utf-8 -*-
# ------------------------------------------------------------------------------
#
#   Copyright 2022-2025 Valory AG
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

"""Tests for config data types."""

import copy
import operator
from itertools import permutations
from math import isnan
from typing import Tuple

import pytest
from hypothesis import assume, given
from hypothesis import strategies as st

from aea.configurations.data_types import (
    Dependency,
    PackageId,
    PackageVersion,
    PublicId,
)

from tests.conftest import MAX_FLAKY_RERUNS
from tests.strategies.data_types import (
    package_id_strategy,
    public_id_strategy,
    version_info_strategy,
)


NUMERIC_TYPES = int, float
SEQUENCE_TYPES = str, list, tuple
ITERATOR_TYPES = *SEQUENCE_TYPES, set, frozenset, zip, map
CUSTOM_TYPES = PublicId, PackageId, Dependency
ALL_TYPES = *NUMERIC_TYPES, *ITERATOR_TYPES, *CUSTOM_TYPES
COMPARISON_OPERATORS = [
    operator.lt,
    operator.le,
    operator.eq,
    operator.ne,
    operator.ge,
    operator.gt,
]


def all_comparisons_operations_equal(pair_a, pair_b) -> bool:
    """Check whether all operator comparisons return the same result."""

    def all_comparisons(pair) -> Tuple[bool, ...]:
        return tuple(f(*pair) for f in COMPARISON_OPERATORS)

    return all_comparisons(pair_a) == all_comparisons(pair_b)


@pytest.mark.parametrize("self_type", [PackageVersion, PublicId, PackageId])
def test_self_type_comparison(self_type):
    """Test comparison to self"""

    self = st.from_type(self_type).example()
    other = copy.deepcopy(self)
    for f in COMPARISON_OPERATORS:
        assert isinstance(f(self, other), bool)
        assert isinstance(f(other, self), bool)


# possible issue with bad generated version specifier
@pytest.mark.flaky(reruns=MAX_FLAKY_RERUNS)
@given(
    st.one_of(list(map(st.from_type, ALL_TYPES))),
    st.one_of(list(map(st.from_type, CUSTOM_TYPES))),
)
def test_type_comparison(self, other):
    """Test type comparison"""

    if isinstance(self, float):
        assume(not isnan(self))
    assume(type(self) is not type(other))

    funcs = (operator.le, operator.lt, operator.ge, operator.gt)

    assert not isinstance(self, type(other))
    assert not isinstance(other, type(self))
    assert self.__eq__(self)
    assert other.__eq__(other)
    assert self.__ne__(other)
    assert other.__ne__(self)

    for f in funcs:
        with pytest.raises((TypeError, ValueError)):
            assert f(self, other)


@given(st.tuples(version_info_strategy, version_info_strategy))
def test_package_version_comparison(version_pair):
    """Test package version comparison"""

    package_pair = tuple(map(PackageVersion, version_pair))
    assert all_comparisons_operations_equal(version_pair, package_pair)


@given(st.tuples(public_id_strategy, public_id_strategy))
def test_public_id_comparison(public_id_pair):
    """Test public id comparison"""

    public_id_pair[0]._name = public_id_pair[1]._name
    public_id_pair[0]._author = public_id_pair[1]._author
    version_pair = tuple(p.package_version._version for p in public_id_pair)
    assert all_comparisons_operations_equal(version_pair, public_id_pair)


@given(st.tuples(package_id_strategy, package_id_strategy))
def test_package_id_comparison(package_id_pair):
    """Test package id comparison"""

    package_id_pair[0]._public_id = package_id_pair[1]._public_id
    package_id_pair[0]._package_type = package_id_pair[1]._package_type
    version_pair = tuple(p.public_id.package_version._version for p in package_id_pair)
    assert all_comparisons_operations_equal(version_pair, package_id_pair)


@pytest.mark.parametrize("version_like", ["any", "latest", "0.1.0"])
def test_any_and_latest_equal(version_like: str):
    """Test special version types "any" and "latest" when equal."""

    version_a, version_b = (PackageVersion(version_like) for _ in range(2))
    assert version_a == version_b
    assert not version_a < version_b


@pytest.mark.parametrize(
    "version_like_pair", permutations(["any", "latest", "0.1.0"], 2)
)
def test_any_latest_and_numeric_unequal(version_like_pair: Tuple[str]):
    """Test special version types "any" and "latest" when equal."""

    self, other = map(PackageVersion, version_like_pair)
    assert not self == other
    assert self != other

    funcs = (operator.le, operator.lt, operator.ge, operator.gt)
    for f in funcs:
        with pytest.raises(TypeError, match="not supported between"):
            assert f(self, other)


class TestDependency:
    """Test Dependency class."""

    def test_parse_from_string(self) -> None:
        """Test from_string method."""

        string = "tomte==0.4.0"
        dep = Dependency.from_string(string=string)
        assert dep.name == "tomte"
        assert str(dep.version) == "==0.4.0"
        assert dep.to_pip_string() == string

    def test_parse_from_string_wth_extras(self) -> None:
        """Test from_string method."""

        string = "tomte[tox,tests]==0.4.0"
        dep = Dependency.from_string(string=string)
        assert dep.name == "tomte"
        assert str(dep.version) == "==0.4.0"
        assert dep.extras == ["tox", "tests"]
        assert dep.to_pip_string() == string

    def test_parse_from_git_string(self) -> None:
        """Test from_string method."""

        string = "git+https://github.com/valory-xyz/tomte.git@03adee2a0a5681c6d8e77160be27edffaa8e3bee#egg=tomte"
        dep = Dependency.from_string(string=string)
        assert dep.name == "tomte"
        assert str(dep.ref) == "03adee2a0a5681c6d8e77160be27edffaa8e3bee"
        assert dep.git == "https://github.com/valory-xyz/tomte.git"
        assert dep.to_pip_string() == string

    def test_parse_from_pipfile_specifier(self) -> None:
        """Test from_pipfile_specifier method"""

        string = 'tomte = "==0.4.0"'
        dep = Dependency.from_pipfile_string(string)
        assert dep.name == "tomte"
        assert str(dep.version) == "==0.4.0"
        assert dep.to_pipfile_string() == string

    def test_parse_from_pipfile_specifier_with_extras(self) -> None:
        """Test from_pipfile_specifier method"""

        string = 'tomte = {version = "==0.4.0", extras = ["tox", "tests"]}'
        dep = Dependency.from_pipfile_string(string)
        assert dep.name == "tomte"
        assert str(dep.version) == "==0.4.0"
        assert dep.extras == ["tox", "tests"]
        assert dep.to_pipfile_string() == string

    def test_parse_from_pipfile_specifier_with_git_ref(self) -> None:
        """Test from_pipfile_specifier method"""

        string = 'tomte = {ref = "03adee2a0a5681c6d8e77160be27edffaa8e3bee", git = "git+https://github.com/valory-xyz/tomte.git"}'
        dep = Dependency.from_pipfile_string(string)
        assert dep.name == "tomte"
        assert str(dep.ref) == "03adee2a0a5681c6d8e77160be27edffaa8e3bee"
        assert dep.git == "https://github.com/valory-xyz/tomte.git"
        assert dep.to_pipfile_string() == string
