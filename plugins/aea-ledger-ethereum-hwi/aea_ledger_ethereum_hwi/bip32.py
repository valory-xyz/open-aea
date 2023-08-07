# -*- coding: utf-8 -*-
# ------------------------------------------------------------------------------
#
#   Copyright 2023 Valory AG
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

"""
BIP32 utils

Original implementation: https://github.com/LedgerHQ/apduboy/blob/master/apduboy/lib/bip32.py
"""

from dataclasses import dataclass, field
from typing import List


BIP32_HARDEN_BIT = 0x80000000


@dataclass
class Level:
    """Level separator."""

    _value: int

    @property
    def value(self) -> int:
        """Value"""
        return self._value

    def __str__(self) -> str:
        """String representation."""
        if self._value & BIP32_HARDEN_BIT:
            value = self._value - BIP32_HARDEN_BIT
            return f"{value}'"
        return f"{self._value}"


@dataclass
class Derivation:
    """Path derivation"""

    _path_list: List["Level"] = field(default_factory=list)

    def __truediv__(self, level: int) -> "Derivation":
        """Combine multiple path derivations using `/` operator."""
        return Derivation(self._path_list + [Level(level)])

    @property
    def account(self) -> int:
        """Account value."""
        if self.depth < 3:
            raise ValueError(f"Insufficient HD tree depth: {self.depth}")
        return self._path_list[2].value

    @property
    def parent(self) -> "Derivation":
        """Parent value."""
        return Derivation(self._path_list[:-1])

    @property
    def path(self) -> str:
        """Calculated path."""
        if not self._path_list:
            return "m"
        return "m/" + "/".join(str(level) for level in self._path_list)

    def to_list(self) -> List[int]:
        """Convert to list."""
        return [level.value for level in self._path_list]

    @property
    def depth(self) -> int:
        """Depth."""
        return len(self._path_list)

    def __repr__(self):
        """String representation."""
        return self.path

    def __str__(self):
        """String representation."""
        return self.path


def h(value: int) -> int:
    """Wrap value."""
    return value + BIP32_HARDEN_BIT


m = Derivation()
