# -*- coding: utf-8 -*-
# ------------------------------------------------------------------------------
#
#   Copyright 2021-2026 Valory AG
#   Copyright 2018-2019 Fetch.AI Limited
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
"""This module contains the tests for the base classes for the skills."""

import shutil
import types
import unittest.mock
from pathlib import Path
from queue import Queue
from textwrap import dedent
from types import SimpleNamespace
from unittest import TestCase, mock
from unittest.mock import MagicMock, Mock, patch

import pytest
from aea_ledger_ethereum import EthereumCrypto
from aea_ledger_ethereum.test_tools.constants import ETHEREUM_PRIVATE_KEY_PATH
from aea_ledger_fetchai import FetchAICrypto
from aea_ledger_fetchai.test_tools.constants import FETCHAI_PRIVATE_KEY_PATH

import aea
from aea.aea import AEA
from aea.common import Address
from aea.configurations.base import PublicId, SkillComponentConfiguration, SkillConfig
from aea.configurations.data_types import ComponentType
from aea.configurations.loader import load_component_configuration
from aea.crypto.wallet import Wallet
from aea.exceptions import AEAHandleException, _StopRuntime
from aea.identity.base import Identity
from aea.multiplexer import MultiplexerStatus
from aea.protocols.base import Message
from aea.protocols.dialogue.base import Dialogue, Dialogues
from aea.registries.resources import Resources
from aea.skills.base import (
    Behaviour,
    Handler,
    Model,
    Skill,
    SkillComponent,
    SkillContext,
    _SkillComponentLoader,
    _print_warning_message_for_non_declared_skill_components,
)
from aea.test_tools.test_cases import BaseAEATestCase

from tests.conftest import CUR_PATH, ROOT_DIR, _make_dummy_connection


class BaseTestSkillContext:
    """Test the skill context."""

    @classmethod
    def setup_class(cls, decision_maker_handler_class=None):
        """Test the initialisation of the AEA."""
        cls.wallet = Wallet(
            {
                FetchAICrypto.identifier: FETCHAI_PRIVATE_KEY_PATH,
                EthereumCrypto.identifier: ETHEREUM_PRIVATE_KEY_PATH,
            }
        )
        cls.connection = _make_dummy_connection()
        resources = Resources()
        resources.add_connection(cls.connection)
        cls.identity = Identity(
            "name",
            addresses=cls.wallet.addresses,
            public_keys=cls.wallet.public_keys,
            default_address_key=FetchAICrypto.identifier,
        )
        cls.my_aea = AEA(
            cls.identity,
            cls.wallet,
            data_dir=MagicMock(),
            resources=resources,
            decision_maker_handler_class=decision_maker_handler_class,
        )

        cls.skill_context = SkillContext(
            cls.my_aea.context, skill=MagicMock(contracts={})
        )

    def test_agent_name(self):
        """Test the agent's name."""
        assert self.skill_context.agent_name == self.my_aea.name

    def test_agent_addresses(self):
        """Test the agent's addresses."""
        assert self.skill_context.agent_addresses == self.my_aea.identity.addresses

    def test_agent_public_keys(self):
        """Test the agent's public_keys."""
        assert self.skill_context.public_keys == self.my_aea.identity.public_keys

    def test_agent_address(self):
        """Test the default agent's address."""
        assert self.skill_context.agent_address == self.my_aea.identity.address

    def test_agent_public_key(self):
        """Test the default agent's public_key."""
        assert self.skill_context.public_key == self.my_aea.identity.public_key

    def test_connection_status(self):
        """Test the default agent's connection status."""
        assert isinstance(self.skill_context.connection_status, MultiplexerStatus)

    def test_decision_maker_message_queue(self):
        """Test the decision maker's queue."""
        assert isinstance(self.skill_context.decision_maker_message_queue, Queue)

    def test_decision_maker_handler_context(self):
        """Test the decision_maker_handler_context."""
        assert isinstance(
            self.skill_context.decision_maker_handler_context,
            SimpleNamespace,
        )

    def test_storage(self):
        """Test the agent's storage."""
        assert self.skill_context.storage is None

    def test_message_in_queue(self):
        """Test the 'message_in_queue' property."""
        assert isinstance(self.skill_context.message_in_queue, Queue)

    def test_logger_setter(self):
        """Test the logger setter."""
        logger = self.skill_context.logger
        self.skill_context._logger = None
        self.skill_context.logger = logger
        assert self.skill_context.logger == logger

    def test_agent_context_setter(self):
        """Test the agent context setter."""
        agent_context = self.skill_context._agent_context
        self.skill_context.set_agent_context(agent_context)
        assert self.skill_context.agent_name == agent_context.agent_name
        assert self.skill_context.agent_address == agent_context.address
        assert self.skill_context.agent_addresses == agent_context.addresses

    def test_is_active_property(self):
        """Test is_active property getter."""
        assert self.skill_context.is_active is True

    def test_new_behaviours_queue(self):
        """Test 'new_behaviours_queue' property getter."""
        assert isinstance(self.skill_context.new_behaviours, Queue)

    def test_new_handlers_queue(self):
        """Test 'new_behaviours_queue' property getter."""
        assert isinstance(self.skill_context.new_handlers, Queue)

    def test_search_service_address(self):
        """Test 'search_service_address' property getter."""
        assert (
            self.skill_context.search_service_address
            == self.my_aea.context.search_service_address
        )

    def test_decision_maker_address(self):
        """Test 'decision_maker_address' property getter."""
        assert (
            self.skill_context.decision_maker_address
            == self.my_aea.context.decision_maker_address
        )

    def test_default_ledger_id(self):
        """Test 'default_ledger_id' property getter."""
        assert (
            self.skill_context.default_ledger_id
            == self.my_aea.context.default_ledger_id
        )

    def test_currency_denominations(self):
        """Test 'currency_denominations' property getter."""
        assert (
            self.skill_context.currency_denominations
            == self.my_aea.context.currency_denominations
        )

    def test_namespace(self):
        """Test the 'namespace' property getter."""
        assert isinstance(self.skill_context.namespace, SimpleNamespace)

    def test_send_to_skill(self):
        """Test the send_to_skill method."""
        with unittest.mock.patch.object(
            self.my_aea.context, "_send_to_skill", return_value=None
        ):
            self.skill_context.send_to_skill("envelope", "context")

    @classmethod
    def teardown_class(cls):
        """Test teardown."""
        pass


class TestSkillContextDefault(BaseTestSkillContext):
    """Test skill context with default dm."""

    @pytest.mark.parametrize("flag", (True, False))
    def test_is_abstract(self, flag: bool):
        """Test the `is_abstract` property."""
        skill_context = SkillContext(
            MagicMock(),
            Skill(
                SkillConfig("test_name", "test_author", is_abstract=flag), MagicMock()
            ),
        )
        assert skill_context.is_abstract_component is flag


class SkillContextTestCase(TestCase):
    """Test case for SkillContext class."""

    @staticmethod
    def test_data_dir():
        """Test data_dir property."""
        agent_context = mock.Mock()
        agent_context.data_dir = "path"
        obj = SkillContext(agent_context)
        assert obj.data_dir == "path"

    def test_shared_state_positive(self):
        """Test shared_state property positive result"""
        agent_context = mock.Mock()
        agent_context.shared_state = "shared_state"
        obj = SkillContext(agent_context)
        obj.shared_state

    def test_skill_id_positive(self):
        """Test skill_id property positive result"""
        obj = SkillContext("agent_context")
        obj._skill = mock.Mock()
        obj._skill.config = mock.Mock()
        obj._skill.config.public_id = "public_id"
        obj.skill_id

    @mock.patch("aea.skills.base._default_logger.debug")
    @mock.patch("aea.skills.base.SkillContext.skill_id")
    def test_is_active_positive(self, skill_id_mock, debug_mock):
        """Test is_active setter positive result"""
        obj = SkillContext("agent_context")
        obj.is_active = "value"
        debug_mock.assert_called_once()

    def test_task_manager_positive(self):
        """Test task_manager property positive result"""
        agent_context = mock.Mock()
        agent_context.task_manager = "task_manager"
        obj = SkillContext(agent_context)
        with self.assertRaises(ValueError):
            obj.task_manager
        obj._skill = mock.Mock()
        obj.task_manager

    @mock.patch("aea.skills.base.SimpleNamespace")
    def test_handlers_positive(self, *mocks):
        """Test handlers property positive result"""
        obj = SkillContext("agent_context")
        with self.assertRaises(ValueError):
            obj.handlers
        obj._skill = mock.Mock()
        obj._skill.handlers = {}
        obj.handlers

    @mock.patch("aea.skills.base.SimpleNamespace")
    def test_behaviours_positive(self, *mocks):
        """Test behaviours property positive result"""
        obj = SkillContext("agent_context")
        with self.assertRaises(ValueError):
            obj.behaviours
        obj._skill = mock.Mock()
        obj._skill.behaviours = {}
        obj.behaviours

    def test_logger_positive(self):
        """Test logger property positive result"""
        obj = SkillContext("agent_context")
        obj.logger
        obj._logger = mock.Mock()
        obj.logger


class SkillComponentTestCase(TestCase):
    """Test case for SkillComponent class."""

    def setUp(self):
        """Set the test up."""

        class TestComponent(SkillComponent):
            """Test class for SkillComponent"""

            def parse_module(self, *args):
                """Parse module."""
                pass

            def setup(self, *args):
                """Set up."""
                pass

            def teardown(self, *args):
                """Tear down."""
                pass

        self.TestComponent = TestComponent

    def test_init_no_ctx(self):
        """Test init method no context provided."""

        with self.assertRaises(ValueError):
            self.TestComponent(name="some_name", skill_context=None)
        with self.assertRaises(ValueError):
            self.TestComponent(name=None, skill_context="skill_context")

    def test_skill_id_positive(self):
        """Test skill_id property positive."""
        ctx = mock.Mock()
        ctx.skill_id = "skill_id"
        component = self.TestComponent(
            name="name", skill_context=ctx, configuration=Mock()
        )
        component.skill_id

    def test_config_positive(self):
        """Test config property positive."""
        component = self.TestComponent(
            configuration=Mock(args={}), skill_context="ctx", name="name"
        )
        component.config

    def test_kwargs_not_empty(self):
        """Test the case when there are some kwargs not-empty"""
        kwargs = dict(foo="bar")
        component_name = "component_name"
        skill_context = SkillContext()
        with mock.patch.object(skill_context.logger, "warning") as mock_logger:
            self.TestComponent(component_name, skill_context, **kwargs)
            mock_logger.assert_any_call(
                f"The kwargs={kwargs} passed to {component_name} have not been set!"
            )


def test_load_skill():
    """Test the loading of a skill."""
    agent_context = MagicMock(agent_name="name")
    skill = Skill.from_dir(
        Path(ROOT_DIR, "tests", "data", "dummy_skill"), agent_context=agent_context
    )
    assert isinstance(skill, Skill)


def test_compute_module_dotted_path_for_init_py_returns_skill_dotted_path():
    """The skill's own `__init__.py` maps to `self.skill_dotted_path` exactly.

    `load_aea_package` registers the skill's `__init__.py` under
    ``packages.<a>.skills.<n>`` (no trailing ``.__init__`` suffix). The
    loader must compute that same key so its subsequent `load_module`
    call cache-hits and does NOT re-execute the file — re-execution
    would create a second module object with duplicate class
    identities, the dual-class-object problem the loader is built to
    avoid. Discovery of components defined directly in `__init__.py`
    is preserved because the cached module is still inspected via
    `inspect.getmembers`.
    """
    loader = _make_skill_component_loader_for_dummy_skill()
    assert (
        loader._compute_module_dotted_path(Path("__init__.py"))
        == loader.skill_dotted_path
    )
    # Subpackage __init__.py uses the subpackage name with no further suffix.
    assert (
        loader._compute_module_dotted_path(Path("subpkg") / "__init__.py")
        == f"{loader.skill_dotted_path}.subpkg"
    )
    # Depth-2 nested subpackage joins every parent directory.
    assert (
        loader._compute_module_dotted_path(Path("subpkg") / "inner" / "__init__.py")
        == f"{loader.skill_dotted_path}.subpkg.inner"
    )


def test_skill_loader_reuses_load_aea_package_module_for_init_py():
    """The AEA loader must not re-execute the skill's `__init__.py`.

    After ``load_aea_package`` registers the skill's `__init__.py` in
    sys.modules at ``self.skill_dotted_path``, the subsequent
    ``load_module`` call for that same file must cache-hit and return
    the already-registered module — not execute the file a second time
    and create duplicate class objects.
    """
    import sys

    from aea.components.base import perform_load_aea_package
    from aea.helpers.base import load_module

    loader = _make_skill_component_loader_for_dummy_skill()
    skill_dotted_path = loader.skill_dotted_path
    init_py = loader.skill_directory / "__init__.py"

    sys.modules.pop(skill_dotted_path, None)
    perform_load_aea_package(
        loader.skill_directory,
        loader.configuration.public_id.author,
        "skills",
        loader.configuration.public_id.name,
    )
    pre = sys.modules[skill_dotted_path]
    sentinel = object()
    pre._b3_sentinel = sentinel  # type: ignore[attr-defined]
    try:
        post = load_module(skill_dotted_path, init_py)
        assert post is pre, "load_module re-executed the skill's __init__.py"
        assert (
            getattr(post, "_b3_sentinel", None) is sentinel
        ), "sentinel lost: a fresh module object was created"
    finally:
        sys.modules.pop(skill_dotted_path, None)


def test_load_skill_components_have_canonical_module_paths():
    """Loaded skill component classes carry the long packages-prefixed __module__.

    The skill loader assigns ``packages.<author>.skills.<name>.<file>`` as
    the module dotted path. Beyond the prefix check, the class object the
    loader produced must be **identity-equal** to the class resolved via
    ``importlib.import_module(__module__)`` — that's the user-facing
    contract this PR establishes: a single class object per source file,
    so e.g. open-autonomy's ``_MetaPayload.registry`` shrinks from two
    entries (short + long) to one. A regression that re-executed the
    file would stamp the same ``__module__`` on a duplicate class and
    pass a prefix-only assertion; the identity check rejects it.
    """
    import importlib

    agent_context = MagicMock(agent_name="name")
    skill = Skill.from_dir(
        Path(ROOT_DIR, "tests", "data", "dummy_skill"), agent_context=agent_context
    )
    expected_prefix = "packages.dummy_author.skills.dummy."
    for component in list(skill.behaviours.values()) + list(skill.handlers.values()):
        cls = type(component)
        assert cls.__module__.startswith(expected_prefix), (
            f"{cls.__name__} has __module__={cls.__module__!r}, expected "
            f"to start with {expected_prefix!r}"
        )
        resolved = getattr(importlib.import_module(cls.__module__), cls.__name__)
        assert resolved is cls, (
            f"{cls.__name__} loaded by the skill loader is not "
            f"identity-equal to the class resolvable via "
            f"importlib.import_module({cls.__module__!r}) — "
            "re-execution / duplicate-class regression."
        )


def test_load_module_registers_in_sys_modules():
    """``load_module`` puts the loaded module in sys.modules under its dotted path."""
    import sys

    from aea.helpers.base import load_module

    dotted_path = "tests.data.dummy_skill.behaviours_b3_smoke"
    filepath = Path(ROOT_DIR, "tests", "data", "dummy_skill", "behaviours.py")
    sys.modules.pop(dotted_path, None)
    try:
        module = load_module(dotted_path, filepath)
        assert sys.modules.get(dotted_path) is module
    finally:
        sys.modules.pop(dotted_path, None)


def test_load_module_pops_sys_modules_on_exec_failure(tmp_path):
    """If `exec_module` raises, the broken stub is removed from sys.modules.

    Without rollback, a transient module-level error (syntax error, missing
    env var at import time, etc.) permanently poisons sys.modules with a
    half-initialised stub. Subsequent imports for the same dotted path
    would then return the broken object rather than retrying the load.
    """
    import sys

    from aea.helpers.base import load_module

    broken = tmp_path / "broken.py"
    broken.write_text("raise RuntimeError('boom at import time')\n")
    dotted_path = "tests_b3_broken_module"
    sys.modules.pop(dotted_path, None)
    try:
        with pytest.raises(RuntimeError, match="boom at import time"):
            load_module(dotted_path, broken)
        assert (
            dotted_path not in sys.modules
        ), "load_module must roll back its sys.modules entry on exec failure"
    finally:
        sys.modules.pop(dotted_path, None)


def test_load_module_reuses_cached_module_for_same_dotted_path(tmp_path):
    """`load_module` reuses any module already cached at the dotted path.

    Whether the second call points at the same physical file or a
    different one (e.g. a vendor copy in a tmpdir vs the source tree
    in test fixtures), `load_module` returns the cached object — never
    re-executes. Re-execution would create duplicate class objects
    for callers that already hold references to the original
    definitions (e.g. via an earlier ``from ... import X``). Mirrors
    Python's own import semantics: once registered, the cached module
    is canonical for that dotted path.
    """
    import sys

    from aea.helpers.base import load_module

    same_src = tmp_path / "cached_source.py"
    same_src.write_text("class Marker:\n    pass\n")
    other_src = tmp_path / "different_source.py"
    other_src.write_text("class Other:\n    pass\n")

    dotted_path = "tests_b3_cache_reuse"
    sys.modules.pop(dotted_path, None)
    try:
        first = load_module(dotted_path, same_src)
        first_marker = first.Marker  # type: ignore[attr-defined]

        # Same file → reuse.
        second = load_module(dotted_path, same_src)
        assert second is first, "load_module re-executed for the same file"
        assert second.Marker is first_marker  # type: ignore[attr-defined]

        # Different file at the same dotted path → still reuse the
        # cached module. ``Marker`` survives; ``Other`` is NOT defined
        # on the returned module because the second source was never
        # executed.
        third = load_module(dotted_path, other_src)
        assert third is first, (
            "load_module re-executed when the cached dotted path was "
            "called with a different physical file"
        )
        assert hasattr(third, "Marker")
        assert not hasattr(third, "Other")
    finally:
        sys.modules.pop(dotted_path, None)


def test_load_module_raises_import_error_on_explicit_none_block_sentinel(
    tmp_path,
):
    """An explicit ``sys.modules[key] = None`` raises ``ImportError``.

    ``None`` is CPython's block-import sentinel. `load_module` mirrors
    standard import semantics: it raises ``ImportError`` rather than
    overwriting the sentinel with a fresh exec, and the sentinel
    survives the failed call so the caller's deliberate block stays
    in place.
    """
    import sys

    from aea.helpers.base import load_module

    src = tmp_path / "should_not_be_loaded.py"
    src.write_text("class Marker:\n    pass\n")
    dotted_path = "tests_b3_block_import_sentinel"

    sys.modules[dotted_path] = None  # type: ignore[assignment]
    try:
        with pytest.raises(ImportError, match="None in sys.modules"):
            load_module(dotted_path, src)
        assert (
            dotted_path in sys.modules
        ), "load_module unexpectedly removed the explicit-None prior"
        assert sys.modules[dotted_path] is None
    finally:
        sys.modules.pop(dotted_path, None)


def test_load_module_resolves_via_sys_modules_on_re_import():
    """A normal `import` of the just-loaded dotted path returns the same object.

    The skill loader pre-loads parent `__init__.py` files and then calls
    ``load_module`` for individual files (`behaviours.py`, etc.). Without the
    sys.modules write, a subsequent ``from packages.X.skills.Y.foo import Bar``
    would re-execute `foo.py` and produce a second copy of every class. With
    the write, the import is a cache hit.
    """
    import importlib
    import sys

    agent_context = MagicMock(agent_name="name")
    Skill.from_dir(
        Path(ROOT_DIR, "tests", "data", "dummy_skill"), agent_context=agent_context
    )
    canonical = "packages.dummy_author.skills.dummy.behaviours"
    assert canonical in sys.modules, sorted(
        k for k in sys.modules if k.startswith("packages.dummy_author.")
    )
    cached = sys.modules[canonical]
    assert importlib.import_module(canonical) is cached


def _make_skill_component_loader_for_dummy_skill():
    """Construct a fully-initialised `_SkillComponentLoader` for the dummy fixture.

    Uses the normal `__init__` path so every invariant the production loader
    relies on (including `skill_directory` and `skill_dotted_path`) is set
    consistently — tests that touch private methods through this loader will
    survive future refactors that read additional state from `self`.
    """
    skill_dir = Path(ROOT_DIR, "tests", "data", "dummy_skill")
    configuration = load_component_configuration(
        ComponentType.SKILL, skill_dir, skip_consistency_check=True
    )
    configuration._directory = skill_dir  # pylint: disable=protected-access
    skill_context = MagicMock()
    return _SkillComponentLoader(configuration, skill_context)


def test_parse_module_preserves_subpackage_path_in_dotted_key(tmp_path, monkeypatch):
    """`_parse_module`'s dotted key matches the main loader for subpackages.

    A flat file produces the same key under both paths trivially; a
    subpackage file diverges if `_parse_module` drops parent
    directories. Drives through a real `SkillContext` + `Skill` (not a
    `MagicMock`) so the production attribute path —
    ``skill_context._skill.configuration.directory`` — is exercised.
    A regression on that path would auto-vivify on a Mock and silently
    pass; here it surfaces.
    """
    skill_root = tmp_path / "myskill"
    (skill_root / "subpkg").mkdir(parents=True)
    behaviour_file = skill_root / "subpkg" / "behaviours.py"
    behaviour_file.write_text("# stub\n")

    captured = {}

    def fake_load_module(dotted_path, *_args, **_kwargs):
        captured["dotted_path"] = dotted_path
        return types.ModuleType("fake")

    monkeypatch.setattr("aea.skills.base.load_module", fake_load_module)

    configuration = SkillConfig(name="myskill", author="dummy_author")
    configuration._directory = skill_root  # pylint: disable=protected-access
    skill = Skill(configuration=configuration)

    try:
        Behaviour.parse_module(
            behaviour_file,
            {"b": SkillComponentConfiguration("FakeBehaviour")},
            skill.skill_context,
        )
    except Exception:  # pragma: nocover
        pass

    assert captured["dotted_path"] == (
        "packages.dummy_author.skills.myskill.subpkg.behaviours"
    ), (
        "legacy parse_module path must preserve subpackage parents in the "
        f"dotted key; got {captured['dotted_path']!r}."
    )


def test_parse_module_keys_by_file_stem_not_type_plural(tmp_path, monkeypatch):
    """`_parse_module` keys the loaded module by the file stem.

    A custom skill may have a `strategy.py` parsed via `Model.parse_module`.
    `_compute_module_dotted_path` would key it under
    ``packages.<a>.skills.<n>.strategy``. If `_parse_module` keyed instead
    by the plural type-name (``models``) the two cache entries would
    diverge and reintroduce the dual-module-object problem this PR
    eliminates.
    """
    captured = {}

    class _DummyModel(Model):
        def __init__(self, **kwargs):  # pragma: nocover
            pass

    _DummyModel.__module__ = "packages.dummy_author.skills.dummy.strategy"
    fake_module = types.ModuleType("fake_strategy")
    fake_module.S = _DummyModel  # type: ignore[attr-defined]

    def fake_load_module(dotted_path, *_args, **_kwargs):
        captured["dotted_path"] = dotted_path
        return fake_module

    monkeypatch.setattr("aea.skills.base.load_module", fake_load_module)

    strategy_file = tmp_path / "strategy.py"
    strategy_file.write_text("# stub\n")

    skill_context = MagicMock()
    skill_context.skill_id = PublicId.from_str("dummy_author/dummy:0.1.0")

    Model.parse_module(
        strategy_file,
        {"s": SkillComponentConfiguration("S")},
        skill_context,
    )
    assert captured["dotted_path"] == ("packages.dummy_author.skills.dummy.strategy"), (
        "Legacy parse_module path must key its load_module call by the "
        f"file stem to match _compute_module_dotted_path. Got "
        f"{captured['dotted_path']!r}."
    )


def test_parse_module_keeps_classes_under_canonical_long_path(tmp_path, monkeypatch):
    """The legacy `_parse_module` path keeps this skill's own classes.

    After `_parse_module` was switched to call `load_module` with the canonical
    long dotted path (`packages.<author>.skills.<name>.<file>`), classes
    defined in the loaded module carry that long `__module__`. The old
    "exclude classes whose `__module__` starts with this skill's path"
    clause — present in the legacy filter before this PR — would now wrongly
    drop them. This test pins the filter alignment with `_filter_classes`.
    """

    class _LocalBehaviour(Behaviour):
        def setup(self):  # pragma: nocover
            pass

        def act(self):  # pragma: nocover
            pass

        def teardown(self):  # pragma: nocover
            pass

    # __module__ matches the dotted path `_parse_module` now computes for
    # this skill's `behaviours.py`. A class loaded by the real `load_module`
    # under that name would observe exactly this value.
    _LocalBehaviour.__module__ = "packages.local_author.skills.local.behaviours"

    import types as types_module

    fake_module = types_module.ModuleType("fake_behaviours")
    fake_module.LocalBehaviour = _LocalBehaviour  # type: ignore[attr-defined]

    monkeypatch.setattr("aea.skills.base.load_module", lambda *_a, **_k: fake_module)

    behaviour_file = tmp_path / "behaviours.py"
    behaviour_file.write_text("# stub\n")

    skill_context = MagicMock()
    skill_context.skill_id = PublicId.from_str("local_author/local:0.1.0")

    result = Behaviour.parse_module(
        behaviour_file,
        {"local_b": SkillComponentConfiguration("LocalBehaviour")},
        skill_context,
    )
    assert "local_b" in result, (
        "the legacy parse_module path dropped a class loaded under the "
        f"canonical long dotted path; got {sorted(result.keys())}"
    )
    assert isinstance(result["local_b"], _LocalBehaviour)


def test_unused_class_warning_includes_init_py_level_components():
    """The unused-class warning fires for `__init__.py`-level components.

    `SkillComponent` subclasses defined at the skill's ``__init__.py`` level
    have ``__module__`` equal to ``self.skill_dotted_path`` exactly, with no
    trailing dot. Without the exact-match clause they would be silently
    filtered out and the "found but not declared" warning would never fire.
    """

    class _InitPyHandler(Handler):
        def setup(self):  # pragma: nocover
            pass

        def handle(self, message):  # pragma: nocover
            pass

        def teardown(self):  # pragma: nocover
            pass

    loader = _make_skill_component_loader_for_dummy_skill()
    # Pin __module__ to the skill's dotted path exactly — the shape a class
    # defined directly in `packages/<a>/skills/<n>/__init__.py` would have.
    _InitPyHandler.__module__ = loader.skill_dotted_path

    init_py_path = Path(loader.skill_directory, "__init__.py")
    loader._print_warning_message_for_unused_classes(
        component_classes_by_path={
            init_py_path: {("_InitPyHandler", _InitPyHandler)},
        },
        used_classes=set(),
    )
    warnings = [
        call.args[0] for call in loader.skill_context.logger.warning.call_args_list
    ]
    assert any(
        "_InitPyHandler" in msg for msg in warnings
    ), f"Expected a warning mentioning the __init__.py-level class; got {warnings!r}"


def test_load_skill_filter_keeps_cross_skill_re_exports():
    """Cross-skill re-exports survive `_filter_classes`.

    SkillComponent subclasses whose ``__module__`` points at another skill —
    the canonical FSM composition idiom where a skill re-exports a parent's
    ``AbciDialogues`` / ``HttpHandler`` etc. as its own — must be kept.
    """

    class _ForeignHandler(Handler):
        """A Handler whose __module__ belongs to a different skill."""

        def setup(self):  # pragma: nocover
            pass

        def handle(self, message):  # pragma: nocover
            pass

        def teardown(self):  # pragma: nocover
            pass

    # Simulate the cross-skill re-export: the class was defined in another
    # skill's package, but `getmembers` on the composing skill's module
    # surfaces it via a top-level import.
    _ForeignHandler.__module__ = "packages.dummy_author.skills.parent.handlers"

    loader = _make_skill_component_loader_for_dummy_skill()
    kept = loader._filter_classes([("AbciHandler", _ForeignHandler)])
    assert kept == [("AbciHandler", _ForeignHandler)], (
        "Cross-skill re-exports must survive the filter; composition skills "
        "rely on this to bind a parent skill's Handler as their own."
    )


def test_behaviour():
    """Test behaviour initialization."""

    class CustomBehaviour(Behaviour):
        def setup(self) -> None:
            pass

        def teardown(self) -> None:
            pass

        def act(self) -> None:
            pass

    behaviour = CustomBehaviour("behaviour", skill_context=MagicMock())

    # test getters (default values)
    assert behaviour.tick_interval == 0.001
    assert behaviour.start_at is None
    assert behaviour.is_done() is False


def test_behaviour_parse_module_without_configs():
    """Call Behaviour.parse_module without configurations."""
    assert Behaviour.parse_module(MagicMock(), {}, MagicMock()) == {}


def test_behaviour_parse_module_missing_class():
    """Test Behaviour.parse_module when a class is missing."""
    skill_context = SkillContext(
        skill=MagicMock(skill_id=PublicId.from_str("author/name:0.1.0"))
    )
    dummy_behaviours_path = Path(
        ROOT_DIR, "tests", "data", "dummy_skill", "behaviours.py"
    )
    with unittest.mock.patch.object(
        aea.skills.base._default_logger, "warning"
    ) as mock_logger_warning:
        behaviours_by_id = Behaviour.parse_module(
            dummy_behaviours_path,
            {
                "dummy_behaviour": SkillComponentConfiguration("DummyBehaviour"),
                "unknown_behaviour": SkillComponentConfiguration("UnknownBehaviour"),
            },
            skill_context,
        )
        mock_logger_warning.assert_called_with(
            "Behaviour 'UnknownBehaviour' cannot be found."
        )
        assert "dummy_behaviour" in behaviours_by_id


def test_handler_parse_module_without_configs():
    """Call Handler.parse_module without configurations."""
    assert Handler.parse_module(MagicMock(), {}, MagicMock()) == {}


def test_handler_parse_module_missing_class():
    """Test Handler.parse_module when a class is missing."""
    skill_context = SkillContext(
        skill=MagicMock(skill_id=PublicId.from_str("author/name:0.1.0"))
    )
    dummy_handlers_path = Path(ROOT_DIR, "tests", "data", "dummy_skill", "handlers.py")
    with unittest.mock.patch.object(
        aea.skills.base._default_logger, "warning"
    ) as mock_logger_warning:
        behaviours_by_id = Handler.parse_module(
            dummy_handlers_path,
            {
                "dummy_handler": SkillComponentConfiguration("DummyHandler"),
                "unknown_handelr": SkillComponentConfiguration("UnknownHandler"),
            },
            skill_context,
        )
        mock_logger_warning.assert_called_with(
            "Handler 'UnknownHandler' cannot be found."
        )
        assert "dummy_handler" in behaviours_by_id


def test_model_parse_module_without_configs():
    """Call Model.parse_module without configurations."""
    assert Model.parse_module(MagicMock(), {}, MagicMock()) == {}


def test_model_parse_module_missing_class():
    """Test Model.parse_module when a class is missing."""
    skill_context = SkillContext(
        skill=MagicMock(skill_id=PublicId.from_str("author/name:0.1.0"))
    )
    dummy_models_path = Path(ROOT_DIR, "tests", "data", "dummy_skill", "dummy.py")
    with unittest.mock.patch.object(
        aea.skills.base._default_logger, "warning"
    ) as mock_logger_warning:
        models_by_id = Model.parse_module(
            dummy_models_path,
            {
                "dummy_model": SkillComponentConfiguration("DummyModel"),
                "unknown_model": SkillComponentConfiguration("UnknownModel"),
            },
            skill_context,
        )
        mock_logger_warning.assert_called_with("Model 'UnknownModel' cannot be found.")
        assert "dummy_model" in models_by_id


def test_print_warning_message_for_non_declared_skill_components():
    """Test the helper function '_print_warning_message_for_non_declared_skill_components'."""
    with unittest.mock.patch.object(
        aea.skills.base._default_logger, "warning"
    ) as mock_logger_warning:
        _print_warning_message_for_non_declared_skill_components(
            SkillContext(),
            {"unknown_class_1", "unknown_class_2"},
            set(),
            "type",
            "path",
        )
        mock_logger_warning.assert_any_call(
            "Class unknown_class_1 of type type found in skill module path but not declared in the configuration file."
        )
        mock_logger_warning.assert_any_call(
            "Class unknown_class_2 of type type found in skill module path but not declared in the configuration file."
        )


class TestSkill:
    """Test skill attributes."""

    @classmethod
    def setup_class(cls):
        """Set the tests up."""
        cls.skill = Skill.from_dir(
            Path(ROOT_DIR, "tests", "data", "dummy_skill"),
            MagicMock(agent_name="agent_name"),
        )

    def test_logger(self):
        """Test the logger getter."""
        self.skill.logger

    def test_logger_setter_raises_error(self):
        """Test that the logger setter raises error."""
        with pytest.raises(ValueError, match="Cannot set logger to a skill component."):
            logger = self.skill.logger
            self.skill.logger = logger

    def test_skill_context(self):
        """Test the skill context getter."""
        context = self.skill.skill_context
        assert isinstance(context, SkillContext)


class TestSkillProgrammatic:
    """Test skill attributes."""

    @classmethod
    def setup_class(cls):
        """Set the tests up."""
        skill_context = SkillContext()
        skill_config = SkillConfig(
            name="simple_skill", author="fetchai", version="0.1.0"
        )

        class MyHandler(Handler):
            def setup(self):
                pass

            def handle(self, message: Message):
                pass

            def teardown(self):
                pass

        class MyBehaviour(Behaviour):
            def setup(self):
                pass

            def act(self):
                pass

            def teardown(self):
                pass

        cls.handler_name = "some_handler"
        cls.handler = MyHandler(skill_context=skill_context, name=cls.handler_name)
        cls.model_name = "some_model"
        cls.model = Model(skill_context=skill_context, name=cls.model_name)
        cls.behaviour_name = "some_behaviour"
        cls.behaviour = MyBehaviour(
            skill_context=skill_context, name=cls.behaviour_name
        )
        cls.skill = Skill(
            skill_config,
            skill_context,
            handlers={cls.handler.name: cls.handler},
            models={cls.model.name: cls.model},
            behaviours={cls.behaviour.name: cls.behaviour},
        )

    def test_behaviours(self):
        """Test the behaviours getter on skill context."""
        assert (
            getattr(self.skill.skill_context.behaviours, self.behaviour_name, None)
            == self.behaviour
        )

    def test_handlers(self):
        """Test the handlers getter on skill context."""
        assert (
            getattr(self.skill.skill_context.handlers, self.handler_name, None)
            == self.handler
        )

    def test_models(self):
        """Test the handlers getter on skill context."""
        assert getattr(self.skill.skill_context, self.model_name, None) == self.model

    def test_protocol_dialogues(self):
        """Test the retrieving protocol dialogues via handler"""
        error_message = f"SUPPORTED_PROTOCOL not set on {self.handler}"
        with pytest.raises(ValueError, match=error_message):
            self.handler.protocol_dialogues()

        protocol = PublicId.from_str("open_aea/simple_skill:0.1.0")
        self.handler.SUPPORTED_PROTOCOL = protocol
        error_message = "'SkillContext' object has no attribute "
        with pytest.raises(AttributeError, match=error_message):
            self.handler.protocol_dialogues()


class TestHandlerHandleExceptions:
    """Test exceptions in the handle wrapper."""

    @classmethod
    def setup_class(cls):
        """Setup test class."""

        class StandardExceptionHandler(Handler):
            def setup(self):
                pass

            def handle(self, message: Message):
                raise ValueError("expected")

            def teardown(self):
                pass

        cls.handler = StandardExceptionHandler(skill_context=mock.Mock(), name="name")

    def test_handler_standard_exception(self):
        """Test the handler exception."""
        with pytest.raises(AEAHandleException):
            with pytest.raises(ValueError):
                self.handler.handle_wrapper("msg")

    def test_handler_stop_exception(self):
        """Test the handler exception."""
        with pytest.raises(_StopRuntime):
            with mock.patch.object(self.handler, "handle", side_effect=_StopRuntime()):
                self.handler.handle_wrapper("msg")


class DefaultDialogues(Model, Dialogues):
    """The dialogues class keeps track of all dialogues."""

    def __init__(self, **kwargs) -> None:
        """
        Initialize dialogues.

        :return: None
        """
        Model.__init__(self, **kwargs)

        def role_from_first_message(  # pylint: disable=unused-argument
            message: Message, receiver_address: Address
        ) -> Dialogue.Role:
            """Infer the role of the agent from an incoming/outgoing first message

            :param message: an incoming/outgoing first message
            :param receiver_address: the address of the receiving agent
            :return: The role of the agent
            """
            return 1  # type: ignore

        Dialogues.__init__(
            self,
            self_address=self.context.agent_name,
            end_states=[Mock()],  # type: ignore
            message_class=Message,
            dialogue_class=Dialogue,
            role_from_first_message=role_from_first_message,
        )


def test_model_dialogues_keep_terminal_dialogues_option():
    """Test Model Dialogues class."""
    dialogues = DefaultDialogues(name="test", skill_context=Mock())
    assert (
        DefaultDialogues._keep_terminal_state_dialogues
        == dialogues.is_keep_dialogues_in_terminal_state
    )

    dialogues = DefaultDialogues(
        name="test", skill_context=Mock(), keep_terminal_state_dialogues=True
    )
    assert dialogues.is_keep_dialogues_in_terminal_state is True
    assert (
        DefaultDialogues._keep_terminal_state_dialogues
        == Dialogues._keep_terminal_state_dialogues
    )

    dialogues = DefaultDialogues(
        name="test", skill_context=Mock(), keep_terminal_state_dialogues=False
    )
    assert dialogues.is_keep_dialogues_in_terminal_state is False
    assert (
        DefaultDialogues._keep_terminal_state_dialogues
        == Dialogues._keep_terminal_state_dialogues
    )


def test_setup_teardown_methods():
    """Test skill etup/teardown methods with proper super() calls."""

    def role_from_first_message(  # pylint: disable=unused-argument
        message: Message, receiver_address: Address
    ) -> Dialogue.Role:
        return None  # type: ignore

    class Test(Model, Dialogues):
        def __init__(self, name, skill_context):
            Model.__init__(self, name, skill_context)
            Dialogues.__init__(
                self, "addr", MagicMock(), Message, Dialogue, role_from_first_message
            )

        def setup(self) -> None:
            super().setup()

        def teardown(self) -> None:
            super().teardown()

    skill_context = MagicMock()
    skill_context.skill_id = PublicId("test", "test", "1.0.1")
    t = Test(name="test", skill_context=skill_context)

    with patch.object(t._dialogues_storage, "setup") as mock_setup, patch.object(
        t._dialogues_storage, "teardown"
    ) as mock_teardown:
        t.setup()
        t.teardown()

    mock_setup.assert_called_once()
    mock_teardown.assert_called_once()


class TestSkillLoadingWarningMessages(BaseAEATestCase):
    """
    Test warning message in case undeclared skill are found.

    That is:
    - copy dummy_aea in a temporary directory
    - add a skill module with two skill components
      - one that has 'is_programmatically_defined' set to False
      - one that has 'is_programmatically_defined' set to True
    - test that we have a warning message only from the first.
    """

    agent_name = "dummy_aea"

    cli_log_options = ["-v", "DEBUG"]
    _TEST_HANDLER_CLASS_NAME = "TestHandler"
    _TEST_BEHAVIOUR_CLASS_NAME = "TestBehaviour"

    _test_skill_module_path = "skill_module_for_testing.py"
    _test_skill_module_content = dedent(f"""
    from aea.skills.base import Behaviour, Handler

    class {_TEST_HANDLER_CLASS_NAME}(Handler):

        is_programmatically_defined = False

        def setup(self):
            pass
        def handle(self, message):
            pass
        def teardown(self):
            pass

    class {_TEST_BEHAVIOUR_CLASS_NAME}(Behaviour):

        is_programmatically_defined = True

        def setup(self):
            pass
        def act(self):
            pass
        def teardown(self):
            pass
    """)

    @classmethod
    def setup_class(cls):
        """Set up the test."""
        super().setup_class()
        path_to_aea = Path(CUR_PATH, "data", "dummy_aea")
        shutil.copytree(path_to_aea, cls.t / cls.agent_name)

        # add a module in 'dummy' skill with a Handler and a Behaviour
        dummy_skill_path = cls.t / cls.agent_name / "skills" / "dummy"
        (dummy_skill_path / cls._test_skill_module_path).write_text(
            cls._test_skill_module_content
        )
        skill_config = load_component_configuration(
            ComponentType.SKILL, dummy_skill_path, skip_consistency_check=True
        )
        skill_config._directory = dummy_skill_path

        cls.skill_context_mock = MagicMock()
        cls.skill_component_loader = _SkillComponentLoader(
            skill_config, cls.skill_context_mock
        )

        # load the skill - it will trigger the warning messages.
        cls.skill_component_loader.load_skill()

    def test_warning_message_when_component_not_declared_and_flag_is_false(self):
        """
        Test warning message.

        Test that the warning message is printed when component not declared
         and when the flag 'is_programmatically_defined' is false.
        """
        expected_message = f"Class {self._TEST_HANDLER_CLASS_NAME} of type handler found in skill module {self._test_skill_module_path} but not declared in the configuration file."
        self.skill_context_mock.logger.warning.assert_any_call(expected_message)

    def test_no_warning_message_when_component_not_declared_but_flag_is_true(self):
        """
        Test warning message.

        Test that the warning message is NOT printed when component not declared
         AND the flag 'is_programmatically_defined' is true.
        """
        not_expected_message = f"Class {self._TEST_BEHAVIOUR_CLASS_NAME} of type behaviour found in skill module {self._test_skill_module_path} but not declared in the configuration file."
        # note: we do want the mock assert to fail
        with pytest.raises(AssertionError):
            self.skill_context_mock.logger.warning.assert_any_call(not_expected_message)
