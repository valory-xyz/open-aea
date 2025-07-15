This page provides some tips on how to upgrade AEA projects between different versions of the AEA framework. For full release notes check the <a href="https://github.com/valory-xyz/open-aea/tags" target="_blank">AEA repo</a>.

The primary tool for upgrading AEA projects is the `aea upgrade` command in the <a href="../cli-commands/">CLI</a>.

Below we describe the additional manual steps required to upgrade between different versions:


# Open AEA

### Upgrade guide

## `v1.65.0` to `v0.2.0`

- No longer supports Python 3.8 and 3.9.
- `get_metavar` now requires a new parameter, `ctx: Context`
- `aea` and its subcommands that expect some arguments (for example `aea`, `aea ipfs`, etc.), when used without any arguments will now finish with exit code 2 instead of 0, and print their usage help in `stderr`.

## `v1.64.0` to `v1.65.0`

- No backwards incompatible changes

## `v1.63.0` to `v1.64.0`

- No backwards incompatible changes

## `v1.62.0` to `v1.63.0`

- No backwards incompatible changes

## `v1.61.0` to `v1.62.0`

- If `EthereumApi` is used for chains other than Gnosis then `min_allowed_tip` must be set to `1` through `gas_price_strategies` parameter. The default value is only suitable for Gnosis.

## `v1.60.0` to `v1.61.0`

- No backwards incompatible changes

## `v1.59.0` to `v1.60.0`

- No backwards incompatible changes

## `v1.58.0` to `v1.59.0`

- No backwards incompatible changes

## `v1.57.0` to `v1.58.0`

- No backwards incompatible changes

## `v1.56.0` to `v1.57.0`

- No backwards incompatible changes

## `v1.55.0` to `v1.56.0`

- The `priority_fee_estimation_trigger` has been removed from the `eip1559` configuration of the ledger.
- The `default_priority_fee` is now optional. 
  If it is set to `None`, dynamic pricing will be applied. 
  Otherwise, the specified value will be used.

## `v1.54.0` to `v1.55.0`

- No backwards incompatible changes

## `v1.53.0` to `v1.54.0`

- No backwards incompatible changes

## `v1.52.0` to `v1.53.0`

- No backwards incompatible changes

## `v1.51.0` to `v1.52.0`

This release contains updated version range for several dependencies so please update you environments with following dependency versions

- `psutil>=5.7.0,<6.0.0`
- `bech32>=1.2.0,<2`
- `PyNaCl>=1.5.0,<2`
- `click>=8.1.0,<9`
- `pyyaml>=6.0.1,<9`
- `requests>=2.28.1,<3`

## `v1.50.0` to `v1.51.0`

- No backwards incompatible changes

## `v1.49.0` to `v1.50.0`

- No backwards incompatible changes

## `v1.48.0.post1` to `v1.49.0`

- No backwards incompatible changes

## `v1.48.0` to `v1.48.0.post1`

- No backwards incompatible changes

## `v1.47.0` to `v1.48.0`

- No backwards incompatible changes

## `v1.46.0` to `v1.47.0`

The `send_signed_transaction` method implementation has been updated to follow the ledger plugin pattern, which means it will return the transaction digest, not the transaction receipt. To retrieve the transaction receipt use the `get_transaction_receipt` method.

## `v1.45.0` to `v1.46.0`

- No backwards incompatible changes
 
## `v1.44.0` to `v1.45.0`

- No backwards incompatible changes
 
## `v1.43.0.post2` to `v1.44.0`

- No backwards incompatible changes
  
## `v1.43.0.post1` to `v1.43.0.post2`

- No backwards incompatible changes

## `v1.43.0` to `v1.43.0.post1`

- No backwards incompatible changes

## `v1.42.0` to `v1.43.0`

- No backwards incompatible changes

## `v1.41.0.post1` to `v1.42.0`

- No backwards incompatible changes

## `v1.41.0` to `v1.41.0.post1`

- No backwards incompatible changes

## `v1.41.0` to `v1.41.0.post1`

- No backwards incompatible changes

## `v1.40.0` to `v1.41.0`

- The way the dependencies will be selected for installation when running `aea install` has changed. Before this version, the versions were being merging all of the versions for a python package and using the most compatible version specifier possible. With this release, this behaviour will be replaced by overriding the dependencies in the following order `extra dependencies provided by flag > agent > skill > connection > contract > protocol` what this means is, let's say you have 3 packages with a same python package as a dependency

* protocol package with `protobuf>1.0.0`
* connection package with `protobuf==1.0.0`
* skill package with `protobuf>=1.0.0,<2.0.0`

`protobuf>=1.0.0,<2.0.0` will be used for installation since skill has higher priority over protocol and connection packages.

## `v1.39.0.post1` to `v1.40.0`

- `open-aea-web3` has been replaced with `web3py`
- `protobuf` has been bumped to `protobuf>=4.21.6,<5.0.0`, this means you will have to bump your protocol generator to `v24.3` and generate your protocol packages again.
- Because of the protobuf version bump hardware wallet plugin might now work as expected, so please export `PROTOCOL_BUFFERS_PYTHON_IMPLEMENTATION="python"` to use the hardware wallet without any issues
- The `valory/open-aea-user` image will use Python 3.11 as default interpreter for running AEAs

## `v1.39.0` to `v1.39.0.post1`

- No backwards incompatible changes

## `v1.38.0` to `v1.39.0`

- No backwards incompatible changes

## `v1.37.0` to `v1.38.0`

- `web3py` has been replaced with `open-aea-web3` and we forked this from `web3py@v6.0.0`, that means the method names will use the `snake_case` and the `camelCase` naming has been deprecated
- `apduboy` has been deprecated as a dependency
- `flashbots` has been replaced with `open-aea-flashbots`
- Support for `Python 3.7` has been deprecated

## `v1.36.0` to `v1.37.0`

- No backwards incompatible changes

## `v1.35.0` to `v1.36.0`

- No backwards incompatible changes
  
## `v1.34.0` to `v1.35.0`

- No backwards incompatible changes
  
## `v1.33.0` to `v1.34.0`

- No backwards incompatible changes

## `v1.32.0` to `v1.33.0`

- No backwards incompatible changes

## `v1.31.0` to `v1.32.0`

- No backwards incompatible changes

You will have to generate the protocols again since protocol generator will use `double` to represent float values.

## `v1.30.0` to `v1.31.0`

- No backwards incompatible changes

**Note** The `Ethereum Flashbots` ledger plugin and `Solana` ledger plugin are only supported on Python 3.10 or greater.

## `v1.29.0` to `v1.30.0`

- No backwards incompatible changes

## `v1.28.0.post1` to `v1.29.0`

- No backwards incompatible changes
  
## `v1.28.0` to `v1.28.0.post1`

- No backwards incompatible changes

## `v1.27.0` to `v1.28.0`

One breaking change

- The public id format now requires the author name and the package name to be in snake case format

### Upgrade guide

## `v1.26.0` to `v1.27.0`

Multiple small backwards incompatible changes:
- `BaseContractTestCase` no longer sets a default `path_to_contract` and `ledger_identifier`. The user is expected to set these and an exception is thrown if classes are defined without these.
- `BaseContractTestCase` had wrongly defined `setup`. This is now changed to `setup_class`.
- `BaseSkillTestCase` no longer sets a default `path_to_skill`. The user is expected to set this and an exception is thrown if classes are defined without this.
- Comparison operators were fixed for multiple custom classes. Some edge cases will behave differently. Consult <a href="https://github.com/valory-xyz/open-aea/pull/428" target="_blank">#428</a> and related PRs.

Plugins from previous versions are not compatible anymore.

## `v1.25.0` to `v1.26.0`

No backwards incompatible changes.

Plugins from previous versions are not compatible anymore.

## `v1.24.0` to `v1.25.0`

No backwards incompatible changes.

Plugins from previous versions are not compatible anymore.

The usage of `aea hash all` command has been deprecated and will be removed on `v2.0.0`, use `aea packages lock` command to perform hash updates for package dependencies.

## `v1.23.0` to `v1.24.0`

No backwards incompatible changes.

Plugins from previous versions are not compatible anymore.

## `v1.22.0` to `v1.23.0`

No backwards incompatible changes.

Plugins from previous versions are not compatible anymore.


This release introduces a new format for `packages.json` file, the older version is still supported but will be deprecated on `v2.0.0` so make sure to update your projects to use the new format.

## `v1.21.0` to `v1.22.0`

No backwards incompatible changes.

Plugins from previous versions are not compatible anymore.

## `v1.20.0` to `v1.21.0`

No backwards incompatible changes.

Plugins from previous versions are not compatible anymore.

## `v1.19.0` to `v1.20.0`


No backwards incompatible changes.

Plugins from previous versions are not compatible anymore.

## `v1.18.0` to `v1.19.0`

- Deprecated the usage of `hashes.csv` and replaces it with `packages.json`, which is maintained by `aea packages lock`
- `--check` flag is deprecated from `aea hash all`, from now package consistencies can be verified by `aea packages lock --check`
- When running `init` if no registry flags provided, `local` will be used as the default registry and `IPFS` as the default remote registry

Plugins from previous versions are not compatible anymore.

## `v1.17.0` to `v1.18.0`

No backwards incompatible changes.

Plugins from previous versions are not compatible anymore.

## `v1.16.0` to `v1.17.0`

No backwards incompatible changes.

Plugins from previous versions are not compatible anymore.

## `v1.15.0` to `v1.16.0`

- A typo change, now import `from aea.helpers.dependency_tree import DependencyTree` rather than `from aea.helpers.dependency_tree import DependecyTree`.
- The global configuration file for the `aea` CLI has a breaking change. Please remove `~/.aea/cli_config.yaml` and rerun `autonomy init --remote`.

Plugins from previous versions are not compatible anymore.

## `v1.14.0` to `v1.15.0`

No backwards incompatible changes.

Plugins from previous versions are not compatible anymore.

## `v1.13.0` to `v1.14.0`

No backwards incompatible changes.

Plugins from previous versions are not compatible anymore.

## `v1.12.0` to `v1.13.0`

This releases introduces the usage of CID v1 IPFS hashes. We still support CID v0 hashes, but it is advisable to switch to CID v1 hashes.

Plugins from previous versions are not compatible anymore.

## `v1.11.0` to `v1.12.0`

No backwards incompatible changes.

Plugins from previous versions are not compatible anymore.

## `v1.10.0` to `v1.11.0`

No backwards incompatible changes.

Plugins from previous versions are not compatible anymore.

## `v1.9.0` to `v1.10.0`

Python 3.6 no longer supported

Plugins from previous versions are not compatible anymore.

## `v1.8.0` to `v1.9.0`

No backwards incompatible changes.

Plugins from previous versions are not compatible anymore.

## `v1.7.0` to `1.8.0`

This release introduces a new format for `PublicId` parameter which allows users to use IPFS hashes as a part of the `PublicId` which may lead to some unexpected behaviours or bugs.

Previous implementation of `PublicId` used `author/package:version` format, The new implementation uses `author/package:version:hash`

This release also fixes the hash inconsistency by using wrapper hashes to represent packages.

Plugins from previous versions are not compatible anymore.

## `v1.6.0` to `v1.7.0`

No backwards incompatible changes.

Plugins from previous versions are not compatible anymore.

## `v1.5.0` to `v1.6.0`

No backwards incompatible changes.

Plugins from previous versions are not compatible anymore.

## `v1.4.0` to `v1.5.0`

No backwards incompatible changes.

Plugins from previous versions are not compatible anymore.

## `v1.3.0` to `v1.4.0`

No backwards incompatible changes.

Plugins from previous versions are not compatible anymore.

## `v1.2.0` to `v1.3.0`

No backwards incompatible changes.

The `open-aea-ledger-ethereum` plugin now supports EIP1559 based gas estimation.

## `v1.1.0` to `v1.2.0`

No backwards incompatible changes.

The `open-aea-ledger-ethereum` plugin now supports EIP1159-style transactions.

## `aea==v1.1.0` to `open-aea==v1.1.0`

Backwards incompatible changes:

- removal of the GOP decision maker handler. However, via the configuration option of the decision maker handler this can be simply added as a standalone file.

- conversion of plugins due to their dependency on `aea`. Simply replace `aea-ledger-fetchai` with `open-aea-ledger-fetchai` etc.

Legacy packages can be used in open AEA too!

# Legacy AEA

## `v1.0.2` to `v1.1.0`

No backwards incompatible changes.

We advise everyone to upgrade their `fetchai` packages and plugins to get the latest fixes.

## `v1.0.1` to `v1.0.2`

No backwards incompatible changes.

We advise everyone to upgrade their `fetchai` packages and plugins to get the latest fixes.

## `v1.0.0` to `v1.0.1`

No backwards incompatible changes.

We advise everyone to upgrade their `fetchai` packages to get the latest fixes.

## `v1.0.0rc2` to `v1.0.0`

No backwards incompatible changes to component development.

We advise everyone to upgrade to `v1` as soon as possible. When upgrading from versions below `v1.0.0rc1` first upgrade to the first release candidate, then to `v1`.

## `v1.0.0rc1` to `v1.0.0rc2`

No backwards incompatible changes to component development.

Various configuration changes introduced in `v1.0.0rc1` are now enforced strictly.

## `v0.11.1` to `v1.0.0rc1`

No backwards incompatible changes to component development.

The `aea-config.yaml` now requires the field `required_ledgers` which must specify all ledgers for which private keys are required to run the agent. Please add it to your project.

The `registry_path` field has been removed from the `aea-config.yaml`. Please remove it from your project.

All packages provided by author `fetchai` must be upgraded.

## `v0.11.0` to `v0.11.1`

No backwards incompatible changes.

## `v0.10.1` to `v0.11.0`

Take special care when upgrading to `v0.11.0`. We introduced several breaking changes in preparation for `v1`!

### CLI GUI

We removed the CLI GUI. It was not used by anyone as far as we know and needs to be significantly improved. Soon we will release the AEA Manager App to make up for this.

### Message routing

Routing has been completely revised and simplified. The new message routing logic is described <a href="../message-routing/">here</a>.

When upgrading take the following steps:

- For agent-to-agent communication: ensure the default routing and default connection are correctly defined and that the dialogues used specify the agent's address as the `self_address`. This is most likely already the case. Only in some edge cases will you need to use an `EnvelopeContext` to target a connection different from the one specified in the `default_routing` map.

- For component-to-component communication: there is now only one single way to route component to component (skill to skill, skill to connection, connection to skill) messages, this is by specifying the component id in string form in the `sender`/`to` field. The `EnvelopeContext` can no longer be used, messages are routed based on their target (`to` field). Ensure that dialogues in skills set the `skill_id` as the `self_address` (in connections they need to set the `connection_id`).

### Agent configuration and ledger plugins

Agent configuration files have a new optional field, `dependencies`,  analogous to `dependencies` field in other AEA packages. The default value is the empty object `{}`. The field will be made mandatory in the next release.

Crypto modules have been extracted and released as independent plug-ins, released on PyPI. In particular:

- Fetch.ai crypto classes have been released in the `aea-ledger-fetchai` package;
- Ethereum crypto classes have been released in the `aea-ledger-ethereum` package;
- Cosmos crypto classes have been released in the `aea-ledger-cosmos` package.

If an AEA project, or an AEA package, makes use of crypto functionalities, it will be needed to add the above packages as PyPI dependencies with version specifiers ranging from the latest minor and the latest minor + 1 (excluded). E.g. if the latest version if `0.1.0`, the version specifier should be `<0.2.0,>=0.1.0`:
```yaml
dependencies:
  aea-ledger-cosmos:
    version: <3.0.0,>=2.0.0
  aea-ledger-ethereum:
    version: <3.0.0,>=2.0.0
  aea-ledger-fetchai:
    version: <3.0.0,>=2.0.0
```
The version specifier sets are important, as these plug-ins, at version `0.1.0`, depend on a specific range of the `aea` package.

Then, running `aea install` inside the AEA project should install them in the current Python environment.

For more, read the <a href="../ledger-integration">guide on ledger plugins</a>.

## `v0.10.0` to `v0.10.1`

No backwards incompatible changes for skill and connection development.

## `v0.9.2` to `v0.10.0`

Skill development sees no backward incompatible changes.

Connection development requires updating the keyword arguments of the constructor: the new `data_dir` argument must be defined.

Protocol specifications now need to contain a `protocol_specification_id` in addition to the public id. The `protocol_specification_id` is used for identifying Envelopes during transport. By being able to set the id independently of the protocol id, backwards compatibility in the specification (and therefore wire format) can be maintained even when the Python implementation changes.

Please update to the latest packages by running `aea upgrade` and then re-generating your own protocols.

## `v0.9.1` to `v0.9.2`

No backwards incompatible changes for skill and connection development.

## `v0.9.0` to `v0.9.1`

No backwards incompatible changes for skill and connection development.

## `v0.8.0` to `v0.9.0`

This release introduces <a href="../por">proof of representation</a> in the ACN. You will need to upgrade to the latest `fetchai/p2p_libp2p` or `fetchai/p2p_libp2p_client` connection and then use two key pairs, one for your AEA's decision maker and one for the connection.

Please update to the latest packages by running `aea upgrade`.

## `v0.7.5` to `v0.8.0`

Minimal backwards incompatible changes for skill and connection development:

- The semantics of the `<`, `<=`, `>` and `>=` relations in `ConstraintTypes` are simplified.
- Protocols now need to correctly define terminal states. Regenerate your protocol to identify if your protocol's dialogue rules are valid.

Please update to the latest packages by running `aea upgrade`.

## `v0.7.4` to `v0.7.5`

No backwards incompatible changes for skill and connection development.

## `v0.7.3` to `v0.7.4`

No backwards incompatible changes for skill and connection development.

## `v0.7.2` to `v0.7.3`

No backwards incompatible changes for skill and connection development.

## `v0.7.1` to `v0.7.2`

No backwards incompatible changes for skill and connection development.

## `v0.7.0` to `v0.7.1`

To improve performance, in particular optimize memory usage, we refactored the `Message` and `Dialogue` classes. This means all protocols need to be bumped to the latest version or regenerated using the `aea generate protocol` command in the <a href="../cli-commands/">CLI</a>.

## `v0.6.3` to `v0.7.0`

Multiple breaking changes require action in this order:

- Custom configuration overrides in `aea-config.yaml` are now identified via `public_id` rather than `author`, `name` and `version` individually. Please replace the three fields with the equivalent `public_id`.

- Run `aea upgrade` command to upgrade your project's dependencies. Note, you still do have to manually update the public ids under `default_routing` and `default_connection` in `aea-config.yaml` as well as the public ids in the non-vendor packages.

- Previously, connection `fetchai/stub`, skill `fetchai/error` and protocols `fetchai/default`, `fetchai/signing` and `fetchai/state_update` where part of the AEA distribution. Now they need to be fetched from registry. If you create a new project with `aea create` then this happens automatically. For existing projects, add the dependencies explicitly if not already present. You also must update the import paths as follows:

    - `aea.connections.stub` > `packages.fetchai.connections.stub`
    - `aea.protocols.default` > `packages.fetchai.protocols.default`
    - `aea.protocols.signing` > `packages.fetchai.protocols.signing`
    - `aea.protocols.state_update` > `packages.fetchai.protocols.state_update`
    - `aea.skills.error` > `packages.fetchai.skills.error`

- If you use custom protocols, regenerate them.

- In your own skills' `__init__.py` files add the public id (updating the string as appropriate):

``` python
from aea.configurations.base import PublicId


PUBLIC_ID = PublicId.from_str("author/name:0.1.0")
```
- The `fetchai/http` protocol's `bodyy` field has been renamed to `body`.

- Skills can now specify `connections` as dependencies in the configuration YAML.


## `v0.6.2` to `v0.6.3`

A new `upgrade` command is introduced to upgrade agent projects and components to their latest versions on the registry. To use the command first upgrade the AEA PyPI package to the latest version, then enter your project and run `aea upgrade`. The project's vendor dependencies will be updated where possible.

## `v0.6.1` to `v0.6.2`

No public APIs have been changed.

## `v0.6.0` to `v0.6.1`

The `soef` connection and `oef_search` protocol have backward incompatible changes.

## `v0.5.4` to `v0.6.0`

### `Dialogue` and `Dialogues` API updates

The dialogue and dialogues APIs have changed significantly. The constructor is different for both classes and there are now four primary methods for the developer:

- `Dialogues.create`: this method is used to create a new dialogue and message:
``` python
cfp_msg, fipa_dialogue = fipa_dialogues.create(
    counterparty=opponent_address,
    performative=FipaMessage.Performative.CFP,
    query=query,
)
```
The method will raise if the provided arguments are inconsistent.

- `Dialogues.create_with_message`: this method is used to create a new dialogue from a message:
``` python
fipa_dialogue = fipa_dialogues.create_with_message(
    counterparty=opponent_address,
    initial_message=cfp_msg
)
```
The method will raise if the provided arguments are inconsistent.

- `Dialogues.update`: this method is used to handle messages passed by the framework:
``` python
fipa_dialogue = fipa_dialogues.update(
    message=cfp_msg
)
```
The method will return a valid dialogue if it is a valid message, otherwise it will return `None`.

- `Dialogue.reply`: this method is used to reply within a dialogue:
``` python
proposal_msg = fipa_dialogue.reply(
    performative=FipaMessage.Performative.PROPOSE,
    target_message=cfp_msg,
    proposal=proposal,
)
```
The method will raise if the provided arguments are inconsistent.

The new methods significantly reduce the lines of code needed to maintain a dialogue. They also make it easier for the developer to construct valid dialogues and messages.

### `FetchAICrypto` - default crypto

The `FetchAICrypto` has been upgraded to the default crypto. Update your `default_ledger` to `fetchai`.

### Private key file naming

The private key files are now consistently named with the `ledger_id` followed by `_private_key.txt` (e.g. `fetchai_private_key.txt`). Rename your existing files to match this pattern.

### Type in package YAML

The package YAML files now contain a type field. This must be added for the loading mechanism to work properly.

### Moved address type

The address type has moved to `aea.common`. The import paths must be updated.

## `v0.5.3` to `v0.5.4`

The contract base class was slightly modified. If you have implemented your own contract package you need to update it accordingly.

The dialogue reference nonce is now randomly generated. This can result in previously working but buggy implementations (which relied on the order of dialogue reference nonces) to now fail.

## `v0.5.2` to `v0.5.3`

Connection states and logger usage in connections where updated. If you have implemented your own connection package you need to update it accordingly.

Additional dialogue consistency checks where enabled. This can result in previously working but buggy implementations to now fail.

## `v0.5.1` to `0.5.2`

No public APIs have been changed.

## `v0.5.0` to `0.5.1`

No public APIs have been changed.

## `v0.4.1` to `0.5.0`

A number of breaking changes where introduced which make backwards compatibility of skills rare.

- Ledger APIs <a href="../api/crypto/ledger_apis#ledger-apis-objects">`LedgerApis`</a> have been removed from the AEA constructor and skill context. `LedgerApis` are now exposed in the `LedgerConnection` (`fetchai/ledger`). To communicate with the `LedgerApis` use the `fetchai/ledger_api` protocol. This allows for more flexibility (anyone can add another `LedgerAPI` to the registry and execute it with the connection) and removes dependencies from the core framework.
- Skills can now depend on other skills. As a result, skills have a new required configuration field in `skill.yaml` files, by default empty: `skills: []`.

## `v0.4.0` to `v0.4.1`

There are no upgrade requirements if you use the CLI based approach to AEA development.

Connections are now added via <a href="../api/registries/resources#resources-objects">`Resources`</a> to the AEA, not the AEA constructor directly. For programmatic usage remove the list of connections from the AEA constructor and instead add the connections to resources.

## `v0.3.3` to `v0.4.0`

<ul>
<li> Message sending in the skills has been updated. In the past you had to construct messages, then serialize them and place them in an envelope:

``` python
cfp_msg = FipaMessage(...)
self.context.outbox.put_message(
    to=opponent_addr,
    sender=self.context.agent_address,
    protocol_id=FipaMessage.protocol_id,
    message=FipaSerializer().encode(cfp_msg),
)
# or
cfp_msg = FipaMessage(...)
envelope = Envelope(
    to=opponent_addr,
    sender=self.context.agent_address,
    protocol_id=FipaMessage.protocol_id,
    message=FipaSerializer().encode(cfp_msg),
)
self.context.outbox.put(envelope)
```

Now this has been simplified to:
``` python
cfp_msg = FipaMessage(...)
cfp_msg.counterparty = opponent_addr
self.context.outbox.put_message(message=cfp_msg)
```

You must update your skills as the old implementation is no longer supported.
</li>
<li> Connection constructors have been simplified. In the past you had to implement both the `__init__` as well as the `from_config` methods of a Connection. Now you only have to implement the `__init__` method which by default at load time now receives the following keyword arguments: `configuration: ConnectionConfig, identity: Identity, crypto_store: CryptoStore`. See for example in the scaffold connection:

``` python
class MyScaffoldConnection(Connection):
    """Proxy to the functionality of the SDK or API."""

    connection_id = PublicId.from_str("fetchai/scaffold:0.1.0")

    def __init__(
        self,
        configuration: ConnectionConfig,
        identity: Identity,
        crypto_store: CryptoStore,
    ):
        """
        Initialize a connection to an SDK or API.

        :param configuration: the connection configuration.
        :param crypto_store: object to access the connection crypto objects.
        :param identity: the identity object.
        """
        super().__init__(
            configuration=configuration, crypto_store=crypto_store, identity=identity
        )
```

As a result of this feature, you are now able to pass key-pairs to your connections via the `CryptoStore`.

You must update your connections as the old implementation is no longer supported.
</li>
</ul>


