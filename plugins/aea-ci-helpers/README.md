# open-aea-ci-helpers

CI helper utilities for AEA-based projects. Intended to be run from CI jobs and local pre-release checks, not at agent runtime.

## Installation

```bash
pip install open-aea-ci-helpers
```

This installs an `aea-ci` command.

## Commands

```
aea-ci check-dependencies     Check dependencies are consistent across tox.ini and pyproject.toml
aea-ci check-doc-hashes       Validate and fix IPFS hashes in documentation
aea-ci check-imports          Verify all imports are declared as dependencies
aea-ci check-ipfs-pushed      Verify all package IPFS hashes from the latest git tag are reachable
aea-ci check-pkg-versions     Verify package IDs in documentation match actual package configurations
aea-ci check-pyproject        Verify pyproject.toml and tox.ini dependencies are aligned
aea-ci generate-api-docs      Generate API documentation from source
aea-ci generate-pkg-list      Generate markdown table of all packages with their IPFS hashes
```

Run any command with `--help` for details.
