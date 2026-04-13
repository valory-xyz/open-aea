# open-aea-dev-helpers

Development and release helper utilities for AEA-based projects. Used for local development workflows and release engineering — not for agent runtime.

## Installation

```bash
pip install open-aea-dev-helpers
```

This installs an `aea-dev` command.

## Commands

```
aea-dev bump-version            Bump AEA and plugin versions throughout the codebase
aea-dev deploy-registry         Push all packages to the registry in dependency order
aea-dev publish-local           Publish local packages to an IPFS node
aea-dev update-pkg-versions     Interactive package version bumping with registry checks
aea-dev update-plugin-versions  Bump plugin versions and update version specifiers
aea-dev update-symlinks         Update symlinks for the project (cross-platform)
```

Run any command with `--help` for details.
