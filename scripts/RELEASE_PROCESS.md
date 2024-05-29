
# Release Process from develop to main

1. Make sure you have a clean develop virtual environment (`make new_env`). Make sure all tests pass, coverage is at 100% and the local branch is in a clean state (nothing to commit after running `make formatters`, `make code-checks` and `make generators`).

2. Determine the next AEA version: Create new release branch named "release/{new-version}, switch to this branch and run `python scripts/bump_aea_version.py --new-version NEW_VERSION_HERE`. Commit if satisfied.

3. Bump plugin versions if necessary by running `python scripts/update_plugin_versions.py --update "PLUGIN_NAME,NEW_VERSION"`. Commit if satisfied.

4. Update the package and dependency hashes, protocols, as well as docs using `make generators`. Commit if changes occurred.

5. Ensure all links are configured `tox -e docs-serve`. Commit if satisfied.

6. Write release notes and place them in `HISTORY.md`. Add upgrading tips in `upgrading.md`. If necessary, adjust version references in `SECURITY.md`. Commit if satisfied.

7. Run spell checker `./scripts/spell-check.sh`. Run `pylint --disable all --enable spelling ...`. Commit if required.

8. Open PRs and merge into develop. Then open develop to main PR and merge it.

9. Tag a release from main.

If something goes wrong and only needs a small fix do `LAST_VERSION.post1` as version, apply fixes, push again to PyPI.
