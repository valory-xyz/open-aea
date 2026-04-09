<a id="plugins.aea-ci-helpers.aea_ci_helpers.check_ipfs_pushed"></a>

# plugins.aea-ci-helpers.aea`_`ci`_`helpers.check`_`ipfs`_`pushed

This module contains the tools for checking that all packages have been pushed to the ipfs registry.

<a id="plugins.aea-ci-helpers.aea_ci_helpers.check_ipfs_pushed.REQUEST_TIMEOUT"></a>

#### REQUEST`_`TIMEOUT

seconds

<a id="plugins.aea-ci-helpers.aea_ci_helpers.check_ipfs_pushed.check_ipfs_hash_pushed"></a>

#### check`_`ipfs`_`hash`_`pushed

```python
def check_ipfs_hash_pushed(ipfs_hash: str,
                           retries: int = 5) -> Tuple[str, bool]
```

Check that the given ipfs hash exists in the registry

<a id="plugins.aea-ci-helpers.aea_ci_helpers.check_ipfs_pushed.get_latest_git_tag"></a>

#### get`_`latest`_`git`_`tag

```python
def get_latest_git_tag() -> str
```

Get the latest git tag

<a id="plugins.aea-ci-helpers.aea_ci_helpers.check_ipfs_pushed.get_file_from_tag"></a>

#### get`_`file`_`from`_`tag

```python
def get_file_from_tag(file_path: str, latest_tag: Optional[str] = None) -> str
```

Get a specific file version from the commit history given a tag/commit

