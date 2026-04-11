<a id="plugins.aea-dev-helpers.aea_dev_helpers.publish_local"></a>

# plugins.aea-dev-helpers.aea`_`dev`_`helpers.publish`_`local

Publish local packages to an IPFS node.

<a id="plugins.aea-dev-helpers.aea_dev_helpers.publish_local.get_package_list"></a>

#### get`_`package`_`list

```python
def get_package_list(packages_dir: Union[str, Path]) -> List[Path]
```

Return a list of package directories.

**Arguments**:

- `packages_dir`: path to the packages directory.

**Returns**:

list of package directory paths.

<a id="plugins.aea-dev-helpers.aea_dev_helpers.publish_local.publish_local"></a>

#### publish`_`local

```python
def publish_local(package_dir: str = "./packages") -> None
```

Publish local packages to an IPFS node.

**Arguments**:

- `package_dir`: path to the packages directory.

