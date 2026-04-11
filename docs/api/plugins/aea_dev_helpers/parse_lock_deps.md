<a id="plugins.aea-dev-helpers.aea_dev_helpers.parse_lock_deps"></a>

# plugins.aea-dev-helpers.aea`_`dev`_`helpers.parse`_`lock`_`deps

Parse main dependencies from a Pipfile.lock and output in requirements.txt format.

<a id="plugins.aea-dev-helpers.aea_dev_helpers.parse_lock_deps.parse_lock_deps"></a>

#### parse`_`lock`_`deps

```python
def parse_lock_deps(pipfile_lock_path: str,
                    output: Optional[str] = None) -> str
```

Parse a Pipfile.lock and return requirements in requirements.txt format.

**Arguments**:

- `pipfile_lock_path`: path to the Pipfile.lock file.
- `output`: optional path to write the output to. If None, returns the string.

**Returns**:

the requirements string.

