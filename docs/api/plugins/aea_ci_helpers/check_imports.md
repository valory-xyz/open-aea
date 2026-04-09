<a id="plugins.aea-ci-helpers.aea_ci_helpers.check_imports"></a>

# plugins.aea-ci-helpers.aea`_`ci`_`helpers.check`_`imports

Check aea dependencies.

<a id="plugins.aea-ci-helpers.aea_ci_helpers.check_imports.DEP_NAME_RE"></a>

#### DEP`_`NAME`_`RE

type: ignore

<a id="plugins.aea-ci-helpers.aea_ci_helpers.check_imports.list_decorator"></a>

#### list`_`decorator

```python
def list_decorator(fn: Callable) -> Callable
```

Wraps generator to return list.

<a id="plugins.aea-ci-helpers.aea_ci_helpers.check_imports.DependenciesTool"></a>

## DependenciesTool Objects

```python
class DependenciesTool()
```

Tool to work with setup.py dependencies.

<a id="plugins.aea-ci-helpers.aea_ci_helpers.check_imports.DependenciesTool.get_package_files"></a>

#### get`_`package`_`files

```python
@staticmethod
def get_package_files(package_name: str) -> List[Path]
```

Get package files list.

<a id="plugins.aea-ci-helpers.aea_ci_helpers.check_imports.DependenciesTool.clean_dependency_name"></a>

#### clean`_`dependency`_`name

```python
@staticmethod
def clean_dependency_name(dependecy_specification: str) -> str
```

Get dependency name from dependency specification.

<a id="plugins.aea-ci-helpers.aea_ci_helpers.check_imports.ImportsTool"></a>

## ImportsTool Objects

```python
class ImportsTool()
```

Tool to work with 3rd part imports in source code.

<a id="plugins.aea-ci-helpers.aea_ci_helpers.check_imports.ImportsTool.get_imports_for_file"></a>

#### get`_`imports`_`for`_`file

```python
@staticmethod
def get_imports_for_file(pyfile: Union[str, Path]) -> List[str]
```

Get all imported modules for python source file.

<a id="plugins.aea-ci-helpers.aea_ci_helpers.check_imports.ImportsTool.get_module_file"></a>

#### get`_`module`_`file

```python
@staticmethod
def get_module_file(module_name: str) -> str
```

Get module source file name.

<a id="plugins.aea-ci-helpers.aea_ci_helpers.check_imports.ImportsTool.list_all_pyfiles"></a>

#### list`_`all`_`pyfiles

```python
@staticmethod
@list_decorator
def list_all_pyfiles(root_path: Union[Path, str],
                     pattern: str = "**/*.py") -> Generator
```

List all python files in directory.

<a id="plugins.aea-ci-helpers.aea_ci_helpers.check_imports.ImportsTool.get_third_part_imports_for_file"></a>

#### get`_`third`_`part`_`imports`_`for`_`file

```python
@classmethod
@list_decorator
def get_third_part_imports_for_file(cls, pyfile: str) -> Generator
```

Get list of third part modules imported for source file.

<a id="plugins.aea-ci-helpers.aea_ci_helpers.check_imports.ImportsTool.list_all_pyfiles_with_3rdpart_imports"></a>

#### list`_`all`_`pyfiles`_`with`_`3rdpart`_`imports

```python
@classmethod
@list_decorator
def list_all_pyfiles_with_3rdpart_imports(
        cls,
        root_path: Union[str, Path],
        pattern: str = "**/*.py") -> Generator
```

Get list of all python sources with 3rd party modules imported.

<a id="plugins.aea-ci-helpers.aea_ci_helpers.check_imports.CheckTool"></a>

## CheckTool Objects

```python
class CheckTool()
```

Tool to check imports in sources match dependencies in setup.py.

<a id="plugins.aea-ci-helpers.aea_ci_helpers.check_imports.CheckTool.get_section_dependencies_from_setup"></a>

#### get`_`section`_`dependencies`_`from`_`setup

```python
@classmethod
def get_section_dependencies_from_setup(
        cls) -> Dict[str, Dict[str, List[Path]]]
```

Get sections with dependencies with files lists.

<a id="plugins.aea-ci-helpers.aea_ci_helpers.check_imports.CheckTool.sections_dependencies_add_files"></a>

#### sections`_`dependencies`_`add`_`files

```python
@staticmethod
def sections_dependencies_add_files(
    sections_dependencies: Dict[str, List[str]]
) -> Dict[str, Dict[str, List[Path]]]
```

Add packages file lists to dependencies in sections.

<a id="plugins.aea-ci-helpers.aea_ci_helpers.check_imports.CheckTool.run"></a>

#### run

```python
@classmethod
def run(cls) -> None
```

Run dependency check.

<a id="plugins.aea-ci-helpers.aea_ci_helpers.check_imports.CheckTool.make_sections_with_3rdpart_imports"></a>

#### make`_`sections`_`with`_`3rdpart`_`imports

```python
@staticmethod
def make_sections_with_3rdpart_imports(
        files_and_modules: List[Tuple[str, List[Tuple[str, Path]]]],
        section_names: Set[str]) -> Dict[str, Set[Tuple[str, Path]]]
```

Make sections with list of 3r part imports.

<a id="plugins.aea-ci-helpers.aea_ci_helpers.check_imports.CheckTool.check_imports"></a>

#### check`_`imports

```python
@staticmethod
def check_imports(
    sections_imports: Dict[str, Set[Tuple[str, Path]]],
    sections_dependencies: Dict[str, Dict[str, List[Path]]]
) -> Tuple[Dict[str, List[str]], List[str]]
```

Find missing dependencies for imports and not imported dependencies.

