"""The .deb installs its Python dependencies from a list in packaging/Makefile,
not from pyproject.toml, so the two can drift and only a real install shows it.
"""

import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
PYPROJECT = REPO_ROOT / "pyproject.toml"
PACKAGING_MAKEFILE = REPO_ROOT / "packaging" / "Makefile"

REQUIREMENT = re.compile(r"^(?P<name>[A-Za-z0-9_.\-]+)(?P<extras>\[[^\]]*\])?(?P<spec>.*)$")


def _normalise(name: str) -> str:
    return name.lower().replace("_", "-")


def _pyproject_dependencies() -> dict[str, str]:
    text = PYPROJECT.read_text()
    block = re.search(r"^dependencies\s*=\s*\[(.*?)^\]", text, re.DOTALL | re.MULTILINE)
    assert block, "pyproject.toml has no top-level dependencies array"
    found = {}
    for raw in re.findall(r'"([^"]+)"', block.group(1)):
        match = REQUIREMENT.match(raw.strip())
        assert match, raw
        found[_normalise(match.group("name"))] = match.group("spec").strip()
    return found


def _deb_dependencies() -> dict[str, str]:
    for line in PACKAGING_MAKEFILE.read_text().splitlines():
        if "pip install" not in line or "--target" not in line:
            continue
        found = {}
        for raw in re.findall(r"'([^']+)'", line):
            match = REQUIREMENT.match(raw.strip())
            assert match, raw
            found[_normalise(match.group("name"))] = match.group("spec").strip()
        return found
    msg = "packaging/Makefile has no pip install --target line"
    raise AssertionError(msg)


def test_the_deb_installs_what_the_code_is_tested_against():
    """A version the deb ships but the tests never import is a release blocker.

    aleph-message drifted to 1.4 in the deb while the code moved to 1.5, and
    every V-PROGRAM create on an installed node raised AttributeError.
    """
    project = _pyproject_dependencies()
    deb = _deb_dependencies()

    drifted = {name: (deb[name], project[name]) for name in deb.keys() & project.keys() if deb[name] != project[name]}
    assert not drifted, "packaging/Makefile disagrees with pyproject.toml: " + ", ".join(
        f"{name} is {shipped!r} in the deb and {tested!r} in pyproject" for name, (shipped, tested) in drifted.items()
    )
