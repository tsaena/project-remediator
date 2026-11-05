"""Package-name normalization shared by scanners and correlation."""

import re


def canonical_pypi_name(name: str) -> str:
    """PEP 503 normalization: case-insensitive, with runs of -_. as one '-'."""
    return re.sub(r"[-_.]+", "-", name).lower()


def normalized_name(ecosystem: str, name: str) -> str:
    """PEP 503 for PyPI; other ecosystems keep the name exactly as reported."""
    return canonical_pypi_name(name) if ecosystem == "PyPI" else name
