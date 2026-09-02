"""
M1 structural tests — verify the project has the expected foundation files.
These run in CI without any external dependencies.

Pipeline-specific unit tests are added in M2–M4 alongside the components they cover.
"""

import os
import subprocess

ROOT = os.path.dirname(os.path.dirname(__file__))


def _exists(*parts: str) -> bool:
    return os.path.exists(os.path.join(ROOT, *parts))


def _git_tracked(*parts: str) -> bool:
    """Return True if the path is currently tracked by git (i.e. committed or staged)."""
    result = subprocess.run(
        ["git", "ls-files", "--error-unmatch", os.path.join(*parts)],
        cwd=ROOT,
        capture_output=True,
    )
    return result.returncode == 0


def test_docker_files_present():
    assert _exists("Dockerfile"), "Dockerfile missing"
    assert _exists("docker-compose.yml"), "docker-compose.yml missing"
    assert _exists(".dockerignore"), ".dockerignore missing"


def test_config_template_present():
    assert _exists("config.yaml.example"), "config.yaml.example missing"


def test_config_yaml_not_committed():
    """config.yaml must never be committed — it contains secrets.

    Checks git tracking, not local file existence, so the test passes
    in normal development setups where the file exists but is gitignored.
    """
    assert not _git_tracked("config.yaml"), (
        "config.yaml is tracked by git — it contains secrets. "
        "Remove it with: git rm --cached config.yaml"
    )


def test_requirements_files_present():
    assert _exists("requirements.txt"), "requirements.txt missing"
    assert _exists("requirements-dev.txt"), "requirements-dev.txt missing"


def test_ci_workflow_present():
    assert _exists(".github", "workflows", "ci.yml"), ".github/workflows/ci.yml missing"


def test_main_entrypoint_present():
    assert _exists("dive", "main.py"), "dive/main.py missing"
    assert _exists("dive", "__init__.py"), "dive/__init__.py missing"


def test_gitignore_excludes_secrets():
    """config.yaml and .env must be listed in .gitignore."""
    gitignore_path = os.path.join(ROOT, ".gitignore")
    assert os.path.exists(gitignore_path), ".gitignore missing"
    content = open(gitignore_path).read()
    assert "config.yaml" in content, "config.yaml not in .gitignore"
    assert ".env" in content, ".env not in .gitignore"


def test_no_native_select_in_templates():
    """Every native <select> was converted to a .menu (ui.param_menu /
    ui.field_menu, see templates/_macros.html) — its OS-drawn popup covers
    its own trigger, which CSS cannot fix. A cheap permanent guard against a
    new one creeping back in.

    Strips {# Jinja comments #} first — several templates explain the
    conversion in prose that names <select> by tag."""
    import glob
    import re

    offenders = []
    for path in glob.glob(os.path.join(ROOT, "templates", "*.html")):
        with open(path) as fh:
            content = fh.read()
        content = re.sub(r"\{#.*?#\}", "", content, flags=re.DOTALL)
        if "<select" in content:
            offenders.append(os.path.relpath(path, ROOT))
    assert not offenders, f"native <select> found in: {offenders}"
