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
    assert _exists("main.py"), "main.py missing"


def test_gitignore_excludes_secrets():
    """config.yaml and .env must be listed in .gitignore."""
    gitignore_path = os.path.join(ROOT, ".gitignore")
    assert os.path.exists(gitignore_path), ".gitignore missing"
    content = open(gitignore_path).read()
    assert "config.yaml" in content, "config.yaml not in .gitignore"
    assert ".env" in content, ".env not in .gitignore"
