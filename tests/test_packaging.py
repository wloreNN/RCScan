from importlib.metadata import entry_points, version

from rcscan import __version__
from rcscan.core.config import load_config


def test_installed_distribution_version_matches_module() -> None:
    assert version("rcscan") == __version__


def test_console_script_targets_cli_application() -> None:
    scripts = entry_points(group="console_scripts")
    rcscan = next(item for item in scripts if item.name == "rcscan")

    assert rcscan.value == "rcscan.cli.main:app"


def test_default_configuration_requires_no_packaged_files() -> None:
    config = load_config()

    assert config.profile.name == "safe-default"
    assert config.scope.allow_public_targets is False
    assert config.web_throttling.max_transient_retries == 1
