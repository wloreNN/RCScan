from pathlib import Path

import pytest

from rcscan.core.exceptions import TargetValidationError
from rcscan.scope.models import TargetType
from rcscan.scope.parser import parse_target_file


def write_targets(path: Path, content: str) -> Path:
    path.write_text(content, encoding="utf-8")
    return path


def test_reads_utf8_comments_blanks_and_deduplicates(tmp_path: Path) -> None:
    path = write_targets(
        tmp_path / "targets.txt",
        "# UTF-8 targets — café\n"
        "\n"
        "  10.0.0.1  \n"
        "# ignored comment\n"
        "Example.COM.\n"
        "example.com\n"
        "10.0.0.1\n",
    )

    targets = parse_target_file(path, max_targets=2)

    assert [(target.type, target.value) for target in targets] == [
        (TargetType.IP, "10.0.0.1"),
        (TargetType.HOSTNAME, "example.com"),
    ]


def test_reports_original_line_number_for_invalid_target(tmp_path: Path) -> None:
    path = write_targets(
        tmp_path / "targets.txt",
        "# heading\n\n10.0.0.1\n999.1.1.1\n",
    )

    with pytest.raises(TargetValidationError, match=r"Target file line 4:"):
        parse_target_file(path, max_targets=10)


def test_maximum_counts_unique_targets_only(tmp_path: Path) -> None:
    path = write_targets(
        tmp_path / "targets.txt",
        "10.0.0.1\n10.0.0.1\n10.0.0.2\n",
    )

    targets = parse_target_file(path, max_targets=2)

    assert tuple(target.value for target in targets) == ("10.0.0.1", "10.0.0.2")


def test_rejects_target_file_over_maximum(tmp_path: Path) -> None:
    path = write_targets(tmp_path / "targets.txt", "10.0.0.1\n10.0.0.2\n")

    with pytest.raises(TargetValidationError, match="configured maximum of 1"):
        parse_target_file(path, max_targets=1)


def test_rejects_empty_or_comment_only_target_file(tmp_path: Path) -> None:
    path = write_targets(tmp_path / "targets.txt", "\n# no targets\n   \n")

    with pytest.raises(TargetValidationError, match="contains no targets"):
        parse_target_file(path, max_targets=10)


def test_rejects_non_utf8_target_file(tmp_path: Path) -> None:
    path = tmp_path / "targets.txt"
    path.write_bytes(b"10.0.0.1\n\xff")

    with pytest.raises(TargetValidationError, match="Unable to read target file"):
        parse_target_file(path, max_targets=10)


def test_rejects_missing_target_file(tmp_path: Path) -> None:
    with pytest.raises(TargetValidationError, match="Unable to read target file"):
        parse_target_file(tmp_path / "missing.txt", max_targets=10)
