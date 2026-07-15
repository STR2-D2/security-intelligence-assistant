from pathlib import Path

import pytest

from watchlist.loader import load_watchlists


def write_yaml(path: Path, content: str) -> None:
    path.write_text(content, encoding="utf-8")


def test_loading_one_valid_yaml_file(tmp_path) -> None:
    write_yaml(
        tmp_path / "cloud.yaml",
        """
category: cloud
keywords:
  Azure:
    aliases:
      - Microsoft Azure
    tags:
      - cloud
    score: 30
""",
    )

    keywords = load_watchlists(tmp_path)

    assert len(keywords) == 1
    assert keywords[0].canonical_name == "Azure"
    assert keywords[0].category == "cloud"
    assert keywords[0].score == 30


def test_loading_multiple_yaml_files_in_filename_order(tmp_path) -> None:
    write_yaml(
        tmp_path / "b.yaml",
        "category: b\nkeywords:\n  B:\n    aliases: []\n    tags: []\n    score: 1\n",
    )
    write_yaml(
        tmp_path / "a.yaml",
        "category: a\nkeywords:\n  A:\n    aliases: []\n    tags: []\n    score: 1\n",
    )

    keywords = load_watchlists(tmp_path)

    assert [keyword.canonical_name for keyword in keywords] == ["A", "B"]


def test_canonical_alias_dedupe_and_tag_dedupe(tmp_path) -> None:
    write_yaml(
        tmp_path / "items.yaml",
        """
category: identity
keywords:
  Active Directory:
    aliases:
      - Active Directory
      - AD
      - AD
      - " "
    tags:
      - identity
      - identity
      - directory
      - ""
    score: 30
""",
    )

    keyword = load_watchlists(tmp_path)[0]

    assert keyword.aliases == ("Active Directory", "AD")
    assert keyword.tags == ("identity", "directory")


@pytest.mark.parametrize(
    ("content", "message"),
    [
        ("category: ''\nkeywords: {}\n", "category"),
        ("category: cloud\nkeywords: []\n", "keywords"),
        ("category: cloud\nkeywords:\n  Azure:\n    aliases: bad\n    tags: []\n    score: 1\n", "aliases"),
        ("category: cloud\nkeywords:\n  Azure:\n    aliases: []\n    tags: bad\n    score: 1\n", "tags"),
        ("category: cloud\nkeywords:\n  Azure:\n    aliases: []\n    tags: []\n    score: 101\n", "score"),
    ],
)
def test_malformed_yaml_structures_raise_value_error(
    tmp_path,
    content: str,
    message: str,
) -> None:
    write_yaml(tmp_path / "bad.yaml", content)

    with pytest.raises(ValueError, match=message):
        load_watchlists(tmp_path)


def test_duplicate_category_and_canonical_name_rejected(tmp_path) -> None:
    content = """
category: cloud
keywords:
  Azure:
    aliases: []
    tags: []
    score: 1
"""
    write_yaml(tmp_path / "a.yaml", content)
    write_yaml(tmp_path / "b.yaml", content)

    with pytest.raises(ValueError, match="Duplicate"):
        load_watchlists(tmp_path)


def test_yaml_syntax_error_raises_value_error(tmp_path) -> None:
    write_yaml(tmp_path / "bad.yaml", "category: [\n")

    with pytest.raises(ValueError, match="Malformed YAML"):
        load_watchlists(tmp_path)
