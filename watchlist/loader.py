from pathlib import Path
from typing import Any

import yaml

from watchlist.models import WatchKeyword


DEFAULT_WATCHLIST_DIR = Path("config/watchlists")


def load_watchlists(watchlist_dir: Path | str = DEFAULT_WATCHLIST_DIR) -> list[WatchKeyword]:
    directory = Path(watchlist_dir)
    keywords: list[WatchKeyword] = []
    seen: set[tuple[str, str]] = set()

    for path in sorted(directory.glob("*.yaml")):
        for keyword in _load_file(path):
            identity = (keyword.category, keyword.canonical_name)
            if identity in seen:
                raise ValueError(
                    f"Duplicate watchlist keyword {keyword.category}:{keyword.canonical_name}"
                )
            seen.add(identity)
            keywords.append(keyword)

    return keywords


def _load_file(path: Path) -> list[WatchKeyword]:
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        raise ValueError(f"Malformed YAML in {path}: {exc}") from exc

    if not isinstance(data, dict):
        raise ValueError(f"Watchlist file {path} must contain a mapping")

    category = _require_non_empty_string(data.get("category"), f"{path}: category")
    raw_keywords = data.get("keywords")
    if not isinstance(raw_keywords, dict):
        raise ValueError(f"{path}: keywords must be a mapping")

    keywords: list[WatchKeyword] = []
    for canonical_name, config in raw_keywords.items():
        canonical = _require_non_empty_string(canonical_name, f"{path}: canonical name")
        if not isinstance(config, dict):
            raise ValueError(f"{path}: keyword {canonical} must be a mapping")

        aliases = _require_string_list(config.get("aliases"), f"{path}: {canonical}.aliases")
        tags = _require_string_list(config.get("tags"), f"{path}: {canonical}.tags")
        score = config.get("score")
        if not isinstance(score, int) or not 0 <= score <= 100:
            raise ValueError(f"{path}: {canonical}.score must be an integer from 0 to 100")

        keywords.append(
            WatchKeyword(
                canonical_name=canonical,
                category=category,
                aliases=tuple(_dedupe([canonical, *aliases])),
                tags=tuple(_dedupe(tags)),
                score=score,
            )
        )

    return keywords


def _require_non_empty_string(value: Any, name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{name} must be a non-empty string")
    return value.strip()


def _require_string_list(value: Any, name: str) -> list[str]:
    if not isinstance(value, list):
        raise ValueError(f"{name} must be a list of strings")
    items: list[str] = []
    for item in value:
        if not isinstance(item, str):
            raise ValueError(f"{name} must be a list of strings")
        text = item.strip()
        if text:
            items.append(text)
    return items


def _dedupe(values: list[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for value in values:
        if value not in seen:
            seen.add(value)
            result.append(value)
    return result

