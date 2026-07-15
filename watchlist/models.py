from dataclasses import dataclass


@dataclass(frozen=True)
class WatchKeyword:
    canonical_name: str
    category: str
    aliases: tuple[str, ...]
    tags: tuple[str, ...]
    score: int


@dataclass(frozen=True)
class KeywordMatch:
    canonical_name: str
    category: str
    matched_alias: str
    matched_field: str
    tags: tuple[str, ...]


@dataclass(frozen=True)
class WatchlistMatchResult:
    vulnerability_id: int | None
    cve_id: str | None
    matched: bool
    relevance_matched: bool
    vulnerability_type_matched: bool
    score: int
    relevance_score: int
    vulnerability_type_score: int
    matches: list[KeywordMatch]
    tags: tuple[str, ...]
