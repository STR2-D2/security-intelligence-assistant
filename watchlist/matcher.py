import re

from database.models import Vulnerability
from watchlist.models import KeywordMatch, WatchKeyword, WatchlistMatchResult


MATCH_FIELDS = ("title", "description", "vendor", "product", "source")


class WatchlistMatcher:
    def __init__(self, keywords: list[WatchKeyword]) -> None:
        self.keywords = keywords

    def evaluate(self, vulnerability: Vulnerability) -> WatchlistMatchResult:
        matches: list[KeywordMatch] = []
        matched_keywords: set[tuple[str, str]] = set()
        relevance_score = 0
        vulnerability_type_score = 0
        relevance_matched = False
        vulnerability_type_matched = False
        tags: list[str] = []

        for keyword in self.keywords:
            keyword_matched = False
            for field in MATCH_FIELDS:
                text = getattr(vulnerability, field) or ""
                for alias in keyword.aliases:
                    if _matches_alias(str(text), alias):
                        matches.append(
                            KeywordMatch(
                                canonical_name=keyword.canonical_name,
                                category=keyword.category,
                                matched_alias=alias,
                                matched_field=field,
                                tags=keyword.tags,
                            )
                        )
                        keyword_matched = True

            identity = (keyword.category, keyword.canonical_name)
            if keyword_matched and identity not in matched_keywords:
                matched_keywords.add(identity)
                if keyword.category == "vulnerability_type":
                    vulnerability_type_matched = True
                    vulnerability_type_score += keyword.score
                else:
                    relevance_matched = True
                    relevance_score += keyword.score
                for tag in keyword.tags:
                    if tag not in tags:
                        tags.append(tag)

        score = min(100, relevance_score + vulnerability_type_score)
        return WatchlistMatchResult(
            vulnerability_id=vulnerability.id,
            cve_id=vulnerability.cve_id,
            matched=bool(matches),
            relevance_matched=relevance_matched,
            vulnerability_type_matched=vulnerability_type_matched,
            score=score,
            relevance_score=relevance_score,
            vulnerability_type_score=vulnerability_type_score,
            matches=matches,
            tags=tuple(tags),
        )


def _matches_alias(text: str, alias: str) -> bool:
    normalized_text = text.strip()
    normalized_alias = alias.strip()
    if not normalized_text or not normalized_alias:
        return False

    if _requires_token_boundary(normalized_alias):
        return re.search(
            rf"(?<![A-Za-z0-9]){re.escape(normalized_alias)}(?![A-Za-z0-9])",
            normalized_text,
            flags=re.IGNORECASE,
        ) is not None

    return normalized_alias.casefold() in normalized_text.casefold()


def _requires_token_boundary(alias: str) -> bool:
    return alias.isascii() and alias.replace(" ", "").isalnum() and len(alias) <= 3
