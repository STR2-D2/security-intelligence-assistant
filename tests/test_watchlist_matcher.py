from database.models import Vulnerability
from watchlist.matcher import WatchlistMatcher
from watchlist.models import WatchKeyword


def vulnerability(**overrides: object) -> Vulnerability:
    values = {
        "id": 1,
        "source": "nvd",
        "source_url": None,
        "cve_id": "CVE-2099-0001",
        "title": "",
        "description": "",
        "vendor": "",
        "product": "",
        "severity": None,
        "cvss_score": None,
        "published_at": None,
        "updated_at": None,
        "has_poc": False,
        "in_kev": False,
        "ai_summary": None,
        "status": "new",
    }
    values.update(overrides)
    return Vulnerability(**values)


def keyword(
    canonical_name: str,
    aliases: tuple[str, ...],
    score: int = 20,
    tags: tuple[str, ...] = ("tag",),
    category: str = "category",
) -> WatchKeyword:
    return WatchKeyword(canonical_name, category, aliases, tags, score)


def test_chinese_canonical_keyword_match() -> None:
    matcher = WatchlistMatcher(
        [
            keyword(
                "\u963f\u91cc\u4e91",
                ("\u963f\u91cc\u4e91",),
                tags=("\u4e91\u5e73\u53f0",),
            )
        ]
    )

    result = matcher.evaluate(
        vulnerability(title="\u963f\u91cc\u4e91\u670d\u52a1\u6f0f\u6d1e")
    )

    assert result.matched is True
    assert result.tags == ("\u4e91\u5e73\u53f0",)


def test_english_alias_and_case_insensitive_match() -> None:
    matcher = WatchlistMatcher([keyword("Azure", ("Microsoft Azure",))])

    result = matcher.evaluate(vulnerability(title="microsoft azure privilege issue"))

    assert result.matches[0].matched_alias == "Microsoft Azure"


def test_vendor_product_title_description_and_source_fields_match() -> None:
    matcher = WatchlistMatcher(
        [
            keyword("Vendor", ("Acme",), category="vendor"),
            keyword("Product", ("Widget",), category="product"),
            keyword("Title", ("RCE",), category="type"),
            keyword("Description", ("Path Traversal",), category="type"),
            keyword("Source", ("nvd",), category="source"),
        ]
    )

    result = matcher.evaluate(
        vulnerability(
            vendor="Acme",
            product="Widget",
            title="RCE vulnerability",
            description="Path Traversal in component",
            source="nvd",
        )
    )

    assert [match.matched_field for match in result.matches] == [
        "vendor",
        "product",
        "title",
        "description",
        "source",
    ]


def test_one_canonical_keyword_scores_only_once_but_preserves_details() -> None:
    matcher = WatchlistMatcher([keyword("Windows", ("Windows", "Microsoft Windows"), score=20)])

    result = matcher.evaluate(
        vulnerability(title="Microsoft Windows Windows vulnerability", product="Windows")
    )

    assert result.score == 20
    assert len(result.matches) >= 2


def test_multiple_keywords_accumulate_and_score_is_capped() -> None:
    matcher = WatchlistMatcher(
        [
            keyword("A", ("Alpha",), score=60, tags=("shared",)),
            keyword("B", ("Beta",), score=60, tags=("shared", "beta")),
        ]
    )

    result = matcher.evaluate(vulnerability(title="Alpha Beta"))

    assert result.score == 100
    assert result.tags == ("shared", "beta")


def test_vulnerability_type_only_match_is_not_relevance_matched() -> None:
    matcher = WatchlistMatcher(
        [keyword("RCE", ("RCE",), score=35, category="vulnerability_type")]
    )

    result = matcher.evaluate(vulnerability(title="RCE vulnerability"))

    assert result.matched is True
    assert result.relevance_matched is False
    assert result.vulnerability_type_matched is True
    assert result.relevance_score == 0
    assert result.vulnerability_type_score == 35
    assert result.score == 35


def test_microsoft_windows_match_is_relevance_matched() -> None:
    matcher = WatchlistMatcher(
        [keyword("Windows", ("Microsoft Windows",), score=30, category="operating_system")]
    )

    result = matcher.evaluate(vulnerability(product="Microsoft Windows"))

    assert result.matched is True
    assert result.relevance_matched is True
    assert result.vulnerability_type_matched is False
    assert result.relevance_score == 30
    assert result.vulnerability_type_score == 0


def test_relevance_and_vulnerability_type_scores_are_split() -> None:
    matcher = WatchlistMatcher(
        [
            keyword("Windows", ("Windows",), score=30, category="operating_system"),
            keyword("RCE", ("RCE",), score=40, category="vulnerability_type"),
        ]
    )

    result = matcher.evaluate(vulnerability(title="Windows RCE"))

    assert result.relevance_matched is True
    assert result.vulnerability_type_matched is True
    assert result.relevance_score == 30
    assert result.vulnerability_type_score == 40
    assert result.score == 70


def test_split_total_score_remains_capped_at_100() -> None:
    matcher = WatchlistMatcher(
        [
            keyword("Windows", ("Windows",), score=80, category="operating_system"),
            keyword("RCE", ("RCE",), score=80, category="vulnerability_type"),
        ]
    )

    result = matcher.evaluate(vulnerability(title="Windows RCE"))

    assert result.relevance_score == 80
    assert result.vulnerability_type_score == 80
    assert result.score == 100


def test_deterministic_match_ordering() -> None:
    matcher = WatchlistMatcher(
        [
            keyword("First", ("first",), category="a"),
            keyword("Second", ("second",), category="b"),
        ]
    )

    result = matcher.evaluate(vulnerability(title="second first"))

    assert [match.canonical_name for match in result.matches] == ["First", "Second"]


def test_short_alias_token_boundaries() -> None:
    matcher = WatchlistMatcher(
        [
            keyword("AD", ("AD",)),
            keyword("HR", ("HR",)),
            keyword("K3", ("K3",)),
        ]
    )

    result = matcher.evaluate(vulnerability(title="AD advisory thread K3 product"))

    assert [match.canonical_name for match in result.matches] == ["AD", "K3"]


def test_ad_does_not_match_advisory() -> None:
    matcher = WatchlistMatcher([keyword("AD", ("AD",))])

    result = matcher.evaluate(vulnerability(title="security advisory"))

    assert result.matched is False
    assert result.score == 0


def test_unmatched_vulnerability_returns_zero_and_does_not_mutate() -> None:
    item = vulnerability(title="nothing relevant")
    before = item.title
    matcher = WatchlistMatcher([keyword("Azure", ("Azure",))])

    result = matcher.evaluate(item)

    assert result.matched is False
    assert result.score == 0
    assert result.matches == []
    assert item.title == before
