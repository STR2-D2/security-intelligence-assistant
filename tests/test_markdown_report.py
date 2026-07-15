from datetime import UTC, datetime

from priority.models import PriorityLevel
from reporting.markdown import MarkdownReportRenderer
from reporting.models import ReportItem, ReportPeriod, WeeklyReport


GENERATED = datetime(2026, 1, 8, 12, 0, tzinfo=UTC)
PERIOD = ReportPeriod(
    datetime(2026, 1, 1, tzinfo=UTC),
    datetime(2026, 1, 8, tzinfo=UTC),
)


def item(**overrides) -> ReportItem:
    values = {
        "vulnerability_id": 1,
        "cve_id": "CVE-2099-0001",
        "title": "Azure RCE",
        "source": "nvd",
        "source_url": "https://example.test/advisory",
        "published_at": GENERATED,
        "updated_at": GENERATED,
        "priority_score": 80,
        "priority_level": PriorityLevel.CRITICAL,
        "generic_risk_score": 70,
        "relevance_score": 60,
        "vulnerability_type_score": 30,
        "matched_keywords": ("Azure", "RCE"),
        "tags": ("cloud", "critical"),
        "risk_reasons": ("Known exploited",),
        "priority_reasons": ("Weighted priority",),
        "description": "Line one | with pipe\nLine two",
    }
    values.update(overrides)
    return ReportItem(**values)


def report(**overrides) -> WeeklyReport:
    values = {
        "generated_at": GENERATED,
        "period": PERIOD,
        "total_database_vulnerabilities": 10,
        "period_vulnerability_count": 5,
        "relevance_matched_count": 2,
        "priority_distribution": {
            PriorityLevel.LOW: 1,
            PriorityLevel.MEDIUM: 2,
            PriorityLevel.HIGH: 1,
            PriorityLevel.CRITICAL: 1,
        },
        "top_keyword_counts": (("Azure", 2),),
        "top_tag_counts": (("cloud", 2),),
        "focus_items": [item()],
    }
    values.update(overrides)
    return WeeklyReport(**values)


def test_required_sections_are_rendered() -> None:
    markdown = MarkdownReportRenderer().render(report())

    assert "# 每周安全漏洞预警报告" in markdown
    assert "## 一、报告概览" in markdown
    assert "## 二、优先级分布" in markdown
    assert "## 三、重点关注领域" in markdown
    assert "## 四、本期重点漏洞" in markdown
    assert "## 五、处置建议" in markdown
    assert "## 六、说明" in markdown


def test_priority_distribution_is_rendered() -> None:
    markdown = MarkdownReportRenderer().render(report())

    assert "- LOW: 1" in markdown
    assert "- MEDIUM: 2" in markdown
    assert "- HIGH: 1" in markdown
    assert "- CRITICAL: 1" in markdown


def test_item_fields_are_rendered() -> None:
    markdown = MarkdownReportRenderer().render(report())

    assert "CVE-2099-0001" in markdown
    assert "Azure RCE" in markdown
    assert "企业优先级: 80 / CRITICAL" in markdown
    assert "通用风险分: 70" in markdown
    assert "命中关键词: Azure, RCE" in markdown
    assert "参考链接: https://example.test/advisory" in markdown


def test_missing_optional_dates_and_urls_are_handled() -> None:
    markdown = MarkdownReportRenderer().render(
        report(focus_items=[item(published_at=None, updated_at=None, source_url=None)])
    )

    assert "发布时间:" not in markdown
    assert "更新时间:" not in markdown
    assert "参考链接:" not in markdown


def test_long_description_is_truncated() -> None:
    markdown = MarkdownReportRenderer(max_description_length=10).render(
        report(focus_items=[item(description="x" * 20)])
    )

    assert "源描述: xxxxxxxxxx..." in markdown


def test_pipes_and_line_breaks_are_safe() -> None:
    markdown = MarkdownReportRenderer().render(report())

    assert "Line one \\| with pipe Line two" in markdown


def test_deterministic_output_for_fixed_input() -> None:
    renderer = MarkdownReportRenderer()

    assert renderer.render(report()) == renderer.render(report())
