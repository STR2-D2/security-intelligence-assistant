from datetime import datetime

from priority.models import PriorityLevel
from reporting.models import ReportItem, WeeklyReport


class MarkdownReportRenderer:
    def __init__(self, max_description_length: int = 500) -> None:
        self.max_description_length = max_description_length

    def render(self, report: WeeklyReport) -> str:
        lines: list[str] = [
            "# 每周安全漏洞预警报告",
            "",
            "## 一、报告概览",
            f"- 报告生成时间: {_format_datetime(report.generated_at)}",
            (
                "- 数据统计范围: "
                f"{_format_datetime(report.period.start_at)} 至 "
                f"{_format_datetime(report.period.end_at)}"
            ),
            f"- 数据库漏洞总数: {report.total_database_vulnerabilities}",
            f"- 本次评估漏洞数: {report.period_vulnerability_count}",
            f"- 企业关注命中数: {report.relevance_matched_count}",
            "",
            "## 二、优先级分布",
        ]
        for level in PriorityLevel:
            lines.append(f"- {level.value}: {report.priority_distribution.get(level, 0)}")

        lines.extend(
            [
                "",
                "## 三、重点关注领域",
                "### Top canonical keywords",
            ]
        )
        lines.extend(_count_lines(report.top_keyword_counts))
        lines.append("")
        lines.append("### Top tags")
        lines.extend(_count_lines(report.top_tag_counts))

        lines.extend(["", "## 四、本期重点漏洞"])
        if not report.focus_items:
            lines.append("- 本次范围内没有企业关注命中的重点漏洞。")
        for index, item in enumerate(report.focus_items, start=1):
            lines.extend(self._render_item(index, item))

        lines.extend(
            [
                "",
                "## 五、处置建议",
                "- 优先处理已知被利用漏洞和高 CVSS 漏洞。",
                "- 验证命中的系统、产品或平台是否在企业环境中实际部署。",
                "- 查阅厂商补丁、缓解措施和安全公告。",
                "- 在生产环境发布修复前完成测试验证。",
                "- 跟踪修复状态并保留处置记录。",
                "",
                "## 六、说明",
                "- 企业优先级基于通用漏洞风险和已配置的企业关注关键词计算。",
                "- 关键词命中不等于企业一定部署了受影响产品。",
                "- 后续接入更详细的资产清单可提升匹配准确性。",
                "",
            ]
        )
        return "\n".join(lines)

    def _render_item(self, index: int, item: ReportItem) -> list[str]:
        lines = [
            "",
            f"### {index}. {_safe(item.cve_id or '无 CVE')} - {_safe(item.title)}",
            f"- 企业优先级: {item.priority_score} / {item.priority_level.value}",
            f"- 通用风险分: {item.generic_risk_score}",
            f"- 关注相关性分: {item.relevance_score}",
            f"- 漏洞类型分: {item.vulnerability_type_score}",
            f"- 来源: {_safe(item.source)}",
        ]
        if item.published_at is not None:
            lines.append(f"- 发布时间: {_format_datetime(item.published_at)}")
        if item.updated_at is not None:
            lines.append(f"- 更新时间: {_format_datetime(item.updated_at)}")
        lines.extend(
            [
                f"- 命中关键词: {_join_values(item.matched_keywords)}",
                f"- 标签: {_join_values(item.tags)}",
                f"- 风险原因: {_join_values(item.risk_reasons)}",
                f"- 优先级解释: {_join_values(item.priority_reasons)}",
                f"- 源描述: {_safe(self._truncate(item.description))}",
            ]
        )
        if item.source_url:
            lines.append(f"- 参考链接: {_safe(item.source_url)}")
        return lines

    def _truncate(self, value: str | None) -> str:
        if not value:
            return "无"
        text = value.strip()
        if len(text) <= self.max_description_length:
            return text
        return text[: self.max_description_length].rstrip() + "..."


def _count_lines(counts: tuple[tuple[str, int], ...]) -> list[str]:
    if not counts:
        return ["- 无"]
    return [f"- {_safe(name)}: {count}" for name, count in counts]


def _join_values(values: tuple[str, ...]) -> str:
    if not values:
        return "无"
    return _safe(", ".join(values))


def _safe(value: str) -> str:
    return " ".join(str(value).replace("|", "\\|").splitlines()).strip()


def _format_datetime(value: datetime) -> str:
    return value.isoformat()
