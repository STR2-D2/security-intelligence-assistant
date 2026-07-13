from collectors.base import NormalizedVulnerability


def validate_vulnerabilities(
    vulnerabilities: list[NormalizedVulnerability],
) -> tuple[list[NormalizedVulnerability], list[NormalizedVulnerability]]:
    valid: list[NormalizedVulnerability] = []
    rejected: list[NormalizedVulnerability] = []

    for vulnerability in vulnerabilities:
        if _is_valid(vulnerability):
            valid.append(vulnerability)
        else:
            rejected.append(vulnerability)

    return valid, rejected


def _is_valid(vulnerability: NormalizedVulnerability) -> bool:
    if not vulnerability.source.strip():
        return False
    if not vulnerability.title.strip():
        return False
    if vulnerability.cvss_score is not None:
        return 0.0 <= vulnerability.cvss_score <= 10.0
    return True
